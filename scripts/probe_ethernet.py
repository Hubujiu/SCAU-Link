"""Read-only IPv4 reachability checks bound to the physical Ethernet adapter.

The authentication core remains untouched. DNS queries use that adapter's DNS
server, and both UDP and TCP sockets bind its address and IP_UNICAST_IF. Only
sanitized outcomes are written; addresses and DNS/HTTP payloads stay in memory.
"""

import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import time


HOST = "www.msftconnecttest.com"
IP_UNICAST_IF = 31
ADAPTER_COMMAND = r"""$ErrorActionPreference='Stop'
$taskAdapters=@(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up' -and $_.NdisPhysicalMedium -eq 14})
if($taskAdapters.Count -ne 1){throw 'Expected one connected physical Ethernet adapter.'}
$taskAdapter=$taskAdapters[0]
$taskAddress=Get-NetIPAddress -InterfaceIndex $taskAdapter.ifIndex -AddressFamily IPv4 | Where-Object {$_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*'} | Select-Object -First 1
$taskDns=Get-DnsClientServerAddress -InterfaceIndex $taskAdapter.ifIndex -AddressFamily IPv4
[pscustomobject]@{index=$taskAdapter.ifIndex;address=$taskAddress.IPAddress;dns=@($taskDns.ServerAddresses);original_present=[bool](Get-Process -Name '8021x' -ErrorAction SilentlyContinue)} | ConvertTo-Json -Compress
"""


def adapter_config():
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ADAPTER_COMMAND],
        capture_output=True,
        timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        raise ValueError("adapter_configuration")
    config = json.loads(result.stdout)
    if not config.get("address") or not config.get("dns"):
        raise ValueError("adapter_configuration")
    return config


def bound_socket(config, kind):
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.settimeout(4)
        # Windows requires the interface index in network byte order.
        # https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
        sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", config["index"]))
        sock.bind((config["address"], 0))
        return sock
    except Exception:
        sock.close()
        raise


def skip_name(packet, offset):
    for _ in range(128):
        if offset >= len(packet):
            raise ValueError("dns_packet")
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 2 > len(packet):
                raise ValueError("dns_packet")
            return offset + 2
        if size & 0xC0 or size > 63 or offset + size + 1 > len(packet):
            raise ValueError("dns_packet")
        offset += size + 1
        if not size:
            return offset
    raise ValueError("dns_packet")


def resolve_direct(config):
    transaction = secrets.randbelow(65536)
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in HOST.split("."))
    query = struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + question + b"\0\0\1\0\1"
    for server in config["dns"]:
        try:
            with bound_socket(config, socket.SOCK_DGRAM) as sock:
                sock.connect((server, 53))
                sock.send(query)
                reply = sock.recv(4096)
            if len(reply) < 12:
                continue
            identifier, flags, questions, answers, _, _ = struct.unpack_from("!6H", reply)
            if identifier != transaction or not flags & 0x8000 or flags & 0x020F:
                continue
            offset = 12
            for _ in range(questions):
                offset = skip_name(reply, offset) + 4
            addresses = []
            for _ in range(answers):
                offset = skip_name(reply, offset)
                kind, dns_class, _, size = struct.unpack_from("!HHIH", reply, offset)
                offset += 10
                if offset + size > len(reply):
                    raise ValueError("dns_packet")
                if kind == 1 and dns_class == 1 and size == 4:
                    address = ipaddress.IPv4Address(reply[offset : offset + size])
                    if address.is_global:
                        addresses.append(str(address))
                offset += size
            if addresses:
                return addresses
        except (OSError, ValueError, struct.error):
            continue
    raise ValueError("direct_dns")


def probe():
    started = time.monotonic()
    event = {
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
        "event": "ethernet_direct_probe_failed",
    }
    stage = "adapter_configuration"
    try:
        config = adapter_config()
        event["original_client_present"] = config["original_present"]
        stage = "direct_dns"
        addresses = resolve_direct(config)
        stage = "direct_http"
        for address in addresses:
            try:
                with bound_socket(config, socket.SOCK_STREAM) as sock:
                    sock.connect((address, 80))
                    request = f"GET /connecttest.txt HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
                    sock.sendall(request.encode("ascii"))
                    response = b""
                    while len(response) < 8192:
                        part = sock.recv(min(4096, 8192 - len(response)))
                        if not part:
                            break
                        response += part
                header, separator, body = response.partition(b"\r\n\r\n")
                status = header.split(b"\r\n", 1)[0].split(b" ")
                if separator and len(status) > 1 and status[1] == b"200" and b"Microsoft Connect Test" in body:
                    event["event"] = "ethernet_direct_probe_ok"
                    event["interface_bound"] = True
                    event["dns_direct"] = True
                    event["http_verified"] = True
                    break
            except OSError:
                continue
        else:
            raise ValueError("direct_http")
    except (OSError, ValueError, subprocess.SubprocessError):
        event["failed_stage"] = stage
    event["duration_ms"] = round((time.monotonic() - started) * 1000)
    return event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--status", type=Path, help="Stop when the controlled native test finishes")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--interval", type=float, default=30)
    args = parser.parse_args()
    if not 1 <= args.count <= 2880 or not 1 <= args.interval <= 3600:
        parser.error("Invalid count or interval")
    failed = False
    for index in range(args.count):
        if args.status:
            try:
                status = json.loads(args.status.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                status = {}
            if status.get("ended_at"):
                break
        event = probe()
        failed |= event["event"].endswith("failed")
        line = json.dumps(event, separators=(",", ":"))
        print(line, flush=True)
        if args.log:
            with args.log.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")
        if index + 1 < args.count:
            time.sleep(args.interval)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
