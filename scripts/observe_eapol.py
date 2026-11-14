"""Passively record EAPOL types and lengths; never log authentication values."""

import argparse
import ctypes as C
import datetime
import json
import os
from pathlib import Path
import subprocess
import time


class Header(C.Structure):
    _fields_ = [("seconds", C.c_long), ("microseconds", C.c_long), ("captured", C.c_uint), ("original", C.c_uint)]


class Filter(C.Structure):
    _fields_ = [("length", C.c_uint), ("instructions", C.c_void_p)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    query = "Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up' -and $_.NdisPhysicalMedium -eq 14} | Select-Object InterfaceGuid,MacAddress | ConvertTo-Json -Compress"
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query], capture_output=True, check=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    adapter = json.loads(result.stdout)
    if not isinstance(adapter, dict):
        raise ValueError("Expected one physical Ethernet interface")
    local = bytes.fromhex(adapter["MacAddress"].replace("-", ""))
    system = Path(os.environ["SystemRoot"]) / "System32"
    path = system / "Npcap" / "wpcap.dll"
    if not path.exists():
        path = system / "wpcap.dll"
    pcap = C.CDLL(str(path), winmode=0x00000100 | 0x00000800)
    pcap.pcap_open_live.restype = C.c_void_p
    pcap.pcap_open_live.argtypes = [C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p]
    pcap.pcap_compile.argtypes = [C.c_void_p, C.POINTER(Filter), C.c_char_p, C.c_int, C.c_uint]
    pcap.pcap_setfilter.argtypes = [C.c_void_p, C.POINTER(Filter)]
    pcap.pcap_freecode.argtypes = [C.POINTER(Filter)]
    pcap.pcap_setnonblock.argtypes = [C.c_void_p, C.c_int, C.c_char_p]
    pcap.pcap_next_ex.argtypes = [C.c_void_p, C.POINTER(C.POINTER(Header)), C.POINTER(C.POINTER(C.c_ubyte))]
    pcap.pcap_close.argtypes = [C.c_void_p]
    error = C.create_string_buffer(256)
    guid = str(adapter["InterfaceGuid"]).strip("{}")
    handle = pcap.pcap_open_live(("\\Device\\NPF_{" + guid + "}").encode("ascii"), 65535, 0, 250, error)
    if not handle:
        raise RuntimeError("Cannot open the physical Ethernet capture interface")
    try:
        program = Filter()
        if pcap.pcap_compile(handle, C.byref(program), b"ether proto 0x888e", 1, 0xFFFFFFFF):
            raise RuntimeError("Cannot compile the passive EAPOL filter")
        try:
            if pcap.pcap_setfilter(handle, C.byref(program)):
                raise RuntimeError("Cannot install the passive EAPOL filter")
        finally:
            pcap.pcap_freecode(C.byref(program))
        if pcap.pcap_setnonblock(handle, 1, error):
            raise RuntimeError("Cannot enable nonblocking passive capture")
        finished = None
        header = C.POINTER(Header)()
        data = C.POINTER(C.c_ubyte)()
        with args.log.open("a", encoding="utf-8") as stream:
            print("Passive EAPOL observer ready", flush=True)
            while True:
                try:
                    status = json.loads(args.status.read_text(encoding="utf-8-sig"))
                except (OSError, json.JSONDecodeError):
                    time.sleep(0.1)
                    continue
                if status.get("ended_at") and finished is None:
                    finished = time.monotonic()
                if finished is not None and time.monotonic() - finished > 20:
                    break
                outcome = pcap.pcap_next_ex(handle, C.byref(header), C.byref(data))
                if outcome < 0:
                    raise RuntimeError("Passive capture failed")
                if not outcome:
                    time.sleep(0.025)
                    continue
                if header.contents.captured > 65535 or header.contents.captured < 18:
                    continue
                raw = C.string_at(data, header.contents.captured)
                if raw[6:12] != local and raw[:6] != local:
                    continue
                size = int.from_bytes(raw[16:18], "big")
                item = {
                    "time": datetime.datetime.fromtimestamp(header.contents.seconds + header.contents.microseconds / 1e6, datetime.timezone.utc).isoformat(timespec="milliseconds"),
                    "direction": "tx" if raw[6:12] == local else "rx",
                    "frame_bytes": len(raw),
                    "eapol_type": raw[15],
                    "eapol_payload_bytes": size,
                }
                if raw[15] == 0 and size >= 4 and len(raw) >= 22:
                    item["eap_code"], item["identifier"] = raw[18:20]
                    if raw[18] in (1, 2) and size >= 5 and len(raw) >= 23:
                        item["method"] = raw[22]
                line = json.dumps(item, separators=(",", ":"))
                stream.write(line + "\n")
                stream.flush()
                print(line, flush=True)
    finally:
        pcap.pcap_close(handle)


if __name__ == "__main__":
    main()
