"""Read-only EAPOL metadata capture on one physical Wi-Fi adapter.

Does not send frames, change monitor/promiscuous mode, store packets, or write
identities, passwords, challenges, TLS contents or key material to disk.
"""
import argparse
import ctypes as C
import datetime
import json
import os
from pathlib import Path
import struct
import time


def metadata(packet, local_mac):
    if len(packet) < 18:
        return None
    offset, kind = 14, struct.unpack_from('!H', packet, 12)[0]
    for _ in range(2):
        if kind not in (0x8100, 0x88a8):
            break
        if len(packet) < offset + 4:
            return None
        kind = struct.unpack_from('!H', packet, offset + 2)[0]
        offset += 4
    if kind != 0x888e or len(packet) < offset + 4:
        return None
    version, frame_type, length = struct.unpack_from('!BBH', packet, offset)
    if version not in (1, 2, 3) or len(packet) < offset + 4 + length:
        return None
    direction = 'tx' if packet[6:12] == local_mac else 'rx'
    result = dict(direction=direction, eapol_type=frame_type, length=length)
    if frame_type != 0 or length < 4:
        return result
    offset += 4
    code, identifier, eap_length = struct.unpack_from('!BBH', packet, offset)
    if eap_length < 4 or eap_length > length or code not in (1, 2, 3, 4):
        return None
    result.update(eap_code=code, identifier=identifier, eap_length=eap_length)
    if code not in (1, 2) or eap_length < 5:
        return result
    method = packet[offset + 4]
    result['method'] = method
    # Only TLS transport header fields; never parse an identity or inner method.
    if method in (13, 21, 25) and eap_length >= 6:
        flags = packet[offset + 5]
        result['tls_flags'] = flags
        position = offset + 6 + (4 if flags & 0x80 else 0)
        end = offset + eap_length
        if position + 5 <= end:
            record_type, major, minor, size = struct.unpack_from('!BBBH', packet, position)
            if record_type in (20, 21, 22, 23) and major == 3 and minor <= 4:
                result.update(tls_record_type=record_type, tls_record_length=size)
                if record_type == 22 and position + 6 <= end:
                    result['tls_handshake_type'] = packet[position + 5]
                elif record_type == 21 and position + 7 <= end and size == 2:
                    result.update(tls_alert_level=packet[position + 5], tls_alert_description=packet[position + 6])
    return result


def main():
    from network_lab_windows import ps_json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, required=True)
    parser.add_argument('--interface', type=int, required=True)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 3600 or not 0 < args.interface < 65536:
        return 2
    stream = args.log.open('a', encoding='utf-8', buffering=1)

    def write(value):
        stream.write(json.dumps(dict(time=datetime.datetime.now(datetime.timezone.utc).isoformat(), **value), separators=(',', ':')) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    handle, pcap = None, None
    directory = None
    try:
        adapter = ps_json("$a=Get-NetAdapter -Physical|Where-Object {$_.ifIndex -eq " + str(args.interface) + " -and $_.NdisPhysicalMedium -eq 9};if(@($a).Count -ne 1){throw 'adapter'};[pscustomobject]@{guid=[string]$a.InterfaceGuid;mac=[string]$a.MacAddress}|ConvertTo-Json -Compress")
        guid = adapter['guid'].strip('{}')
        import uuid
        guid = str(uuid.UUID(guid))
        local_mac = bytes.fromhex(adapter['mac'].replace('-', ''))
        if len(local_mac) != 6:
            raise ValueError()
        folder = Path(os.environ['SystemRoot']) / 'System32/Npcap'
        if not (folder / 'wpcap.dll').is_file():
            folder = folder.parent
        directory = os.add_dll_directory(str(folder))
        pcap = C.CDLL(str(folder / 'wpcap.dll'))
        pcap.pcap_open_live.argtypes = [C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p]
        pcap.pcap_open_live.restype = C.c_void_p
        pcap.pcap_datalink.argtypes = [C.c_void_p]
        pcap.pcap_close.argtypes = [C.c_void_p]
        error = C.create_string_buffer(256)
        handle = pcap.pcap_open_live(('\\Device\\NPF_{' + guid.upper() + '}').encode('ascii'), 65535, 0, 100, error)
        if not handle:
            write(dict(event='capture_open_failed'))
            return 3
        if pcap.pcap_datalink(handle) != 1:
            write(dict(event='unsupported_link_type'))
            return 3
        class Program(C.Structure):
            _fields_ = [('length', C.c_uint), ('instructions', C.c_void_p)]
        class Header(C.Structure):
            _fields_ = [('seconds', C.c_long), ('micros', C.c_long), ('captured', C.c_uint), ('original', C.c_uint)]
        program = Program()
        pcap.pcap_compile.argtypes = [C.c_void_p, C.POINTER(Program), C.c_char_p, C.c_int, C.c_uint]
        pcap.pcap_setfilter.argtypes = [C.c_void_p, C.POINTER(Program)]
        pcap.pcap_freecode.argtypes = [C.POINTER(Program)]
        if pcap.pcap_compile(handle, C.byref(program), b'ether proto 0x888e', 1, 0xffffffff):
            raise RuntimeError()
        try:
            if pcap.pcap_setfilter(handle, C.byref(program)):
                raise RuntimeError()
        finally:
            pcap.pcap_freecode(C.byref(program))
        # Nonblocking polling provides a hard duration even with no traffic.
        pcap.pcap_setnonblock.argtypes = [C.c_void_p, C.c_int, C.c_char_p]
        if pcap.pcap_setnonblock(handle, 1, error):
            raise RuntimeError()
        pcap.pcap_next_ex.argtypes = [C.c_void_p, C.POINTER(C.POINTER(Header)), C.POINTER(C.c_void_p)]
        write(dict(event='passive_eap_capture_ready', interface=args.interface))
        end, count = time.monotonic() + args.seconds, 0
        while time.monotonic() < end and count < 2000:
            header, raw = C.POINTER(Header)(), C.c_void_p()
            status = pcap.pcap_next_ex(handle, C.byref(header), C.byref(raw))
            if status < 0:
                write(dict(event='capture_ended', status=status))
                break
            if status == 1 and header and raw and header.contents.captured <= 65535:
                value = metadata(C.string_at(raw, header.contents.captured), local_mac)
                if value:
                    write(dict(event='eap_metadata', **value))
                    count += 1
            else:
                time.sleep(.02)
    except Exception:
        write(dict(event='passive_capture_unavailable'))
        return 4
    finally:
        if handle:
            pcap.pcap_close(handle)
        if directory:
            directory.close()
        stream.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
