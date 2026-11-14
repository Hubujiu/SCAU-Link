"""Analyze local PktMon PCAPNG files without exporting credential values."""

import argparse
import collections
import datetime
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct


MAGIC = bytes.fromhex("00001311")
LOCAL_TIME = datetime.timezone(datetime.timedelta(hours=8))
CLIENT_PROPERTY_NAMES = {
    0x18: "dhcp_status",
    0x2D: "adapter_mac",
    0x2F: "password_related_digest",
    0x35: "ipv6_metadata",
    0x36: "link_local_ipv6",
    0x38: "temporary_ipv6",
    0x39: "selected_service",
    0x4D: "client_validation_data",
    0x4E: "global_ipv6",
    0x54: "device_identifier",
    0x55: "domain_metadata",
    0x62: "security_check_result",
    0x6F: "client_version_string",
    0x70: "architecture_indicator",
    0x76: "secondary_dns",
    0x79: "direct_communication_version",
}
SERVER_PROPERTY_NAMES = {
    0x00: "server_message_or_session_data",
    0x01: "server_message_or_session_data",
    0x2E: "server_capability",
    0x3C: "accounting_message",
    0x3D: "server_text",
    0x56: "server_parameter",
    0x5A: "sam_server_port",
    0x5B: "sam_server_ipv4",
    0x5C: "session_key_material",
    0x5D: "session_iv_material",
    0x5E: "server_utc_time",
    0x66: "service_list",
    0x6E: "client_message_port",
    0x79: "direct_communication_version",
    0x80: "direct_communication_heartbeat_flag",
    0x98: "wireless_connection_parameter",
}


def local_time(timestamp):
    return datetime.datetime.fromtimestamp(timestamp, LOCAL_TIME).isoformat(
        timespec="microseconds"
    )


def capture_packets(path):
    """Yield validated Enhanced Packet Blocks and their original frame bytes."""
    with path.open("rb") as stream, mmap.mmap(
        stream.fileno(), 0, access=mmap.ACCESS_READ
    ) as data:
        offset, ordinal, endian = 0, 0, "<"
        interfaces = []
        while offset < len(data):
            if len(data) - offset < 12:
                raise ValueError(f"Incomplete block in {path.name} at {offset}")
            if data[offset : offset + 4] == bytes.fromhex("0a0d0d0a"):
                order = data[offset + 8 : offset + 12]
                if order not in (bytes.fromhex("4d3c2b1a"), bytes.fromhex("1a2b3c4d")):
                    raise ValueError("Invalid PCAPNG byte order")
                endian = "<" if order == bytes.fromhex("4d3c2b1a") else ">"
                interfaces = []
            kind, size = struct.unpack_from(endian + "II", data, offset)
            if size < 12 or size % 4 or offset + size > len(data):
                raise ValueError(f"Invalid block length in {path.name} at {offset}")
            if struct.unpack_from(endian + "I", data, offset + size - 4)[0] != size:
                raise ValueError("PCAPNG trailing length mismatch")
            if kind == 1:
                if size < 20:
                    raise ValueError("Incomplete interface description")
                link_type = struct.unpack_from(endian + "H", data, offset + 8)[0]
                resolution, seconds_offset = 1e-6, 0
                option = offset + 16
                while option + 4 <= offset + size - 4:
                    code, length = struct.unpack_from(endian + "HH", data, option)
                    if option + 4 + length > offset + size - 4:
                        raise ValueError("Invalid interface option length")
                    value = data[option + 4 : option + 4 + length]
                    if code == 9 and length == 1:
                        resolution = (2 if value[0] & 128 else 10) ** (-(value[0] & 127))
                    elif code == 14 and length == 8:
                        seconds_offset = struct.unpack(endian + "q", value)[0]
                    elif code == 0:
                        break
                    option += 4 + (length + 3) // 4 * 4
                interfaces.append((link_type, resolution, seconds_offset))
            elif kind == 6:
                if size < 32:
                    raise ValueError("Incomplete packet block")
                iface, high, low, captured, original = struct.unpack_from(
                    endian + "IIIII", data, offset + 8
                )
                if iface >= len(interfaces) or captured > size - 32:
                    raise ValueError("Invalid packet interface or captured length")
                ordinal += 1
                link_type, resolution, seconds_offset = interfaces[iface]
                timestamp = ((high << 32) | low) * resolution + seconds_offset
                yield {
                    "file": path.name,
                    "record": ordinal,
                    "timestamp": timestamp,
                    "link_type": link_type,
                    "original_length": original,
                    "frame": data[offset + 28 : offset + 28 + captured],
                }
            offset += size


def ethernet_payload(frame):
    if len(frame) < 14:
        return None, None
    protocol = int.from_bytes(frame[12:14], "big")
    offset = 14
    while protocol in (0x8100, 0x88A8, 0x9100) and len(frame) >= offset + 4:
        protocol = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        offset += 4
    return protocol, offset


def ipv4_packet(frame):
    """PktMon's combined NIC capture can also contain raw IP observations."""
    protocol, ethernet_offset = ethernet_payload(frame)
    candidates = [ethernet_offset, 0] if protocol == 0x0800 else [0]
    for start in candidates:
        if start is None or len(frame) < start + 20 or frame[start] >> 4 != 4:
            continue
        header = (frame[start] & 15) * 4
        total = int.from_bytes(frame[start + 2 : start + 4], "big")
        if header < 20 or total < header or len(frame) < start + total:
            continue
        packet = frame[start : start + total]
        return packet, header, "ethernet_ipv4" if start else "raw_ipv4"
    return None


def properties(frame, start, end, bare):
    """Read property boundaries; preserve lengths without publishing values."""
    output = []
    values = {}
    position = start
    while position < end:
        head = position if bare else position + 2
        if head + 6 > end or frame[head : head + 4] != MAGIC:
            raise ValueError(f"Invalid vendor property at byte {position}")
        prop_type, inner_length = frame[head + 4 : head + 6]
        value_start = head + 6
        length_source = "declared"
        if bare and (prop_type in (0, 1) or inner_length < 2):
            following = frame.find(MAGIC, value_start, end)
            value_end = end if following < 0 else following
            length_source = "next_vendor_marker"
        else:
            if inner_length < 2:
                raise ValueError("Vendor property length is smaller than its header")
            value_end = value_start + inner_length - 2
        if value_end > end:
            raise ValueError("Vendor property exceeds the enclosing frame")
        item = {
            "offset": position,
            "type": f"0x{prop_type:02x}",
            "reference_name": (SERVER_PROPERTY_NAMES if bare else CLIENT_PROPERTY_NAMES).get(
                prop_type, "unmapped_property"
            ),
            "declared_inner_length": inner_length,
            "value_bytes": value_end - value_start,
            "length_source": length_source,
        }
        if not bare:
            item["outer_type"] = f"0x{frame[position]:02x}"
            item["outer_length_matches"] = frame[position + 1] == value_end - position
        value = frame[value_start:value_end]
        item["all_zero"] = not any(value)
        if not bare and prop_type == 0x39:
            text = value.rstrip(b"\0").decode("gb18030", errors="replace")
            if text in ("有线1x上网", "无线web上网", "scau.edu.cn"):
                item["service"] = text
                item["gbk_encoding_confirmed"] = value.rstrip(b"\0") == text.encode("gbk")
        if not bare and prop_type == 0x6F and value.startswith(b"RG_SU_For_Windows"):
            item["version_string"] = value.rstrip(b"\0").decode("ascii", errors="replace")
        if bare and prop_type in (0x5A, 0x6E, 0x79, 0x80) and len(value) <= 4:
            item["numeric_value"] = int.from_bytes(value, "big")
        if not bare and prop_type in (0x70, 0x79) and len(value) == 1:
            item["numeric_value"] = value[0]
        values[prop_type] = value
        output.append(item)
        position = value_end
    return output, values


def analyze(directory):
    files = sorted(directory.glob("scau*.pcapng"), key=lambda p: int(re.search(r"(\d+)\.pcapng$", p.name)[1]))
    if not files:
        raise ValueError("No scau*.pcapng capture files were found")
    overview, events, selected = [], [], []
    seen = {}
    previous_identity_properties = {}
    sam_server_ips = set()
    total_packets = 0
    raw_eapol_count = 0
    network_layouts = collections.Counter()

    for path in files:
        counts = collections.Counter()
        first = last = None
        for record in capture_packets(path):
            frame, timestamp = record["frame"], record["timestamp"]
            counts["packet_records"] += 1
            total_packets += 1
            counts["truncated_records"] += len(frame) < record["original_length"]
            first = timestamp if first is None else min(first, timestamp)
            last = timestamp if last is None else max(last, timestamp)
            protocol, start = ethernet_payload(frame)
            if protocol != 0x888E or start is None or len(frame) < start + 4:
                continue
            raw_eapol_count += 1
            digest = hashlib.sha256(frame).digest()
            duplicate = digest in seen and 0 <= timestamp - seen[digest] < 0.002
            seen[digest] = timestamp
            if duplicate:
                continue
            version, eapol_type = frame[start : start + 2]
            declared = int.from_bytes(frame[start + 2 : start + 4], "big")
            end = start + 4 + declared
            if end > len(frame):
                raise ValueError("Truncated EAPOL data")
            event = {
                "file": record["file"],
                "record": record["record"],
                "time": local_time(timestamp),
                "frame_bytes": len(frame),
                "eapol_version": version,
                "eapol_type": eapol_type,
                "eapol_length": declared,
                "trailing_bytes": len(frame) - end,
            }
            if eapol_type == 0 and declared >= 4:
                code, identifier = frame[start + 4 : start + 6]
                event.update(eap_code=code, identifier=identifier)
                if code in (1, 2) and declared >= 5:
                    method = frame[start + 8]
                    event["eap_method"] = method
                    if method == 4:
                        if declared < 6:
                            raise ValueError("Missing MD5 value-size field")
                        value_size = frame[start + 9]
                        if start + 10 + value_size > end:
                            raise ValueError("MD5 value exceeds the declared EAPOL data")
                        event["md5_value_bytes"] = value_size
                        if code == 1:
                            prop_start = start + 10 + value_size
                            event["properties"], _ = properties(frame, prop_start, end, True)
                elif code in (3, 4):
                    event["properties"], server_values = properties(frame, start + 8, end, True)
                    if len(server_values.get(0x5B, b"")) == 4:
                        sam_server_ips.add(server_values[0x5B])
            if len(frame) - end >= 70 and frame[end + 23 : end + 27] == MAGIC:
                event["program_name_matches"] = frame[end + 27 : end + 59].rstrip(b"\0") == b"8021x.exe"
                event["client_version_header"] = frame[end + 59 : end + 63].hex()
                event["declared_property_bytes"] = int.from_bytes(frame[end + 68 : end + 70], "big")
                event["properties"], client_values = properties(frame, end + 70, len(frame), False)
                if event.get("eap_code") == 2 and event.get("eap_method") == 1:
                    previous_identity_properties = client_values
                elif event.get("eap_code") == 2 and event.get("eap_method") == 4:
                    event["changed_property_types_since_identity"] = [
                        f"0x{key:02x}" for key, value in client_values.items()
                        if value != previous_identity_properties.get(key)
                    ]
            events.append(event)
            selected.append(record)
        overview.append({
            "file": path.name,
            "bytes": path.stat().st_size,
            **dict(counts),
            "first": local_time(first) if first is not None else None,
            "last": local_time(last) if last is not None else None,
        })

    sam_traffic = collections.Counter()
    dhcp_messages = collections.Counter()
    for path in files:
        for record in capture_packets(path):
            parsed = ipv4_packet(record["frame"])
            if parsed is None:
                continue
            packet, header, layout = parsed
            network_layouts[layout] += 1
            protocol = packet[9]
            if protocol not in (6, 17) or len(packet) < header + 8:
                continue
            if int.from_bytes(packet[6:8], "big") & 0x1FFF:
                continue
            src_port, dst_port = struct.unpack_from("!HH", packet, header)
            if packet[12:16] in sam_server_ips or packet[16:20] in sam_server_ips:
                direction = "from_server" if packet[12:16] in sam_server_ips else "to_server"
                sam_traffic[(direction, "udp" if protocol == 17 else "tcp", src_port, dst_port)] += 1
            if protocol == 17 and {src_port, dst_port} == {67, 68}:
                payload = packet[header + 8 :]
                if len(payload) < 240 or payload[236:240] != bytes.fromhex("63825363"):
                    continue
                option = 240
                while option < len(payload):
                    code = payload[option]
                    option += 1
                    if code == 255:
                        break
                    if code == 0:
                        continue
                    if option >= len(payload):
                        break
                    length = payload[option]
                    option += 1
                    if option + length > len(payload):
                        break
                    if code == 53 and length == 1:
                        dhcp_messages[payload[option]] += 1
                    option += length

    # Keep a small local-only subset for later protocol work. It still contains
    # authentication identifiers and responses, so it stays under captures/.
    subset = directory / "eapol-only.pcapng"
    with subset.open("wb") as output:
        output.write(struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28))
        output.write(struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20))
        for record in selected:
            frame = record["frame"]
            ticks = round(record["timestamp"] * 1_000_000)
            padding = b"\0" * ((-len(frame)) % 4)
            size = 32 + len(frame) + len(padding)
            output.write(struct.pack("<IIIIIII", 6, size, 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), record["original_length"]))
            output.write(frame + padding + struct.pack("<I", size))

    report = {
        "capture_directory": str(directory),
        "packet_records": total_packets,
        "files": overview,
        "raw_eapol_records": raw_eapol_count,
        "unique_eapol_frames": len(events),
        "deduplication_rule": "Identical complete EAPOL frame within 2 milliseconds",
        "eapol_events": events,
        "ip_observation_layouts": dict(network_layouts),
        "dhcp_message_record_counts": dict(dhcp_messages),
        "sam_server_address_count": len(sam_server_ips),
        "sam_server_tcp_udp_observations": [
            {"direction": key[0], "transport": key[1], "source_port": key[2], "destination_port": key[3], "records": count}
            for key, count in sorted(sam_traffic.items())
        ],
        "eapol_subset": str(subset),
        "privacy": "JSON excludes account values, MAC/IP addresses, device identifiers, challenge values, response digests and session keys",
        "field_name_scope": "Reference names are hypotheses from public implementations and local logs; value lengths and offsets are measured from this capture",
    }
    report_path = directory / "protocol-analysis.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_directory", type=Path)
    args = parser.parse_args()
    result = analyze(args.capture_directory.resolve())
    print(json.dumps({key: value for key, value in result.items() if key != "eapol_events"}, ensure_ascii=False))
    for event in result["eapol_events"]:
        print(json.dumps({key: value for key, value in event.items() if key != "properties"}, ensure_ascii=False))
