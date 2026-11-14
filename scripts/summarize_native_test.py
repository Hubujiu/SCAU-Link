"""Summarize a local native-auth test without exporting authentication values."""

import argparse
import collections
import datetime
import hashlib
import json
from pathlib import Path

from analyze_capture import capture_packets, ethernet_payload


LOCAL = datetime.timezone(datetime.timedelta(hours=8))


def read_events(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def parse_time(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def local_time(value):
    return parse_time(value).astimezone(LOCAL).isoformat(timespec="milliseconds")


def probe_statistics(events):
    success = [item for item in events if item["event"].endswith("_ok")]
    failure = [item for item in events if item["event"].endswith("_failed")]
    times = [parse_time(item["time"]) for item in events]
    gaps = [(right - left).total_seconds() for left, right in zip(times, times[1:])]
    return {
        "successful": len(success),
        "failed": len(failure),
        "first_at": local_time(events[0]["time"]) if events else None,
        "last_at": local_time(events[-1]["time"]) if events else None,
        "max_interval_seconds": round(max(gaps), 3) if gaps else None,
    }


def capture_summary(path):
    sequence = []
    challenge = response = None
    start = accepted = None
    truncated = 0
    for packet in capture_packets(path):
        raw = packet["frame"]
        protocol, offset = ethernet_payload(raw)
        if protocol != 0x888E or len(raw) < offset + 4:
            raise ValueError("Expected an EAPOL-only capture")
        truncated += len(raw) != packet["original_length"]
        kind = raw[offset + 1]
        declared = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        available = raw[offset + 4 :]
        # The original's private echo intentionally advertises 30 bytes while
        # handing 27 bytes to pcap. Admit only that verified encoded structure;
        # ordinary truncated EAP/EAPOL remains an error.
        def reverse_complement(value):
            return int(f"{value:08b}"[::-1], 2) ^ 0xff
        decoded_echo = bytes(reverse_complement(value) for value in available[:27])
        legacy_echo = bool(
            kind == 0xbf and raw[offset] == 1 and declared == 30 and len(available) >= 27
            and decoded_echo[:6] == bytes.fromhex("000013110106")
            and decoded_echo[10:16] == bytes.fromhex("000013110106")
            and decoded_echo[20:27] == bytes.fromhex("00001311010300")
        )
        legacy_short_body = legacy_echo and len(available) == 27
        if offset + 4 + declared > len(raw) and not legacy_short_body:
            raise ValueError("Truncated EAPOL payload")
        body = raw[offset + 4 : offset + 4 + declared]
        item = {
            "time": datetime.datetime.fromtimestamp(packet["timestamp"], LOCAL).isoformat(timespec="milliseconds"),
            "frame_bytes": len(raw),
            "eapol_payload_bytes": declared,
            "trailing_bytes": max(0, len(raw) - offset - 4 - declared),
        }
        if legacy_short_body:
            item["legacy_short_body"] = True
            item["actual_eapol_payload_bytes"] = 27
        if kind in (1, 2):
            item["kind"] = "start" if kind == 1 else "logoff"
            if kind == 1 and start is None:
                start = packet["timestamp"]
        elif kind == 0 and len(body) >= 4:
            code, identifier = body[:2]
            item["kind"] = {1: "request", 2: "response", 3: "success", 4: "failure"}.get(code, "other_eap")
            item["identifier"] = identifier
            if code in (1, 2) and len(body) >= 5:
                method = body[4]
                item["method"] = {1: "identity", 4: "md5"}.get(method, "other")
                if method == 4 and len(body) >= 22 and body[5] == 16:
                    if code == 1 and challenge is None:
                        challenge = body[6:22]
                    if code == 2 and response is None:
                        response = body[6:22]
            if code == 3 and accepted is None:
                accepted = packet["timestamp"]
        else:
            item["kind"] = "legacy_echo" if legacy_echo else "other_eapol"
        sequence.append(item)
    return {
        "packet_count": len(sequence),
        "truncated_packets": truncated,
        "server_success_observed": accepted is not None,
        "start_to_success_ms": round((accepted - start) * 1000, 3) if start and accepted else None,
        "sequence": sequence,
        "_challenge": challenge,
        "_response": response,
    }


def summarize(directory, baseline=None):
    status = json.loads((directory / "status.json").read_text(encoding="utf-8-sig"))
    events = read_events(directory / "events.jsonl")
    counts = collections.Counter(item["event"] for item in events)
    supervisor_events = read_events(directory / "events.jsonl.supervisor.jsonl")
    supervisor_counts = collections.Counter(item["event"] for item in supervisor_events)
    accepted = next((item for item in events if item["event"] == "authentication_success"), None)
    completed = next((item for item in events if item["event"] == "online_test_completed"), None)
    starts = [item for item in events if item["event"] == "online_observation_started" and (not completed or parse_time(item["time"]) <= parse_time(completed["time"]))]
    observation_start = starts[-1] if starts else accepted
    probes = [item for item in events if item["event"] in ("internet_probe_ok", "internet_probe_failed")]
    if observation_start and completed:
        probes = [item for item in probes if parse_time(observation_start["time"]) <= parse_time(item["time"]) <= parse_time(completed["time"])]
    direct = read_events(directory / "ethernet-probes.jsonl")
    # Preserve setup errors separately. They occurred before any network request
    # and must not be mistaken for a loss of the authenticated session.
    first_direct_success = next((i for i, item in enumerate(direct) if item["event"].endswith("_ok")), len(direct))
    setup_errors = [item for item in direct[:first_direct_success] if item.get("failed_stage") == "adapter_configuration"]
    monitored_direct = [item for item in direct if item not in setup_errors]
    if observation_start and completed:
        monitored_direct = [item for item in monitored_direct if parse_time(observation_start["time"]) <= parse_time(item["time"]) <= parse_time(completed["time"])]
    capture = capture_summary(directory / "authentication.pcapng")
    native_challenge = capture.pop("_challenge")
    native_response = capture.pop("_response")
    if baseline:
        original = capture_summary(baseline)
        capture["challenge_differs_from_original_capture"] = native_challenge is not None and native_challenge != original["_challenge"]
        capture["response_differs_from_original_capture"] = native_response is not None and native_response != original["_response"]
    direct_stats = probe_statistics(monitored_direct)
    direct_stats["setup_errors_before_first_probe"] = len(setup_errors)
    direct_stats["original_client_conflicts"] = sum(item.get("original_client_present", False) for item in monitored_direct)
    result = {
        "recorded_at": datetime.datetime.now(LOCAL).isoformat(timespec="seconds"),
        "phase": status["phase"],
        "planned_online_seconds": status["duration_seconds"],
        "authenticated_at": local_time(accepted["time"]) if accepted else None,
        "observation_started_at": local_time(observation_start["time"]) if observation_start else None,
        "completed_at": local_time(completed["time"]) if completed else None,
        "observed_online_seconds": round((parse_time(completed["time"]) - parse_time(observation_start["time"])).total_seconds(), 3) if observation_start and completed else None,
        "native_exit_code": status["native_exit_code"],
        "controller_reported_original_restored": status["original_restored"],
        "original_authentication_verified": status.get("original_authentication_verified"),
        "native_error_count": counts["error"],
        "event_counts": dict(sorted(counts.items())),
        "supervisor_event_counts": dict(sorted(supervisor_counts.items())),
        "worker_crashes": supervisor_counts["worker_crashed"],
        "system_route_http_probes": probe_statistics(probes),
        "physical_ethernet_probes": direct_stats,
        "authentication_capture": capture,
        "capture_sha256": hashlib.sha256((directory / "authentication.pcapng").read_bytes()).hexdigest(),
    }
    result["authentication_and_online_passed"] = bool(
        completed and accepted
        and completed["value"] >= status["duration_seconds"]
        and capture["server_success_observed"] and not counts["error"]
        and not counts["unsupported_maintenance"] and not counts["invalid_maintenance_parameters"]
        and not any(item.get("value") == 0 for item in events if item["event"] == "maintenance_supported")
        and not any(counts[name] for name in ("sam_transport_lost", "sam_send_failed", "sam_packet_expired", "sam_queue_full"))
        and probes and not any(item["event"].endswith("_failed") for item in probes)
        and direct_stats["successful"] and not direct_stats["failed"]
        and not direct_stats["original_client_conflicts"]
    )
    result["connection_retained_after_observation"] = bool(
        counts["online_test_holding_connection"]
        and status["phase"] in ("online_test_passed_connection_held", "online_test_failed_connection_held")
        and status["native_exit_code"] is None
        and status.get("native_connected", True)
    )
    audit_path = directory / "restoration-audit.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8-sig")) if audit_path.exists() else None
    if audit:
        result["restoration_audit"] = audit
        result["original_authentication_verified"] = audit["original_authentication_verified"]
    result["handoff_passed"] = bool(
        result["connection_retained_after_observation"] or
        (status.get("original_authentication_verified") and (not audit or audit["automatic_handoff_passed"]))
    )
    result["passed"] = result["authentication_and_online_passed"] and result["handoff_passed"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = summarize(args.directory, args.baseline)
    serialized = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
