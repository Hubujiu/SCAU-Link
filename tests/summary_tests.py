"""Offline regression for legacy private frames and recovered observation windows."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import summarize_native_test as summary


ECHO = bytes.fromhex(
    "020000000002020000000001888e01bf001e"
    "ffff37777f9fb7db93edffff37777f9f77bb33ddffff37777f3fff"
)


def inspect(frame):
    row = {"frame": frame, "timestamp": 1794441600.0, "original_length": len(frame)}
    with patch.object(summary, "capture_packets", return_value=iter([row])):
        return summary.capture_summary(Path("unused-synthetic.pcapng"))


class CaptureTests(unittest.TestCase):
    def test_original_echo_and_padded_wire_form(self):
        result = inspect(ECHO)["sequence"][0]
        self.assertEqual(result["kind"], "legacy_echo")
        self.assertTrue(result["legacy_short_body"])
        self.assertEqual(result["actual_eapol_payload_bytes"], 27)
        padded = inspect(ECHO + bytes(15))["sequence"][0]
        self.assertEqual(padded["kind"], "legacy_echo")
        self.assertNotIn("legacy_short_body", padded)

    def test_other_truncations_still_rejected(self):
        for frame in (ECHO[:-1], ECHO[:18] + bytes(27), bytes.fromhex("020000000002020000000001888e0100000803070004")):
            with self.subTest(length=len(frame)):
                with self.assertRaisesRegex(ValueError, "Truncated EAPOL"):
                    inspect(frame)


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="scau-summary-")
        self.directory = Path(self.temporary.name)
        self.status = {"phase": "online_test_passed_connection_held", "duration_seconds": 10,
                       "native_exit_code": None, "original_restored": None, "native_connected": True}
        self.events = [self.event(0, "authentication_success"), self.event(0, "online_observation_started"),
                       self.event(3, "internet_probe_failed"), self.event(5, "online_observation_reset"),
                       self.event(15, "reauthentication_success"), self.event(15, "online_observation_started"),
                       self.event(20, "internet_probe_ok"), self.event(25, "online_test_completed", value=10),
                       self.event(25, "online_test_holding_connection")]
        self.direct = [self.event(3, "ethernet_probe_failed"), self.event(20, "ethernet_probe_ok")]
        (self.directory / "authentication.pcapng").write_bytes(b"synthetic fixture")

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def event(second, name, **fields):
        return {"time": f"2026-11-12T00:00:{second:02d}.000Z", "event": name, **fields}

    def result(self):
        (self.directory / "status.json").write_text(json.dumps(self.status), encoding="utf-8")
        for filename, rows in (("events.jsonl", self.events), ("ethernet-probes.jsonl", self.direct)):
            (self.directory / filename).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        capture = {"server_success_observed": True, "_challenge": None, "_response": None}
        with patch.object(summary, "capture_summary", return_value=copy.deepcopy(capture)):
            return summary.summarize(self.directory)

    def test_recovery_starts_a_new_continuous_window(self):
        result = self.result()
        self.assertEqual(result["observed_online_seconds"], 10)
        self.assertEqual(result["system_route_http_probes"]["failed"], 0)
        self.assertEqual(result["physical_ethernet_probes"]["failed"], 0)
        self.assertTrue(result["passed"])

    def test_unsupported_maintenance_cannot_pass(self):
        self.events.insert(6, self.event(16, "unsupported_maintenance"))
        self.assertFalse(self.result()["authentication_and_online_passed"])

    def test_recovering_core_is_not_a_confirmed_retained_connection(self):
        self.status["native_connected"] = False
        result = self.result()
        self.assertFalse(result["connection_retained_after_observation"])
        self.assertFalse(result["passed"])

    def test_sam_transport_failure_cannot_pass(self):
        self.events.insert(6, self.event(16, "sam_transport_lost"))
        self.assertFalse(self.result()["authentication_and_online_passed"])

    def test_unavailable_bound_sam_port_cannot_pass(self):
        self.events.insert(8, self.event(25, "maintenance_supported", value=0))
        self.assertFalse(self.result()["authentication_and_online_passed"])

    def test_worker_crash_is_reported_separately(self):
        path = self.directory / "events.jsonl.supervisor.jsonl"
        path.write_text(json.dumps(self.event(5, "worker_crashed", value=1)) + "\n", encoding="utf-8")
        self.assertEqual(self.result()["worker_crashes"], 1)


if __name__ == "__main__":
    unittest.main()
