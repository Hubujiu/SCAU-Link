"""Actual subprocess fault injection; never touches real SCAU settings/network."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import network_lab as lab
from passive_eap_probe import metadata
from network_lab_windows import alive, identity, terminate, NO_WINDOW


class OfflineRecoveryTests(unittest.TestCase):
    def test_process_exit_during_identity_read_is_not_a_live_identity_failure(self):
        class Kernel:
            def __init__(self, exits):self.exits=exits;self.waits=0
            def WaitForSingleObject(self,*args):
                self.waits+=1
                return 0 if self.exits and self.waits>1 else 258
            def QueryFullProcessImageNameW(self,*args):return False
        with patch.object(lab.win,'K',Kernel(True)):
            self.assertIsNone(identity(123,handle=1))
        with patch.object(lab.win,'K',Kernel(False)):
            with self.assertRaisesRegex(RuntimeError,'process_identity_unavailable'):
                identity(123,handle=1)
    def sharing_lock(self, path):
        import ctypes
        from ctypes import wintypes
        kernel = lab.win.K
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        return handle

    def test_journal_retries_real_windows_sharing_locks(self):
        with tempfile.TemporaryDirectory(prefix='scau-offline-sharing-') as directory:
            path = Path(directory) / 'heartbeat.json'
            lab.atomic(path, {'sequence': 1})
            handle = self.sharing_lock(path)
            release = None
            try:
                with self.assertRaises(PermissionError):
                    path.read_text(encoding='utf-8')
                release = threading.Timer(.15, lab.win.K.CloseHandle, args=(handle,))
                release.start()
                self.assertEqual(lab.read(path), {'sequence': 1})
                release.join()
            finally:
                if release:
                    release.join()
                else:
                    lab.win.K.CloseHandle(handle)
            handle = self.sharing_lock(path)
            release = None
            try:
                release = threading.Timer(.15, lab.win.K.CloseHandle, args=(handle,))
                release.start()
                lab.atomic(path, {'sequence': 2})
                release.join()
            finally:
                if release:
                    release.join()
                else:
                    lab.win.K.CloseHandle(handle)
            self.assertEqual(lab.read(path), {'sequence': 2})
            self.assertFalse(list(path.parent.glob('*.tmp')))

    def test_journal_persistent_sharing_denial_is_reported(self):
        with tempfile.TemporaryDirectory(prefix='scau-offline-sharing-') as directory:
            path = Path(directory) / 'heartbeat.json'
            lab.atomic(path, {'sequence': 1})
            handle = self.sharing_lock(path)
            try:
                started = time.monotonic()
                with self.assertRaises(PermissionError):
                    lab.atomic(path, {'sequence': 2})
                self.assertLess(time.monotonic() - started, 3)
            finally:
                lab.win.K.CloseHandle(handle)
            self.assertEqual(lab.read(path), {'sequence': 1})
            self.assertFalse(list(path.parent.glob('*.tmp')))

    def test_restore_rejects_stale_or_worker_only_authentication(self):
        import datetime
        born = datetime.datetime.fromisoformat('2026-11-14T09:00:00Z').timestamp()
        original = {'born': int((born + 11644473600) * 10000000)}
        event = dict(source='desktop', event='worker_authenticated', recorded_at='2026-11-14T08:59:59Z')
        self.assertFalse(lab.fresh_authentication([event], original))
        self.assertFalse(lab.fresh_authentication([dict(event, recorded_at='invalid')], original))
        self.assertFalse(lab.fresh_authentication([dict(event, source='worker', recorded_at='2026-11-14T09:00:01Z')], original))
        self.assertTrue(lab.fresh_authentication([dict(event, recorded_at='2026-11-14T09:00:01Z')], original))

    def test_passive_eap_metadata_does_not_export_identity_or_payload(self):
        import struct
        local = b'\x02\x01\x02\x03\x04\x05'
        ethernet = b'\x01\x80\xc2\x00\x00\x03' + local + b'\x88\x8e'
        secret = b'SECRET_USERNAME_AND_PAYLOAD'
        eap = struct.pack('!BBH', 2, 7, 5 + len(secret)) + b'\x01' + secret
        packet = ethernet + struct.pack('!BBH', 1, 0, len(eap)) + eap
        value = metadata(packet, local)
        self.assertEqual(value['method'], 1)
        self.assertEqual(value['direction'], 'tx')
        self.assertNotIn('SECRET', json.dumps(value))
        for i in range(len(packet)):
            self.assertIsNone(metadata(packet[:i], local))

    def test_pid_reuse_guard(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(40)'], creationflags=NO_WINDOW)
        actual = identity(child.pid)
        try:
            wrong = dict(actual, born=actual['born'] + 1)
            self.assertFalse(terminate(wrong))
            self.assertTrue(alive(actual))
            wrong = dict(actual, path=str(ROOT / 'not-the-process.exe'))
            self.assertFalse(terminate(wrong))
            self.assertTrue(alive(actual))
        finally:
            terminate(actual)
            child.wait(10)

    def test_offline_failure_recovers(self):
        self.run_fault('offline_failure')

    def test_controller_crash_recovers(self):
        self.run_fault('controller_crash')

    def test_hung_controller_recovers(self):
        self.run_fault('controller_hang')

    def test_watchdog_crash_controller_recovers(self):
        self.run_fault('watchdog_crash')

    def test_manual_stop_restores(self):
        self.run_fault('manual_stop')

    def test_hard_deadline_restores_despite_live_heartbeat(self):
        self.run_fault('hard_deadline')

    def test_heartbeat_continues_during_slow_restore(self):
        self.run_fault('offline_failure', restore_delay=3)

    def test_corrupt_backup_still_starts_fallback_and_reports_failure(self):
        self.run_fault('corrupt_backup')

    def run_fault(self, fault, restore_delay=0):
        with tempfile.TemporaryDirectory(prefix='scau-offline-lab-') as directory:
            run = Path(directory)
            (run / 'FIXTURE').touch()
            data = run / 'fixture-data'
            data.mkdir()
            original = b'[Desktop]\r\nMiniMode=1\r\nConnectionMode=0\r\n[Other]\r\nKeep=unchanged\r\n'
            (data / 'settings.ini').write_bytes(original)
            cfg = dict(schema=1, fixture=True, fault=fault, dataDirectory=str(data),
                       heartbeatSeconds=2, deadlineSeconds=12, testCore='fixture', restoreDelay=restore_delay,temporaryDhcp=True)
            original_ip = {'dhcp':False,'dns':'original_static_setting'}
            lab.atomic(run / 'fixture-ip.json',original_ip)
            if fault == 'hard_deadline':
                cfg.update(heartbeatSeconds=15, deadlineSeconds=2)
            lab.atomic(run / 'config.json', cfg)
            process = subprocess.Popen([sys.executable, lab.SCRIPT, 'run', '--run', run], creationflags=NO_WINDOW)
            outer = identity(process.pid)
            try:
                if fault == 'manual_stop':
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline and not (run / 'mutated.json').exists():
                        time.sleep(.05)
                    (run / 'STOP').touch()
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline and not (run / 'restored.json').exists():
                    time.sleep(.1)
                restored = lab.read(run / 'restored.json', {})
                self.assertEqual(lab.read(run / 'fixture-ip.json'),original_ip)
                self.assertTrue(restored.get('wireless_ip_restored'))
                if fault == 'corrupt_backup':
                    self.assertFalse(restored.get('ok'))
                    self.assertTrue(restored.get('bound_ethernet'))
                    self.assertFalse(restored.get('settings_restored'))
                else:
                    self.assertTrue(restored.get('ok'), (fault, restored))
                    self.assertEqual((data / 'settings.ini').read_bytes(), original)
                active = lab.read(run / 'active-test.json', {}).get('desktop')
                self.assertIsNotNone(active)
                self.assertFalse(alive(active), 'The failed test application must be stopped')
                self.assertTrue(alive(restored['original']), 'Fallback process must run independently')
                self.assertTrue((run / 'controller.jsonl').is_file())
                self.assertTrue((run / 'watchdog.jsonl').is_file())
                if fault != 'watchdog_crash':
                    process.wait(10)
                    watchdog_log = (run / 'watchdog.jsonl').read_text(encoding='utf-8')
                    if fault == 'hard_deadline':
                        self.assertIn('hard_deadline', watchdog_log)
                    if restore_delay:
                        self.assertNotIn('controller_heartbeat_timeout', watchdog_log)
                else:
                    self.assertEqual(process.wait(10), 92)
            finally:
                for file, key in [('active-test.json', 'desktop'), ('restored.json', 'original')]:
                    record = lab.read(run / file, {}).get(key)
                    if record:
                        terminate(record)
                controller = lab.read(run / 'controller-identity.json')
                if controller:
                    end = time.monotonic() + 3
                    while alive(controller) and time.monotonic() < end:
                        time.sleep(.1)
                    terminate(controller)
                if outer:
                    terminate(outer)
                process.wait(10)

    def test_empty_settings_restores_absence(self):
        with tempfile.TemporaryDirectory(prefix='scau-offline-settings-') as directory:
            run = Path(directory)
            cfg = {'dataDirectory': str(run)}
            settings = lab.save_settings(run, cfg)
            lab.set_mode(cfg, 2)
            self.assertTrue((run / 'settings.ini').exists())
            lab.restore_settings(run, cfg, {'settings': settings})
            self.assertFalse((run / 'settings.ini').exists())

    def test_corrupt_backup_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='scau-offline-settings-') as directory:
            run = Path(directory)
            cfg = {'dataDirectory': str(run)}
            settings = lab.save_settings(run, cfg)
            (run / 'settings.before.bin').write_bytes(b'corrupt')
            with self.assertRaisesRegex(RuntimeError, 'settings_backup_integrity_failed'):
                lab.restore_settings(run, cfg, {'settings': settings})

    def test_logs_exclude_credential_fields_and_ignore_partial_records(self):
        with tempfile.TemporaryDirectory(prefix='scau-offline-logs-') as directory:
            run = Path(directory)
            logs = run / 'logs'
            logs.mkdir()
            cursor = lab.Cursor({'dataDirectory': str(run)})
            target = logs / 'desktop.jsonl'
            target.write_text('{"event":"worker_authenticated","username":"SECRET_USER","password":"SECRET_PASSWORD","detail":"SECRET_TOKEN"}\n{"event":"worker_', encoding='utf-8')
            first = cursor.poll(run, 'fixture')
            self.assertEqual(len(first), 1)
            with target.open('a', encoding='utf-8') as f:
                f.write('terminal","value":4}\n')
            self.assertEqual(cursor.poll(run, 'fixture')[0]['value'], 4)
            with target.open('a', encoding='utf-8') as f:
                f.write('{"event":"wlan_8021x_connect_requested"}\n')
            self.assertEqual(cursor.poll(run, 'fixture')[0]['event'], 'wlan_8021x_connect_requested')
            text = (run / 'controller.jsonl').read_text(encoding='utf-8')
            self.assertNotIn('SECRET_', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
