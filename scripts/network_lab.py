"""Offline-capable SCAU Link experiment. Run through Test-NetworkDelivery.ps1.

The independent watchdog and controller both know how to restore the original
client. Every live run ends in rollback, including a successful experiment.
"""
import argparse
from contextlib import contextmanager
import datetime as DT
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

import network_lab_windows as win

SCRIPT = Path(__file__).resolve()


def utc():
    return DT.datetime.now(DT.timezone.utc).isoformat(timespec="milliseconds")


def read(path, default=None):
    deadline = time.monotonic() + 1
    while True:
        try:
            return json.loads(Path(path).read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            return default
        except PermissionError:
            # A short-lived Windows reader/antivirus sharing lock is not a
            # controller failure. Persistent denial remains a real failure.
            if time.monotonic() >= deadline:
                raise
            time.sleep(.02)


def atomic(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + "." + str(os.getpid()) + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    deadline = time.monotonic() + 1
    try:
        while True:
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                # Python readers on Windows may briefly deny DELETE sharing.
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.02)
    finally:
        tmp.unlink(missing_ok=True)


def exception_codes(error):
    # Preserve enough evidence for local failures without paths/exception text.
    return {"exception_type": type(error).__name__,
            "errno": getattr(error, "errno", None),
            "winerror": getattr(error, "winerror", None)}


def event(run, event_name, **fields):
    # Callers supply fixed event names, numeric values, booleans and safe codes.
    value = dict(time=utc(), event=event_name, **fields)
    with (run / ("watchdog.jsonl" if os.environ.get("SCAU_LAB_WATCHDOG") else "controller.jsonl")).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextmanager
def file_lock(path, wait=0):
    import msvcrt
    path = Path(path)
    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        deadline = time.monotonic() + wait
        while True:
            try:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("another_experiment_or_restorer_is_active")
                time.sleep(.1)
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def spawn(args, cwd=None):
    process = subprocess.Popen([str(a) for a in args], cwd=cwd, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=win.NO_WINDOW, close_fds=True)
    result = win.identity(process.pid)
    if not result:
        raise RuntimeError("new_process_exited_early")
    return result


def check_hashes(cfg, original_only=False):
    for item in cfg["binaries"]:
        if original_only and not any(win.same_path(item["path"], cfg[k]) for k in ("originalApp", "originalCore")):
            continue
        if sha(item["path"]) != item["sha256"].lower():
            raise RuntimeError("binary_hash_mismatch")


def save_settings(run, cfg):
    target = Path(cfg["dataDirectory"]) / "settings.ini"
    present = target.exists()
    content = target.read_bytes() if present else b""
    if len(content) > 65536:
        raise RuntimeError("settings_size_invalid")
    # This file contains UI settings only; credentials stay in Credential Manager.
    backup = run / "settings.before.bin"
    with backup.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return {"present": present, "sha256": sha(backup)}


def restore_settings(run, cfg, snapshot):
    backup = run / "settings.before.bin"
    if sha(backup) != snapshot["settings"]["sha256"]:
        raise RuntimeError("settings_backup_integrity_failed")
    target = Path(cfg["dataDirectory"]) / "settings.ini"
    if snapshot["settings"]["present"]:
        temporary = target.with_name("settings.lab-restore.tmp")
        with temporary.open("wb") as stream:
            stream.write(backup.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    else:
        target.unlink(missing_ok=True)


def set_mode(cfg, mode):
    target = Path(cfg["dataDirectory"]) / "settings.ini"
    # Preserve every other INI section/key using the same Windows INI API as the app.
    kernel = win.K
    import ctypes as C
    from ctypes import wintypes as W
    kernel.WritePrivateProfileStringW.argtypes = [W.LPCWSTR] * 4
    if not kernel.WritePrivateProfileStringW("Desktop", "ConnectionMode", str(mode), str(target)):
        raise RuntimeError("test_mode_write_failed")
    kernel.WritePrivateProfileStringW(None, None, None, str(target))


def live_children(parent, executable):
    output = []
    if not win.alive(parent):
        return output
    for p in win.processes():
        if p["parent"] == parent["pid"] and p.get("path") and win.same_path(p["path"], executable):
            item = win.identity(p["pid"])
            if item:
                item["stop"] = p.get("stop", "")
                output.append(item)
    return output


def stop_desktop(run, cfg, desktop, core, graceful=True):
    if cfg.get("fixture"):
        if desktop:
            win.terminate(desktop)
        return True
    if not desktop or not win.alive(desktop):
        return True
    workers = live_children(desktop, core)
    if graceful:
        for worker in workers:
            win.signal_stop(worker.get("stop"))
        end = time.monotonic() + 8
        while any(win.alive(p) for p in workers) and time.monotonic() < end:
            time.sleep(.1)
    clean_exit = all(not win.alive(p) for p in workers)
    # The app has a kill-on-close job as an additional child-process safeguard.
    win.terminate(desktop)
    for worker in workers:
        if win.alive(worker):
            win.terminate(worker)
    event(run, "desktop_stopped", graceful_worker_exit=clean_exit)
    return clean_exit


def current_test(run):
    return read(run / "active-test.json", {})


def start_test(run, cfg, mode):
    if cfg.get("fixture"):
        app = spawn([sys.executable, SCRIPT, "fixture-app", "--run", run])
    else:
        set_mode(cfg, mode)
        app = win.start_desktop_unelevated(cfg['testApp']) if cfg.get('temporaryDhcp') else spawn([cfg["testApp"], "--silent"], str(Path(cfg["testApp"]).parent))
    atomic(run / "active-test.json", {"desktop": app, "mode": mode})
    event(run, "test_desktop_started", mode=mode, pid=app["pid"])
    return app


def preflight(run, cfg):
    if cfg.get("fixture"):
        settings = save_settings(run, cfg)
        if cfg.get("temporaryDhcp"):
            (run / "private").mkdir(exist_ok=True)
            atomic(run / "private/wlan-ip.before.json", read(run / "fixture-ip.json"))
        return {"settings": settings, "original": None, "ownedProfiles": [], "accountsHash": "fixture", "wiredIndex": 0}
    context = win.context()
    if context["sid"] != cfg["expectedSid"] or not win.same_path(Path(context["local"]) / "ScauLink", cfg["dataDirectory"]):
        raise RuntimeError("wrong_user_or_virtualized_appdata_context")
    if cfg.get("temporaryDhcp") and not context['elevated']:
        raise RuntimeError("administrator_required_for_temporary_wireless_ip_configuration")
    check_hashes(cfg)
    catalog = Path(cfg["dataDirectory"]) / "accounts.dat"
    data = catalog.read_bytes()
    if len(data) < 12 or data[:8] != b"SCAUAC02" or not 1 <= int.from_bytes(data[8:12], "little") <= 64:
        raise RuntimeError("saved_accounts_unavailable")
    items = win.processes()
    desktops = [p for p in items if p.get("path") and win.same_path(p["path"], cfg["originalApp"])]
    if len(desktops) != 1 or any(Path(p.get("path") or "unknown").name.lower() == "8021x.exe" for p in items):
        raise RuntimeError("original_client_identity_or_conflict")
    if any(p.get("path") and win.same_path(p["path"], cfg["testApp"]) for p in items):
        raise RuntimeError("test_client_already_running")
    original = win.identity(desktops[0]["pid"])
    if not original or len(live_children(original, cfg["originalCore"])) != 1:
        raise RuntimeError("original_authentication_worker_unavailable")
    if not win.can_control(original) or not all(win.can_control(w) for w in live_children(original, cfg["originalCore"])):
        raise RuntimeError("original_process_access_insufficient")
    adapters = win.adapters()
    wired = [a for a in adapters if a["medium"] == 14 and a["status"] == "Up"]
    wifi = [a for a in adapters if a["medium"] == 9]
    if len(wired) != 1 or len(wifi) != 1 or wifi[0]["status"] != "Disconnected":
        raise RuntimeError("requires_working_ethernet_and_initially_disconnected_wifi")
    import ctypes as C
    from ctypes import wintypes as W
    win.K.GetPrivateProfileIntW.argtypes = [W.LPCWSTR, W.LPCWSTR, C.c_int, W.LPCWSTR]
    if win.K.GetPrivateProfileIntW("Desktop", "ConnectionMode", 0, str(catalog.parent / "settings.ini")) != 0:
        raise RuntimeError("original_mode_is_not_wired")
    baseline = win.probe(wired[0]["index"])
    atomic(run / "baseline.json", baseline)
    if not baseline["ok"]:
        raise RuntimeError("original_bound_ethernet_baseline_failed")
    settings = save_settings(run, cfg)
    if cfg.get("temporaryDhcp"):
        (run / "private").mkdir(exist_ok=True)
        atomic(run / "private/wlan-ip.before.json", win.ip_snapshot(wifi[0]["index"]))
    if cfg.get('probeKind') in ('wireless-web','fresh-wireless-web','wireless-8021x','backend-web','backend-1x'):
        (run / 'private').mkdir(exist_ok=True)
        atomic(run / 'private/stable-profiles.before.json',win.stable_wlan_profiles(wifi[0]['index']))
    snapshot = {"settings": settings, "original": original, "ownedProfiles": win.owned_profiles(),
                "accountsHash": sha(catalog), "wiredIndex": wired[0]["index"], "wifiIndex": wifi[0]["index"]}
    atomic(run / "preflight.json", {"time": utc(), "ok": True, "context_verified": True,
                                   "saved_account_count": int.from_bytes(data[8:12], "little"),
                                   "binary_hashes_verified": True, "original_pid": original["pid"],
                                   "wired_index": snapshot["wiredIndex"], "wifi_index": snapshot["wifiIndex"]})
    return snapshot


def prepare_test_network(run, cfg):
    if not cfg.get("temporaryDhcp") or (run / "ip-change-intent.json").exists():
        return
    atomic(run / "ip-change-intent.json", {"time": utc()})
    if cfg.get("fixture"):
        atomic(run / "fixture-ip.json", {"dhcp": True, "dns": "automatic"})
    else:
        win.configure_test_ip(run / "private/wlan-ip.before.json")
    event(run, "temporary_wireless_dhcp_enabled")


class Cursor:
    def __init__(self, cfg):
        self.directory = Path(cfg["dataDirectory"]) / "logs"
        self.offsets = {p: p.stat().st_size for p in self.paths()}
        self.pending = {}

    def paths(self):
        return list(self.directory.glob("session-*.jsonl")) + list(self.directory.glob("desktop.jsonl"))

    def poll(self, run, phase):
        result = []
        for path in self.paths():
            offset = self.offsets.get(path, 0)
            with path.open("rb") as stream:
                if path.stat().st_size < offset:
                    raise RuntimeError("authentication_log_rotated_during_test")
                stream.seek(offset)
                raw = stream.read(1024 * 1024)
                self.offsets[path] = stream.tell()
            raw = self.pending.pop(path, b"") + raw
            lines = raw.split(b"\n")
            self.pending[path] = lines.pop()
            for line in lines:
                try:
                    value = json.loads(line)
                except (ValueError, UnicodeError):
                    continue
                name = value.get("event", "")
                if not re.fullmatch("[a-z][a-z0-9_]{0,79}", name):
                    continue
                # Only copy safe keys. Never copy server text, addresses, URLs or usernames.
                clean = {"event": name, "phase": phase, "source": "desktop" if path.name == "desktop.jsonl" else "worker"}
                stamp = value.get("time", "")
                if isinstance(stamp, str) and re.fullmatch(r"[0-9T:.+Z-]{10,40}", stamp):
                    clean["recorded_at"] = stamp
                if isinstance(value.get("value"), (int, float)):
                    clean["value"] = value["value"]
                event(run, "auth_event", **{k: v for k, v in clean.items() if k != "event"}, name=name)
                result.append(clean)
        return result


def abort_check(run, watchdog):
    if (run / "STOP").exists():
        raise RuntimeError("manual_stop_requested")
    if not win.alive(watchdog):
        raise RuntimeError("watchdog_lost_controller_will_restore")


def wait_auth(run, cfg, desktop, cursor, phase, watchdog, timeout=100):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        abort_check(run, watchdog)
        if not win.alive(desktop):
            raise RuntimeError("test_desktop_exited")
        events = cursor.poll(run, phase)
        for e in events:
            if e["source"] != "desktop":
                continue
            if e["event"] == "worker_authenticated":
                return
            if e["event"] in ("worker_terminal", "accounts_exhausted", "desktop_authentication_error", "original_client_conflict", "supervisor_error"):
                raise RuntimeError("authentication_terminal_" + str(e.get("value", "unknown")))
        time.sleep(.25)
    raise RuntimeError("authentication_deadline_exceeded")


def checked_probe(run, index, phase):
    value = win.probe(index)
    event(run, "connectivity_probe", phase=phase, **value)
    return value["ok"]


def fresh_authentication(events, original):
    born = original["born"] / 10000000 - 11644473600
    for item in events:
        if item["source"] != "desktop" or item["event"] != "worker_authenticated":
            continue
        try:
            if DT.datetime.fromisoformat(item.get("recorded_at", "")).timestamp() >= born:
                return True
        except (ValueError, OverflowError):
            continue
    return False


def test_mode(run, cfg, snapshot, mode, watchdog):
    phase = "wired" if mode == 0 else "wireless_8021x"
    outcome = {"mode": mode, "phase": phase, "status": "running", "started_at": utc(), "authentication": False,
               "internet": False, "crash_recovery": False, "observation": False, "disconnect": False}
    atomic(run / (phase + ".json"), outcome)
    cursor, desktop = Cursor(cfg), None
    try:
        if mode == 2:
            prepare_test_network(run, cfg)
        desktop = start_test(run, cfg, mode)
        wait_auth(run, cfg, desktop, cursor, phase, watchdog)
        outcome["authentication"] = True
        atomic(run / (phase + ".json"), outcome)
        index = snapshot["wiredIndex"] if mode == 0 else snapshot["wifiIndex"]
        # Allow DHCP to complete after the successful EAP association.
        dhcp_deadline = time.monotonic() + 45
        while time.monotonic() < dhcp_deadline:
            abort_check(run, watchdog)
            if checked_probe(run, index, phase + "_initial"):
                outcome["internet"] = True
                break
            time.sleep(2)
        if not outcome["internet"]:
            raise RuntimeError("authenticated_but_bound_internet_unavailable")
        atomic(run / (phase + ".json"), outcome)
        workers = live_children(desktop, cfg["testCore"])
        if len(workers) != 1:
            raise RuntimeError("test_worker_identity_not_unique")
        # Drain pre-crash events so a buffered prior success cannot count as recovery.
        cursor.poll(run, phase)
        event(run, "crash_injected", phase=phase, pid=workers[0]["pid"])
        win.terminate(workers[0])
        wait_auth(run, cfg, desktop, cursor, phase + "_recovery", watchdog)
        replacement = live_children(desktop, cfg["testCore"])
        if len(replacement) != 1 or replacement[0]["pid"] == workers[0]["pid"]:
            raise RuntimeError("replacement_worker_not_verified")
        recovered_internet = False
        dhcp_deadline = time.monotonic() + 45
        while time.monotonic() < dhcp_deadline:
            abort_check(run, watchdog)
            if checked_probe(run, index, phase + "_recovered"):
                recovered_internet = True
                break
            time.sleep(2)
        if not recovered_internet:
            raise RuntimeError("recovered_authentication_without_bound_internet")
        outcome["crash_recovery"] = True
        atomic(run / (phase + ".json"), outcome)
        end, count = time.monotonic() + cfg["observationSeconds"], 0
        while time.monotonic() < end:
            abort_check(run, watchdog)
            updates = cursor.poll(run, phase + "_observation")
            if any(e["source"] == "desktop" and e["event"] in ("worker_unauthenticated", "worker_crashed", "worker_terminal", "accounts_exhausted") for e in updates):
                raise RuntimeError("connection_changed_during_observation")
            if not checked_probe(run, index, phase + "_observation"):
                raise RuntimeError("bound_internet_failed_during_observation")
            count += 1
            # Frequent abort checks, no dependency on the agent or internet.
            for _ in range(20):
                abort_check(run, watchdog)
                if time.monotonic() >= end:
                    break
                time.sleep(.5)
        outcome.update(observation=True, observation_probes=count)
    except Exception as exc:
        # Only our fixed exception code is retained, never arbitrary exception text.
        text = str(exc)
        outcome["failure"] = text if re.fullmatch(r"[a-z0-9_]{1,100}", text) else "local_test_error"
        event(run, "case_failed", phase=phase, code=outcome["failure"])
    finally:
        if desktop:
            clean_exit = stop_desktop(run, cfg, desktop, cfg["testCore"])
            outcome["disconnect"] = clean_exit and not win.alive(desktop)
        cursor.poll(run, phase)
        if mode == 2:
            try:
                atomic(run / "wlan-diagnostics.json", win.wlan_diagnostics(outcome["started_at"]))
                residual = win.owned_profiles()
                outcome["owned_profile_cleanup"] = not set(residual).difference(snapshot["ownedProfiles"])
            except Exception:
                outcome["diagnostics_available"] = False
        outcome["ended_at"] = utc()
        outcome["passed"] = all(outcome[k] for k in ("authentication", "internet", "crash_recovery", "observation", "disconnect"))
        outcome["status"] = "passed" if outcome["passed"] else "failed"
        atomic(run / (phase + ".json"), outcome)
    return outcome


def test_native_probe(run, cfg, snapshot, watchdog):
    outcome = {"phase": "native_credential_probe", "profile_store": cfg["probeKind"], "passed": False}
    trace = run / "credential-probe.jsonl"
    prepare_test_network(run, cfg)
    arguments=["--live-test", "--"+cfg['probeKind'], str(trace)]
    app = win.start_desktop_unelevated(cfg['credentialProbe'],arguments) if not cfg.get('fixture') else spawn([cfg['credentialProbe'],*arguments])
    atomic(run / "active-test.json", {"desktop": app, "mode": 2})
    end, authenticated, usable = time.monotonic() + (195 if cfg['probeKind'].startswith('backend-') else 125), False, False
    next_initial_probe=next_recovery_probe=0
    try:
        while time.monotonic() < end:
            abort_check(run, watchdog)
            values = []
            if trace.exists():
                for line in trace.read_text(encoding="utf-8").splitlines():
                    try:
                        values.append(json.loads(line))
                    except ValueError:
                        pass
            if not usable and any(v.get("event") in ("probe_authenticated","probe_network_available") for v in values):
                authenticated = any(v.get("event") == "probe_authenticated" for v in values)
                usable = True
                outcome["authentication"] = authenticated
                outcome["preexisting_network"] = not authenticated
            if usable and not outcome.get('internet') and time.monotonic()>=next_initial_probe:
                outcome["internet"] = checked_probe(run, snapshot["wifiIndex"], "native_credential_probe")
                next_initial_probe=time.monotonic()+1
            if 'crash_recovery' not in outcome and any(v.get('event') in ('probe_reauthenticated','probe_connection_recovered') for v in values):
                outcome['crash_recovery']=True
            if outcome.get('crash_recovery') and not outcome.get('recovery_internet') and time.monotonic()>=next_recovery_probe:
                outcome['recovery_internet']=checked_probe(run,snapshot['wifiIndex'],'native_worker_recovery')
                next_recovery_probe=time.monotonic()+1
            if not win.alive(app):
                outcome["package_balance"] = any(v.get("event") == "probe_package_balance" and v.get("value") == 1 for v in values)
                outcome['clean_terminal']=any(v.get('event')=='probe_terminal' and v.get('value')==0 for v in values)
                outcome["passed"] = usable and outcome.get("internet", False) and (
                    cfg['probeKind'] in ('current-user','all-user') or (outcome['package_balance'] and outcome['clean_terminal']))
                if cfg['probeKind'].startswith('backend-'):
                    outcome['passed']=outcome['passed'] and outcome.get('crash_recovery',False) and outcome.get('recovery_internet',False)
                break
            time.sleep(.2)
        else:
            outcome["failure"] = "native_credential_probe_deadline"
    finally:
        if win.alive(app):
            win.terminate(app)
        atomic(run / "native-credential-probe.json", outcome)
    return outcome


def test_web_discovery(run, cfg, snapshot, watchdog):
    prepare_test_network(run, cfg)
    helper = spawn([sys.executable, SCRIPT.parent / 'web_discovery_probe.py', '--run', run])
    atomic(run / 'active-test.json', {'desktop': helper, 'mode': 1})
    deadline = time.monotonic() + 120
    while win.alive(helper) and time.monotonic() < deadline:
        abort_check(run, watchdog)
        time.sleep(.25)
    if win.alive(helper):
        win.terminate(helper)
    return read(run / 'web-discovery.json', {'passed': False, 'failure': 'web_discovery_deadline'})


def rollback(run, cfg, reason):
    with file_lock(run / "restore.lock", 10):
        existing = read(run / "restored.json")
        if existing and existing.get("ok"):
            return existing
        snapshot = read(run / "snapshot.json")
        if not snapshot:
            return {"ok": True, "network_untouched": True}
        event(run, "restore_started", reason=reason)
        status = {"started_at": utc(), "ok": False, "settings_restored": False, "original_started": False,
                  "original_authentication": False, "bound_ethernet": False}
        try:
            active = current_test(run)
            stop_desktop(run, cfg, active.get("desktop"), cfg.get("testCore", ""))
            if not cfg.get("fixture"):
                # Recover a launch interrupted between CreateProcess and its
                # journal write. Only this controller's exact staged image qualifies.
                controller_id = read(run / "controller-identity.json", {})
                for p in win.processes():
                    owned_path=p.get('path') and (win.same_path(p['path'],cfg['testApp']) or
                        (cfg.get('credentialProbe') and win.same_path(p['path'],cfg['credentialProbe'])))
                    if owned_path and (p.get("parent") == controller_id.get("pid") or cfg.get('temporaryDhcp')):
                        candidate = win.identity(p["pid"])
                        if candidate and candidate["born"] >= controller_id.get("born", 0):
                            stop_desktop(run, cfg, candidate, cfg["testCore"])
            if (run / "ip-change-intent.json").exists():
                try:
                    if cfg.get("fixture"):
                        atomic(run / "fixture-ip.json", read(run / "private/wlan-ip.before.json"))
                    else:
                        win.configure_test_ip(run / "private/wlan-ip.before.json", restore=True)
                    status['wireless_ip_restored'] = True
                except Exception as error:
                    status['wireless_ip_restored'] = False
                    status['wireless_ip_error'] = getattr(error,'diagnostic',{'stage':'local_restore_error'})
            try:
                restore_settings(run, cfg, snapshot)
                status["settings_restored"] = True
            except Exception:
                # Exact restoration failure must not prevent the working wired
                # client from starting. Leave an explicit failed check in the report.
                status["settings_warning"] = "backup_restore_failed_using_wired_mode"
                set_mode(cfg, 0)
            if cfg.get("fixture"):
                time.sleep(cfg.get("restoreDelay", 0))
                original = spawn([sys.executable, SCRIPT, "fixture-app", "--run", run])
                status.update(original=original, original_started=True, original_authentication=True, bound_ethernet=True)
            else:
                check_hashes(cfg, original_only=True)
                # Delete only new, tagged, current-user app profiles; preserve all pre-existing profiles.
                try:
                    win.owned_profiles(delete_except=snapshot["ownedProfiles"])
                    status["owned_profiles_restored"] = not set(win.owned_profiles()).difference(snapshot["ownedProfiles"])
                except Exception:
                    status["owned_profiles_restored"] = False
                if (run / 'private/stable-profiles.before.json').exists():
                    try:
                        status['stable_profiles_restored']=win.stable_wlan_profiles(snapshot['wifiIndex'],
                            restore=read(run / 'private/stable-profiles.before.json'))
                    except Exception:
                        status['stable_profiles_restored']=False
                status["account_catalog_unchanged"] = sha(Path(cfg["dataDirectory"]) / "accounts.dat") == snapshot["accountsHash"]
                original = read(run / "restore-original.json") or snapshot["original"]
                cursor = Cursor(cfg)
                previous_offsets = read(run / "restore-log-offsets.json")
                if previous_offsets is None and win.alive(snapshot['original']):
                    previous_offsets = read(run / 'original-log-offsets.json')
                if previous_offsets is None:
                    atomic(run / "restore-log-offsets.json", {p.name: offset for p, offset in cursor.offsets.items()})
                else:
                    cursor.offsets = {cursor.directory / name: offset for name, offset in previous_offsets.items()
                                      if name == "desktop.jsonl" or re.fullmatch(r"session-[a-zA-Z0-9_.-]+\.jsonl", name)}
                if not win.alive(original):
                    # A prior restorer may have died immediately after launch.
                    # Reuse one exact original image instead of colliding with its mutex.
                    running = [p for p in win.processes() if p.get("path") and win.same_path(p["path"], cfg["originalApp"])]
                    if len(running) > 1:
                        raise RuntimeError("multiple_original_desktops_during_restore")
                    if running:
                        original = win.identity(running[0]["pid"])
                    elif cfg.get('temporaryDhcp'):
                        original = win.start_desktop_unelevated(cfg['originalApp'])
                    else:
                        original = spawn([cfg["originalApp"], "--silent"], str(Path(cfg["originalApp"]).parent))
                atomic(run / "restore-original.json", original)
                status.update(original=original, original_started=True)
                end = time.monotonic() + 110
                while time.monotonic() < end:
                    events = cursor.poll(run, "rollback")
                    if fresh_authentication(events, original):
                        status["original_authentication"] = True
                    # If no handoff happened, old authentication can legitimately remain active.
                    if win.alive(snapshot["original"]) and not (run / "handoff.json").exists():
                        status["original_authentication"] = True
                    if status["original_authentication"] and checked_probe(run, snapshot["wiredIndex"], "rollback"):
                        status["bound_ethernet"] = True
                        break
                    time.sleep(1)
            status["ok"] = bool(status["settings_restored"] and status["original_authentication"] and status["bound_ethernet"] and
                status.get('wireless_ip_restored',True) and status.get('stable_profiles_restored',True) and
                status.get('owned_profiles_restored',True) and status.get('account_catalog_unchanged',True))
        except Exception as exc:
            text = str(exc)
            status["failure"] = text if re.fullmatch(r"[a-z0-9_]{1,100}", text) else "rollback_local_error"
        status["ended_at"] = utc()
        observer = read(run / "observer-identity.json")
        if observer:
            win.terminate(observer)
        packet_observer = read(run / "packet-observer-identity.json")
        if packet_observer:
            win.terminate(packet_observer)
        atomic(run / "restored.json", status)
        event(run, "restore_finished", ok=status["ok"])
        return status


def fixture_controller(run, cfg, watchdog):
    set_mode(cfg, 2)
    prepare_test_network(run, cfg)
    start_test(run, cfg, 2)
    atomic(run / "mutated.json", {"time": utc()})
    fault = cfg["fault"]
    if fault == "controller_crash":
        os._exit(91)
    if fault == "corrupt_backup":
        (run / "settings.before.bin").write_bytes(b'corrupt')
        raise RuntimeError("fixture_settings_backup_corrupted")
    if fault in ("controller_hang", "hard_deadline", "manual_stop"):
        time.sleep(60)
    if fault == "watchdog_crash":
        end = time.monotonic() + 15
        while win.alive(watchdog) and time.monotonic() < end:
            time.sleep(.1)
        if win.alive(watchdog):
            raise RuntimeError("fixture_watchdog_did_not_exit")
        raise RuntimeError("watchdog_lost_controller_will_restore")
    raise RuntimeError("simulated_offline_connectivity_failure")


def controller(run, cfg):
    watchdog = read(run / "watchdog-identity.json")
    snapshot = read(run / "snapshot.json")
    quit_heartbeat = threading.Event()

    def heartbeat():
        while not quit_heartbeat.wait(.5):
            atomic(run / "heartbeat.json", {"pid": os.getpid(), "at": time.time()})
    thread = None
    try:
        journal_deadline = time.monotonic() + 5
        while not read(run / "controller-identity.json"):
            if time.monotonic() > journal_deadline:
                raise RuntimeError("controller_identity_not_journaled")
            time.sleep(.05)
        if cfg.get("fault") != "controller_hang":
            thread = threading.Thread(target=heartbeat, daemon=True)
            thread.start()
        if cfg.get("fixture"):
            fixture_controller(run, cfg, watchdog)
        abort_check(run, watchdog)
        # Write intent before touching the production process. The watchdog already
        # has a flushed snapshot and is running in a separate process.
        if not cfg.get('preserveOriginal'):
            atomic(run / "handoff.json", {"time": utc()})
            original_cursor = Cursor(cfg)
            atomic(run / 'original-log-offsets.json', {p.name: offset for p, offset in original_cursor.offsets.items()})
            stop_desktop(run, cfg, snapshot["original"], cfg["originalCore"])
        results = []
        if cfg.get('probeKind') == 'web-discovery':
            results.append(test_web_discovery(run, cfg, snapshot, watchdog))
        elif cfg.get("probeKind"):
            results.append(test_native_probe(run, cfg, snapshot, watchdog))
        else:
            for mode in cfg["modes"]:
                abort_check(run, watchdog)
                results.append(test_mode(run, cfg, snapshot, mode, watchdog))
        atomic(run / "cases.json", results)
    except Exception as exc:
        text = str(exc)
        event(run, "controller_failed", code=text if re.fullmatch(r"[a-z0-9_]{1,100}", text) else "controller_local_error", **exception_codes(exc))
    finally:
        try:
            rollback(run, cfg, "controller_finally")
            atomic(run / "controller-finished.json", {"time": utc()})
        finally:
            quit_heartbeat.set()
            if thread:
                thread.join(2)


def monitor(run, cfg):
    os.environ["SCAU_LAB_WATCHDOG"] = "1"
    snapshot, child = None, None
    with file_lock(Path(cfg["dataDirectory"]) / ".network-lab.lock"):
        try:
            snapshot = preflight(run, cfg)
            atomic(run / "snapshot.json", snapshot)
            atomic(run / "watchdog-identity.json", win.identity(os.getpid()))
            if cfg.get("observer") and not cfg.get("fixture"):
                observer = spawn([cfg["observer"], "--seconds", str(min(3600, cfg["deadlineSeconds"] + 110)), run / "wlan-events.jsonl"])
                atomic(run / "observer-identity.json", observer)
            if cfg.get("passiveEapCapture") and not cfg.get("fixture"):
                observer = spawn([sys.executable, SCRIPT.parent / "passive_eap_probe.py", "--seconds", str(min(3600, cfg["deadlineSeconds"] + 110)),
                                  "--interface", str(snapshot["wifiIndex"]), "--log", run / "eap-metadata.jsonl"])
                atomic(run / "packet-observer-identity.json", observer)
                observer_deadline = time.monotonic() + 6
                while time.monotonic() < observer_deadline:
                    trace = run / "eap-metadata.jsonl"
                    if trace.exists() and trace.stat().st_size:
                        break
                    if not win.alive(observer):
                        break
                    time.sleep(.1)
            # Child must not inherit the logger role; all file names are fixed.
            os.environ.pop("SCAU_LAB_WATCHDOG", None)
            child = spawn([sys.executable, SCRIPT, "controller", "--run", run])
            os.environ["SCAU_LAB_WATCHDOG"] = "1"
            atomic(run / "controller-identity.json", child)
            event(run, "watchdog_armed", controller_pid=child["pid"], deadline_seconds=cfg["deadlineSeconds"])
            started, reason = time.monotonic(), "controller_exit"
            while win.alive(child):
                if cfg.get("fault") == "watchdog_crash" and (run / "mutated.json").exists():
                    os._exit(92)
                beat = read(run / "heartbeat.json", {})
                age = time.time() - beat.get("at", time.time())
                if (run / "STOP").exists():
                    reason = "manual_stop"
                    break
                if time.monotonic() - started > cfg["deadlineSeconds"]:
                    reason = "hard_deadline"
                    break
                if (beat and age > cfg["heartbeatSeconds"]) or (not beat and time.monotonic() - started > cfg["heartbeatSeconds"]):
                    reason = "controller_heartbeat_timeout"
                    break
                time.sleep(.25)
            if win.alive(child):
                # Stop the controller before it can race with rollback.
                win.terminate(child)
            event(run, "watchdog_triggered", reason=reason)
        except Exception as exc:
            text = str(exc)
            event(run, "preflight_or_watchdog_failed", code=text if re.fullmatch(r"[a-z0-9_]{1,100}", text) else "local_preflight_error", **exception_codes(exc))
        finally:
            if snapshot:
                restored = rollback(run, cfg, "watchdog_finally")
                cases = read(run / "cases.json", [])
                atomic(run / "result.json", {"ended_at": utc(), "restored": restored["ok"],
                    "test_passed": bool(cases) and all(c["passed"] for c in cases), "cases": cases,
                    "not_tested_live": [name for name in ["password_change", "campus_pause_resume", "web_portal", "long_duration_roaming_sleep_resume"]
                        if not (name=='web_portal' and any(c.get('authentication') and 'web' in c.get('profile_store','') for c in cases))]})
            else:
                atomic(run / "result.json", {"ended_at": utc(), "preflight_failed": True, "network_untouched": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("run", "controller", "restore", "stop", "fixture-app"))
    parser.add_argument("--run", type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve(strict=True)
    cfg = read(run / "config.json")
    if not cfg or cfg.get("schema") != 1:
        raise RuntimeError("invalid_lab_configuration")
    if cfg.get("fixture"):
        # Fixture mode cannot point at actual app data or real executables.
        if not (run / "FIXTURE").is_file() or Path(cfg["dataDirectory"]).resolve() != run / "fixture-data":
            raise RuntimeError("fixture_path_guard")
    if args.role == "fixture-app":
        while True:
            time.sleep(1)
    elif args.role == "run":
        monitor(run, cfg)
    elif args.role == "controller":
        os.environ.pop("SCAU_LAB_WATCHDOG", None)
        controller(run, cfg)
    elif args.role == "restore":
        (run / "STOP").touch()
        child = read(run / "controller-identity.json")
        if child:
            win.terminate(child)
        rollback(run, cfg, "manual_restore")
    else:
        (run / "STOP").touch()


if __name__ == "__main__":
    main()
