"""Produce a credential-free report from a completed desktop live test."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path


def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def stamp(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    status = json.loads((args.run_directory / "status.json").read_text(encoding="utf-8-sig"))
    probes = read_jsonl(args.run_directory / "connectivity.jsonl")
    observation = [p for p in probes if p.get("phase") == "observation"]
    observation_ok = [p for p in observation if p["event"] == "ethernet_direct_probe_ok"
                      and p.get("interface_bound") and p.get("dns_direct")
                      and p.get("http_verified") and not p.get("original_client_present")]
    counts = status.get("desktop_event_counts") or {}
    sam = status.get("sam") or {}
    sam_intervals = sam.get("hello_intervals") or []
    sam_messages = sam.get("verified_server_messages", 0)
    elapsed = None
    if status.get("observation_completed_at") and status.get("observation_started_at"):
        elapsed = (stamp(status["observation_completed_at"]) - stamp(status["observation_started_at"])).total_seconds()
    passed = bool(status.get("initial_authentication_passed") and status.get("crash_recovery_passed")
                  and status.get("observation_passed") and elapsed is not None
                  and elapsed >= status["observation_seconds"] and observation_ok
                  and len(observation_ok) == len(observation)
                  and counts.get("worker_crashed") == 1
                  and counts.get("worker_restart_scheduled") == 1
                  and counts.get("account_attempt") == 1)
    performance = []
    samples = read_jsonl(args.run_directory / "performance.jsonl")
    for role in ("desktop", "worker"):
        values = [p for p in samples if p["role"] == role]
        if not values:
            continue
        first, last = values[0], values[-1]
        seconds = (stamp(last["time"]) - stamp(first["time"])).total_seconds()
        cpu_delta = max(0, last["cpu_seconds"] - first["cpu_seconds"])
        performance.append({
            "role": role, "sample_count": len(values), "sample_window_seconds": round(seconds, 3),
            "cpu_seconds_delta": round(cpu_delta, 6),
            "average_cpu_percent_of_one_logical_processor": round(cpu_delta / seconds * 100, 5) if seconds > 0 else None,
            "first_working_set_mib": round(first["working_set_bytes"] / 1024**2, 2),
            "last_working_set_mib": round(last["working_set_bytes"] / 1024**2, 2),
            "first_private_mib": round(first["private_bytes"] / 1024**2, 2),
            "last_private_mib": round(last["private_bytes"] / 1024**2, 2),
            "first_handle_count": first["handle_count"], "last_handle_count": last["handle_count"],
        })
    release = root / "out" / "scau-link-0.6.5-win-x64"
    hashes = {name: hashlib.sha256((release / name).read_bytes()).hexdigest()
              for name in ("SCAU-Link.exe", "scau-auth.exe")}
    report = {
        "product": "SCAU Link", "version": "0.6.5", "kind": "real_campus_network_desktop_test",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "passed": passed, "phase_at_export": status["phase"],
        "evidence_directory": str(args.run_directory.resolve()), "sha256": hashes,
        "timeline": {key: status.get(key) for key in (
            "started_at", "initial_authenticated_at", "crash_injected_at",
            "recovered_authenticated_at", "observation_started_at", "observation_completed_at")},
        "crash_recovery_milliseconds": status.get("recovery_milliseconds"),
        "observation_seconds": round(elapsed, 3) if elapsed is not None else None,
        "observation_probe_successes": len(observation_ok),
        "observation_probe_failures": len(observation) - len(observation_ok),
        "desktop_event_counts": counts, "worker_event_counts": status.get("worker_event_counts"),
        "sam": sam, "performance": performance,
        "connection_held_at_export": status.get("connection_held", False),
        "original_supervisor_temporarily_suspended": status.get("original_supervisor_suspended", False),
        "scope": [
            "Real saved local credential used by the native desktop; no --demo options.",
            "Original 8021x client absent during all successful native connectivity probes.",
            "One verified desktop-owned authentication worker was force-terminated; the desktop remained alive.",
            "DNS and HTTP probes bound to the physical Ethernet interface; no reliance on VPN/TUN routing.",
            "Native window visually showed connected status after recovery; navigation input to this elevated test window was not verified.",
            "No adapter disabling, sleep, route changes, firewall changes or driver installation.",
        ],
        "limitations": [
            "Local SAM configuration/socket readiness alone does not prove a live SAM HELLO/ACK round trip; verified server-message counts are reported separately.",
            "No multi-account rejection/failover test: only one real saved account was supplied.",
            "Cable removal, sleep/resume, Windows autostart, silent-start failure and multi-hour endurance were not exercised.",
            "Working-session hold uses an independent elevated restorer while the original supervisor is paused. Exiting the test desktop restores the original process; original login can require a manual click.",
        ],
        "privacy": "No usernames, passwords, addresses, packet payloads, challenges or session keys included.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    local = dt.timezone(dt.timedelta(hours=8))
    lines = ["# SCAU Link 0.6.5 真实环境测试", "",
             f"结果：{'通过' if passed else '未通过或尚未完成'}。", "",
             f"恢复后观察 {report['observation_seconds']} 秒；绑定物理有线网卡的 DNS + HTTP 检查 "
             f"{len(observation_ok)}/{len(observation)} 次通过。", "",
             f"认证工作进程强制终止 1 次，自动重登耗时 {report['crash_recovery_milliseconds']} 毫秒。"
             "桌面进程保持运行，账号尝试轮次为 1。", "", "| 事件 | 本地时间（UTC+8） |", "|---|---|"]
    for key, label in (("initial_authenticated_at", "首次认证成功"), ("crash_injected_at", "终止工作进程"),
                       ("recovered_authenticated_at", "自动重登成功"), ("observation_started_at", "连续观察开始"),
                       ("observation_completed_at", "连续观察完成")):
        value = status.get(key)
        lines.append(f"| {label} | {stamp(value).astimezone(local).isoformat(timespec='milliseconds') if value else '尚无'} |")
    sam_note = (f"SAM：本次协商的 HELLO 间隔记录为 {sam_intervals}，"
                f"本地通道配置 {sam.get('channel_configured', 0)} 次、UDP 接收端点就绪 {sam.get('transport_ready', 0)} 次；"
                f"可验证的服务器消息 {sam_messages} 条、发送确认 {sam.get('send_confirmed', 0)} 次。")
    if not sam_messages:
        sam_note += "没有可验证的 SAM 服务器消息，不能据此声称完整 SAM 往返握手已在真实环境通过。"
    lines += ["", sam_note, "",
              "| 进程 | 最后工作集 | 最后私有内存 | 采样区间内平均 CPU（单逻辑核） |", "|---|---:|---:|---:|"]
    for value in performance:
        lines.append(f"| {value['role']} | {value['last_working_set_mib']} MiB | {value['last_private_mib']} MiB | "
                     f"{value['average_cpu_percent_of_one_logical_processor']}% |")
    lines += ["", "CPU 数值来自空闲采样窗口，不代表页面动画或拖拽时的开销。", "",
              "完成观察不会断开连接。测试恢复进程继续运行，原锐捷守护进程暂时暂停；退出测试客户端后恢复原锐捷，"
              "原客户端可能需要手动点击连接。", "",
              "未验证：多账号失败切换、拔插网线、睡眠恢复、开机自启、静默失败和数小时以上在线稳定性。", "",
              "证据使用已保存的本机凭证；报告不含账号、密码、地址、认证报文或会话密钥。", "",
              f"本机证据目录：`{args.run_directory.resolve()}`", ""]
    args.output.with_suffix(".md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"passed": passed, "phase": status["phase"], "observation_seconds": report["observation_seconds"],
                      "probe_successes": len(observation_ok), "probe_failures": len(observation)-len(observation_ok),
                      "output": str(args.output.resolve())}, separators=(",", ":")))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
