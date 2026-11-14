"""Read-only post-lab verification; launch through the existing Explorer desktop.

The real user context matters: Codex's packaged AppData view is redirected.
No credential retrieval or network configuration writes are performed here.
"""
import argparse
import json
from pathlib import Path

import network_lab as lab
import network_lab_windows as win


def verify(run):
    cfg = lab.read(run / 'config.json')
    snapshot = lab.read(run / 'snapshot.json')
    restored = lab.read(run / 'restored.json')
    context = win.context()
    same_context = (context['sid'] == cfg['expectedSid'] and
                    win.same_path(Path(context['local']) / 'ScauLink', cfg['dataDirectory']))
    checks = {'realUserContext': same_context}
    if same_context:
        lab.check_hashes(cfg)
        processes = win.processes()
        settings = Path(cfg['dataDirectory']) / 'settings.ini'
        checks.update(
            originalProcessAlive=win.alive(restored['original']),
            noStagedProcesses=not any(p.get('path') and any(win.same_path(p['path'], cfg[k])
                for k in ('testApp', 'testCore')) for p in processes),
            originalSettingsRestored=(settings.exists() and lab.sha(settings) == snapshot['settings']['sha256'])
                if snapshot['settings']['present'] else not settings.exists(),
            accountCatalogUnchanged=lab.sha(Path(cfg['dataDirectory']) / 'accounts.dat') == snapshot['accountsHash'],
            ownedProfilesMatch=set(win.owned_profiles()) == set(snapshot['ownedProfiles']),
            watchdogExited=not win.alive(lab.read(run / 'watchdog-identity.json')),
            controllerExited=not win.alive(lab.read(run / 'controller-identity.json')))
        if (run / 'ip-change-intent.json').exists():
            before = lab.read(run / 'private/wlan-ip.before.json')
            after = win.ip_snapshot(before['index'])
            checks.update(wirelessIpExactMatch=after == before,
                          dhcpSwitchRestored=after['dhcp'] == before['dhcp'],
                          manualDnsRestored=after['dns'] == before['dns'],
                          manualAddressesRestored=after['manual'] == before['manual'])
        probe = win.probe(snapshot['wiredIndex'])
        checks['boundEthernetInternet'] = probe['ok']
    report = {'observedAt': lab.utc(), 'passed': all(checks.values()), 'checks': checks}
    lab.atomic(run / 'final-state.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.run.resolve(strict=True))
    print(json.dumps({'passed': result['passed'], 'checks': len(result['checks'])}))
    raise SystemExit(0 if result['passed'] else 1)
