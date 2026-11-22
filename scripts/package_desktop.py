"""Package the compiled native app, corresponding source and demo validation evidence."""
import argparse
import hashlib
import json
import re
import shutil
import struct
import zipfile
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--preview', action='store_true',
                    help='Produce a clearly labelled preview with recorded, incomplete UI verification.')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
version = re.search(r'project\(ScauNativeAuth VERSION ([\d.]+)',
                    (root / 'CMakeLists.txt').read_text(encoding='utf-8')).group(1)
variant = '-preview' if args.preview else ''
stage = root / 'out' / f'scau-link-{version}-win-x64{variant}'
proof = root / 'docs' / f'ui-native-{version}{variant}'
validation = root / 'docs' / f'validation-{version}.json'
assert stage.is_dir() and stage.resolve().parent == (root / 'out').resolve()
report = json.loads(validation.read_text(encoding='utf-8-sig'))
checks = json.loads((proof / 'interaction-checks.json').read_text(encoding='utf-8-sig'))
if args.preview:
    assert report['releaseChannel'] == 'preview'
    if report['nativeUiChecks']['status'] == 'blocked':
        assert report['nativeUiChecks']['reason']
        assert checks == [], 'Preview must not imply that blocked UI checks were performed'
    else:
        assert report['nativeUiChecks']['status'] == 'passed' and checks and all(c['passed'] for c in checks)
        assert report.get('previewReason'), 'A UI-verified preview must state its remaining release limitation'
else:
    assert report.get('releaseChannel', 'release') == 'release', 'Preview report cannot validate a release'
    assert checks and all(c['passed'] for c in checks), 'Unresolved native UI checks'
test_log = root / 'build/Testing/Temporary/LastTest.log'
tests = test_log.read_text(encoding='utf-8', errors='replace')
test_count = report['automatedTests']['total']
assert report['automatedTests']['passed'] == test_count
assert tests.count('Test Passed.') == test_count and 'Test Failed.' not in tests


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


for name in ['SCAU-Link.exe', 'scau-auth.exe', 'scau-update.exe']:
    assert sha(stage / name) == sha(root / 'build/Release' / name), f'Stale executable: {name}'
binary = (stage / 'SCAU-Link.exe').read_bytes()
pe = struct.unpack_from('<I', binary, 0x3c)[0]
assert binary[:2] == b'MZ' and binary[pe:pe + 4] == b'PE\0\0'
assert struct.unpack_from('<H', binary, pe + 4)[0] == 0x8664
assert struct.unpack_from('<H', binary, pe + 24 + 68)[0] == 2

for name in ['LICENSE', 'THIRD_PARTY_NOTICES.md']:
    shutil.copy2(root / name, stage / name)
source_files = [root / name for name in ['CMakeLists.txt', 'LICENSE', 'THIRD_PARTY_NOTICES.md']]
source_files.extend(root / 'rust' / name for name in ['Cargo.toml', 'Cargo.lock'])
source_files.extend((root / 'rust').glob('*/Cargo.toml'))
for crate_source in (root / 'rust').glob('*/src'):
    source_files.extend(crate_source.rglob('*.rs'))
for folder in ['src', 'tests', 'scripts', 'installer', 'third_party', 'assets']:
    source_files.extend(p for p in (root / folder).rglob('*') if p.is_file()
                        and '__pycache__' not in p.parts
                        and not p.is_relative_to(root / 'assets/cursors')
                        and p.suffix.lower() not in {'.pyc', '.pdb', '.obj', '.exe', '.dll', '.lib'})
source_files.extend(root / 'ui/prototype/assets' / name for name in ['icons.js', 'LUCIDE-LICENSE'])
source_files.append(root / 'docs/desktop-package-README.txt')
source_files.append(root / 'docs/SCAU-Campus-Service-20261113.md')
source_files.append(root / 'docs/SCAU-Billing-Query-20261114.md')
source_files.extend(root / 'docs' / name for name in ['Package-Query-0.14.1.md'])
source_files.extend(root / 'docs' / f'{topic}-{version}.md' for topic in ['Package-Query', 'Startup-Wired']
                    if (root / 'docs' / f'{topic}-{version}.md').is_file())
source_files.append(root / 'docs/SCAU-Automatic-Setup-20261114.md')
source_files.extend(root / 'docs' / name for name in ['SCAU-Wireless-Web-20261114.md',
    'SCAU-Password-Change-20261114.md', 'SCAU-Connection-Modes-20261114.md'])
source_files.append(root / 'docs/SCAU-Wireless-8021X-20261114.md')
source_files.extend(root / 'docs' / name for name in ['Network-Delivery-Lab.md',
    'Network-Delivery-Results-20261114.md'])
source_files.extend(root / 'docs/network-delivery-20261114' / name for name in [
    'result.json', 'wired.json', 'wireless_8021x.json', 'restored.json', 'final-state.json',
    'controller.jsonl', 'watchdog.jsonl', 'preflight.json', 'baseline.json',
    'ctest-0.11.1.txt', 'offline-tests.txt'])
source_files.extend(root / 'docs' / name for name in [
    f'SCAU-First-Run-{version}.md', f'Network-Delivery-Results-{version}.md',
    f'validation-{version}.json'])
source_files.extend(p for p in (root / 'docs' / f'network-delivery-{version}').rglob('*')
                    if p.is_file() and p.suffix.lower() in {'.json', '.jsonl', '.txt'})
source_files.extend(p for p in proof.iterdir() if p.is_file())
source_files.extend(root / 'docs' / name for name in ['Updates-0.13.0.md','Updates-0.14.0.md',
    'SCAU-First-Run-0.12.0.md','Network-Delivery-Results-0.12.0.md','validation-0.12.0.json'])
source_files.extend(p for p in (root/'docs/network-delivery-0.12.0').rglob('*')
                    if p.is_file() and p.suffix.lower() in {'.json','.jsonl','.txt'})
for path in source_files:
    target = stage / 'source' / path.relative_to(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, target)
    assert sha(path) == sha(target), f'Source snapshot mismatch: {path}'
(stage / 'source/README.md').write_text(
    f'# SCAU Link {version} source\n\n'
    'Build with Visual Studio 2022 Build Tools, Windows SDK, Rust MSVC 1.97+, CMake and Python 3.12+. '
    'Run `scripts/build.ps1 -Configuration Release`.\n\n'
    'The bootstrap verifies the bundled OpenSSL 3.5.9 source and downloads a '
    'checksum-pinned portable Perl build tool on the first run. Static TLS libraries '
    'are built locally in build/deps; Perl is not installed system-wide or used at runtime. '
    'Source provenance and licensing are in third_party/openssl.\n\n'
    'Keep SCAU-Link.exe, scau-auth.exe and scau-update.exe together. '
    'The connection page uses Native Shell with Win32, Direct2D and DirectWrite. '
    'Vector icon paths are compiled from src/desktop/icons.hpp. '
    'Optional icon regeneration uses scripts/generate_native_icons.py and Python fontTools. '
    'The application SVG master is assets/app-icon.svg; regenerating the bundled ICO files '
    'uses scripts/generate_app_icon.py with Python resvg-py and Pillow. '
    'Drag cursors use the shared Windows IDC_HAND cursor; no custom cursor assets are bundled.\n',
    encoding='utf-8')
readme = (root / 'docs/desktop-package-README.txt').read_text(encoding='utf-8-sig')
readme = readme.replace('{VERSION}', version)
if args.preview:
    readme = '预览版：' + report.get('previewReason','原生界面交互验证尚未完成') + '，详见 verification.json。\n\n' + readme
readme += ('\n界面更新：账号与托盘共用圆角菜单、Lucide 图标和弹簧高亮；支持键盘选择与 Esc 关闭。'
           '账号横条按住后浮起，可跟随鼠标自由移动；其他横条以弹簧动画让位，松手吸附后保存顺序，拖出列表松手则还原。'
           '点击页面空白或横条间隙取消选中与焦点。\n'
           '浮起后调用用户系统手形，松手恢复系统箭头，不附带自定义指针资源。\n'
           '字体、图标路径和渐变画刷按需缓存，菜单懒创建；动画停止后不运行帧计时器。\n')
(stage / 'README.txt').write_text(readme, encoding='utf-8')
shutil.copytree(proof, stage / 'screenshots', dirs_exist_ok=True)
shutil.copy2(validation, stage / 'verification.json')
shutil.copy2(test_log, stage / 'test-results.txt')
files = sorted(p for p in stage.rglob('*') if p.is_file() and p.name != 'manifest.json')
assert not any(p.suffix.lower() in {'.pcap', '.pcapng', '.scau'} for p in files)
assert not any(p.suffix.lower() in {'.cur', '.ani'} for p in files), 'Unexpected custom cursor asset'
manifest = {p.relative_to(stage).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in files}
(stage / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
archive = stage.parent / (stage.name + '.zip')
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for path in sorted(stage.rglob('*')):
        if path.is_file():
            z.write(path, stage.name + '/' + path.relative_to(stage).as_posix())
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    for name, detail in manifest.items():
        assert hashlib.sha256(z.read(stage.name + '/' + name)).hexdigest() == detail['sha256'], name
release = dict(version=version, releaseChannel='preview' if args.preview else 'release',
               archive=str(archive), bytes=archive.stat().st_size,
               sha256=sha(archive), entry=str(stage / 'SCAU-Link.exe'), files=len(manifest) + 1,
               packagedAt=datetime.now(timezone.utc).isoformat(), ctestPassed=test_count,
               uiChecksPassed=len(checks), uiChecksStatus=report['nativeUiChecks'].get('status', 'passed'),
               archiveIntegrityVerified=True, sourceSnapshotVerified=True)
(root / 'out' / f'scau-link-{version}{variant}-release.json').write_text(
    json.dumps(release, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(release, ensure_ascii=False))
