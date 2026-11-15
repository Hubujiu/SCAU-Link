"""Build the native per-user setup EXE from the verified desktop release.

The checksum-pinned Inno compiler is bootstrapped in portable mode, confined
to build/deps. The optional QA build uses separate registry values/mutexes
and never creates normal shortcuts. No authentication or driver is run.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DEPS = ROOT / 'build/deps'
INNO_VERSION = '7.1.1'
INNO_SHA = '8a5a6711c3766a6e5fb74f280ba0e3551e719ce94538d901fdbd1f8f9920b3f0'
INNO_URL = 'https://github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x64.exe'
CRT_FILES = ['msvcp140.dll', 'msvcp140_atomic_wait.dll', 'vcruntime140.dll', 'vcruntime140_1.dll']

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def signature(path, publisher):
    child_env = dict(os.environ)
    # Python may inherit PowerShell 7's module search path; Windows PowerShell
    # must load its own security module to verify the unmodified signed files.
    child_env.pop('PSModulePath', None)
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', str(ROOT/'scripts/verify_build_dependency.ps1'), '-Path', str(path), '-Publisher', publisher],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, env=child_env)
    if result.returncode:
        raise RuntimeError('Signature verification failed for '+path.name+': '+
                           result.stderr.decode('utf-8', errors='replace')[-1000:])
    return json.loads(result.stdout.decode('utf-8-sig'))

def compiler():
    DEPS.mkdir(parents=True, exist_ok=True)
    archive = DEPS / f'innosetup-{INNO_VERSION}-x64.exe'
    if not archive.exists():
        print('Downloading pinned Inno Setup compiler', flush=True)
        part = archive.with_suffix('.part')
        with urllib.request.urlopen(INNO_URL, timeout=30) as incoming, part.open('wb') as outgoing:
            shutil.copyfileobj(incoming, outgoing)
        if sha(part) != INNO_SHA: raise RuntimeError('Inno compiler download hash mismatch')
        part.replace(archive)
    if sha(archive) != INNO_SHA: raise RuntimeError('Inno compiler hash mismatch')
    signature(archive, 'Pyrsys B.V.')
    folder = DEPS / f'innosetup-{INNO_VERSION}-portable'
    exe = folder / 'ISCC.exe'
    if not exe.exists():
        print('Preparing workspace-only portable Inno compiler', flush=True)
        subprocess.run([str(archive), '/PORTABLE=1', '/CURRENTUSER', '/VERYSILENT', '/SP-',
                        '/SUPPRESSMSGBOXES', '/NORESTART', '/NOICONS', '/TASKS=',
                        '/DIR=' + str(folder), '/LOG=' + str(DEPS/'inno-bootstrap.log')],
                       check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if not exe.is_file(): raise RuntimeError('Portable Inno compiler is missing')
    return exe

def collect_runtime(target):
    base = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'))
    vswhere = base / 'Microsoft Visual Studio/Installer/vswhere.exe'
    installation = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'],
        creationflags=subprocess.CREATE_NO_WINDOW).decode('utf-8-sig').strip()
    redists = Path(installation) / 'VC/Redist/MSVC'
    versions = sorted((p for p in redists.iterdir() if re.fullmatch(r'\d+(?:\.\d+)+', p.name)),
                      key=lambda p: tuple(map(int, p.name.split('.'))), reverse=True)
    source = next((p/'x64/Microsoft.VC143.CRT' for p in versions
                   if all((p/'x64/Microsoft.VC143.CRT'/name).is_file() for name in CRT_FILES)), None)
    if source is None: raise RuntimeError('VS 2022 x64 redistributable CRT files are missing')
    target.mkdir(parents=True, exist_ok=True)
    records = {}
    for name in CRT_FILES:
        path = source / name
        verified = signature(path, 'Microsoft Corporation')
        shutil.copy2(path, target / name)
        records[name] = dict(sha256=sha(path), bytes=path.stat().st_size, signature=verified)
    metadata = dict(source='Visual Studio 2022 Build Tools: VC/Redist/MSVC/x64/Microsoft.VC143.CRT',
                    redistribution='Microsoft Visual Studio distributable code; application-local only',
                    documentation='https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files',
                    version=source.parent.parent.name, files=records)
    (target/'manifest.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    return metadata

def source_archive(target):
    version = re.search(r'project\(ScauNativeAuth VERSION ([\d.]+)',
                        (ROOT/'CMakeLists.txt').read_text(encoding='utf-8')).group(1)
    files = [ROOT/p for p in ['CMakeLists.txt','README.md','LICENSE','THIRD_PARTY_NOTICES.md']]
    for folder in ['src','tests','scripts','installer','third_party','assets']:
        files.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts
                     and p.suffix.lower() not in {'.pyc','.pdb','.obj','.exe','.dll','.lib','.cur','.ani'})
    files.extend(ROOT/'ui/prototype/assets'/p for p in ['icons.js','LUCIDE-LICENSE'])
    files.extend(ROOT/'docs'/p for p in ['desktop-package-README.txt','installer-README.txt',
                 'SCAU-Campus-Service-20261113.md','SCAU-Billing-Query-20261114.md',
                 'SCAU-Automatic-Setup-20261114.md','SCAU-Wireless-Web-20261114.md',
                 'SCAU-Password-Change-20261114.md','SCAU-Connection-Modes-20261114.md',
                 'SCAU-Wireless-8021X-20261114.md','Network-Delivery-Lab.md',
                 'Network-Delivery-Results-20261114.md'])
    files.extend(ROOT/'docs/network-delivery-20261114'/p for p in [
        'result.json','wired.json','wireless_8021x.json','restored.json','final-state.json',
        'controller.jsonl','watchdog.jsonl','preflight.json','baseline.json',
        'ctest-0.11.1.txt','offline-tests.txt'])
    files.extend(ROOT/'docs'/p for p in [f'SCAU-First-Run-{version}.md',
        f'Network-Delivery-Results-{version}.md', f'validation-{version}.json'])
    files.extend(p for p in (ROOT/'docs'/f'network-delivery-{version}').rglob('*')
                 if p.is_file() and p.suffix.lower() in {'.json','.jsonl','.txt'})
    files.extend(p for p in (ROOT/'docs'/f'ui-native-{version}-preview').iterdir() if p.is_file())
    files.extend(ROOT/'docs'/p for p in ['Updates-0.13.0.md','Updates-0.14.0.md','SCAU-First-Run-0.12.0.md',
        'Network-Delivery-Results-0.12.0.md','validation-0.12.0.json'])
    files.extend(p for p in (ROOT/'docs/network-delivery-0.12.0').rglob('*')
                 if p.is_file() and p.suffix.lower() in {'.json','.jsonl','.txt'})
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for p in sorted(set(files)):
            assert p.is_relative_to(ROOT) and p.suffix.lower() not in {'.pcap','.pcapng','.scau'}
            archive.write(p, p.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None
        for p in files:
            assert hashlib.sha256(archive.read(p.relative_to(ROOT).as_posix())).hexdigest() == sha(p)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test', action='store_true', help='Build an isolated QA variant, not a user release.')
    parser.add_argument('--preview', action='store_true', help='Package an explicitly labelled preview with incomplete UI validation.')
    args = parser.parse_args()
    version = re.search(r'project\(ScauNativeAuth VERSION ([\d.]+)',
                        (ROOT/'CMakeLists.txt').read_text(encoding='utf-8')).group(1)
    variant = '-preview' if args.preview else ''
    stage = ROOT/'out'/f'scau-link-{version}-win-x64{variant}'
    report = json.loads((stage/'verification.json').read_text(encoding='utf-8-sig'))
    expected_channel = 'preview' if args.preview else 'release'
    if report.get('releaseChannel','release') != expected_channel:
        raise RuntimeError('Installer channel differs from the verified desktop payload')
    payload = ROOT/'build'/('installer-payload'+variant)
    payload.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for name,key in [('SCAU-Link.exe','desktopSha256'), ('scau-auth.exe','authenticationSha256'),
                     ('scau-update.exe','updaterSha256')]:
        path = stage/name
        digest = sha(path)
        if digest != report[key] or digest != sha(ROOT/'build/Release'/name):
            raise RuntimeError('Desktop payload is not the verified release: ' + name)
        shutil.copy2(path, payload/name)
        hashes[name] = digest
    runtime = collect_runtime(payload/'runtime')
    shutil.copy2(stage/'verification.json',payload/'verification.json')
    source_archive(payload/'source.zip')
    exe = compiler()
    command = [str(exe), '/Qp', '/DAppVersion='+version, '/DRepoRoot='+str(ROOT),
               '/DPayloadDir='+str(payload), '/DOutputDir='+str(ROOT/'out')]
    if args.test: command.append('/DInstallerTest=1')
    if args.preview: command.append('/DPreviewRelease=1')
    command.append(str(ROOT/'installer/scau-link.iss'))
    compilation = subprocess.run(command, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    output = compilation.stdout + compilation.stderr
    (ROOT/'build/installer-compile.log').write_bytes(output)
    if compilation.returncode:
        raise RuntimeError('Inno compilation failed: '+output.decode('utf-8-sig',errors='replace')[-3500:])
    suffix = '-test' if args.test else variant
    result = ROOT/'out'/f'SCAU-Link-{version}-Setup-x64{suffix}.exe'
    metadata = dict(version=version,installer=str(result),bytes=result.stat().st_size,sha256=sha(result),
                    builderVersion=INNO_VERSION,builderSha256=INNO_SHA,installerTest=args.test,releaseChannel=expected_channel,
                    signed=False,applicationHashes=hashes,runtime=runtime,sourceArchiveSha256=sha(payload/'source.zip'),
                    customInstallPath=True,perUser=True,requiresAdministrator=False,autoLaunch=False,
                    closesRunningApplications=False,installsNetworkDrivers=False,
                    builtAt=datetime.now(timezone.utc).isoformat())
    (ROOT/'out'/f'installer-{version}{suffix}.json').write_text(
        json.dumps(metadata,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in metadata.items() if k!='runtime'}, ensure_ascii=False))

if __name__ == '__main__': main()
