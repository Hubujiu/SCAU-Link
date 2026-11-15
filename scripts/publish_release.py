"""Publish verified local artifacts through a complete GitHub Release draft."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
REPOSITORY='Hubujiu/SCAU-Link'


def run(*args):
    return subprocess.check_output(args,cwd=ROOT,text=True,encoding='utf-8',
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',required=True)
    parser.add_argument('--notes-file',type=Path,required=True)
    parser.add_argument('--legacy',action='store_true',help='Pre-updater release <=0.12.0; no update manifest.')
    args=parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+',args.version):parser.error('Invalid version')
    if args.legacy and tuple(map(int,args.version.split('.')))>(0,12,0):parser.error('New releases require a signed update manifest')
    tag='v'+args.version+'-preview'
    run('git','rev-parse','--verify',tag)
    if run('git','rev-parse',tag)!=run('git','rev-parse','HEAD'):
        raise SystemExit('Publish from the exact tagged source revision')
    # The first public release was frozen before updater work; later releases must be clean.
    if not args.legacy and run('git','status','--porcelain'):
        raise SystemExit('Commit the complete release source before publishing')
    out=ROOT/'out'
    installer=out/f'SCAU-Link-{args.version}-Setup-x64-preview.exe'
    portable=out/f'scau-link-{args.version}-win-x64-preview.zip'
    verification=out/f'scau-link-{args.version}-win-x64-preview/verification.json'
    build=json.loads((out/f'installer-{args.version}-preview.json').read_text(encoding='utf-8'))
    if sha(installer)!=build['sha256']:raise SystemExit('Installer differs from verified metadata')
    package=json.loads((out/f'scau-link-{args.version}-preview-release.json').read_text(encoding='utf-8'))
    if sha(portable)!=package['sha256']:raise SystemExit('Portable archive differs from verified metadata')
    report=json.loads(verification.read_text(encoding='utf-8-sig'))
    if report['version']!=args.version or report['releaseChannel']!='preview':raise SystemExit('Verification channel/version mismatch')
    for name,key in [('SCAU-Link.exe','desktopSha256'),('scau-auth.exe','authenticationSha256')]:
        if build['applicationHashes'][name]!=report[key]:raise SystemExit('Application hash mismatch')
    if not args.legacy and build['applicationHashes']['scau-update.exe']!=report['updaterSha256']:
        raise SystemExit('Updater hash mismatch')
    manifest=out/'SCAU-Link-update.json';signature=out/'SCAU-Link-update.sig'
    assets=[installer,portable]
    if not args.legacy:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key=bytes.fromhex((ROOT/'assets/update-public-key.hex').read_text().strip())
        Ed25519PublicKey.from_public_bytes(key).verify(signature.read_bytes(),manifest.read_bytes())
        value=json.loads(manifest.read_bytes())
        if value['tag']!=tag or value['sha256']!=sha(installer) or value['size']!=installer.stat().st_size:
            raise SystemExit('Signed update metadata mismatch')
        assets.extend([manifest,signature])
        if tuple(map(int,args.version.split('.'))) >= (0,14,0):
            live=out/'SCAU-Link-live.json';live_signature=out/'SCAU-Link-live.sig'
            Ed25519PublicKey.from_public_bytes(key).verify(live_signature.read_bytes(),live.read_bytes())
            details=json.loads(live.read_bytes())
            filename=f'SCAU-Link-{args.version}-Live-x64-preview.bin';capsule=out/filename
            if details['tag']!=tag or details['installerSha256']!=sha(installer) or details['filename']!=filename or \
               details['sha256']!=sha(capsule) or details['size']!=capsule.stat().st_size:
                raise SystemExit('Live update metadata differs from the verified release')
            stage=out/f'scau-link-{args.version}-win-x64-preview'
            for name,digest in details['protected'].items():
                if name not in {'scau-auth.exe','msvcp140.dll','msvcp140_atomic_wait.dll','vcruntime140.dll','vcruntime140_1.dll'} or sha(stage/name)!=digest:
                    raise SystemExit('Unexpected live compatibility file')
            if len(details['protected'])!=5:raise SystemExit('Incomplete live compatibility metadata')
            assets.extend([live,live_signature,capsule])
    public_report=out/f'SCAU-Link-{args.version}-verification.json';shutil.copy2(verification,public_report);assets.append(public_report)
    sums=out/f'SCAU-Link-{args.version}-SHA256SUMS.txt'
    sums.write_text(''.join(sha(path)+'  '+path.name+'\n' for path in assets),encoding='ascii');assets.append(sums)
    if not all(path.is_file() for path in assets):raise SystemExit('Missing release asset')
    existing=subprocess.run(['gh','release','view',tag,'--repo',REPOSITORY],cwd=ROOT,capture_output=True)
    if not existing.returncode:raise SystemExit('Release already exists; do not overwrite a published version')
    run('gh','release','create',tag,'--repo',REPOSITORY,'--draft','--prerelease',
        '--verify-tag','--title',f'SCAU Link {args.version} 预览版','--notes-file',str(args.notes_file.resolve(strict=True)))
    run('gh','release','upload',tag,'--repo',REPOSITORY,*map(str,assets))
    run('gh','release','edit',tag,'--repo',REPOSITORY,'--draft=false','--latest=false')
    print(run('gh','release','view',tag,'--repo',REPOSITORY,'--json','url','--jq','.url'))


if __name__=='__main__':main()
