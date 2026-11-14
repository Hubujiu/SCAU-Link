"""Sign the exact update manifest; keep the Ed25519 private key out of source control."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / 'build/signing/update-ed25519.pem'
PUBLIC = ROOT / 'assets/update-public-key.hex'


def main():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'sign'])
    parser.add_argument('--installer', type=Path)
    parser.add_argument('--version')
    parser.add_argument('--channel', choices=['preview', 'stable'], default='preview')
    parser.add_argument('--private-key', type=Path, default=PRIVATE)
    args = parser.parse_args()
    if args.action == 'init':
        if args.private_key.exists() or PUBLIC.exists():
            raise SystemExit('Existing update signing identity must not be overwritten.')
        key = Ed25519PrivateKey.generate()
        args.private_key.parent.mkdir(parents=True, exist_ok=True)
        args.private_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        PUBLIC.write_text(key.public_key().public_bytes(serialization.Encoding.Raw,
            serialization.PublicFormat.Raw).hex()+'\n', encoding='ascii')
        print('Created local signing identity. Commit the public key only.')
        return
    if not args.installer or not args.version:
        parser.error('sign requires --installer and --version')
    import re
    if not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)',args.version):
        parser.error('version must be a three-part numeric version')
    suffix = '-preview' if args.channel == 'preview' else ''
    expected = f'SCAU-Link-{args.version}-Setup-x64{suffix}.exe'
    if args.installer.name != expected:
        parser.error('Installer filename does not match signed version/channel')
    key = serialization.load_pem_private_key(args.private_key.read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey):
        raise SystemExit('Expected Ed25519 signing key')
    public = key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    if public.hex() != PUBLIC.read_text().strip():
        raise SystemExit('Signing identity differs from the public key compiled into the app')
    tag = 'v'+args.version+suffix
    manifest = dict(schema=1,version=args.version,tag=tag,channel=args.channel,architecture='x64',
        filename=expected,size=args.installer.stat().st_size,
        sha256=hashlib.sha256(args.installer.read_bytes()).hexdigest(),
        url=f'https://github.com/Hubujiu/SCAU-Link/releases/download/{tag}/{expected}')
    payload = (json.dumps(manifest,ensure_ascii=True,sort_keys=True,separators=(',',':'))+'\n').encode()
    target = args.installer.parent / 'SCAU-Link-update.json'
    target.write_bytes(payload)
    signature = target.with_suffix('.sig')
    signature.write_bytes(key.sign(payload))
    print(json.dumps(dict(manifest=str(target),signature=str(signature),version=args.version)))


if __name__ == '__main__':
    main()
