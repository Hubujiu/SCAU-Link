"""Build the pinned, bundled OpenSSL source as native MSVC static libraries.

The portable Perl tool is used only during compilation; nothing is installed
system-wide. No prebuilt third-party TLS DLLs are copied from installed apps.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DEPS = ROOT / 'build/deps'
META = json.loads((ROOT / 'third_party/openssl/provenance.json').read_text(encoding='utf-8'))
PERL_VERSION = '5.42.3.1'
PERL_ZIP = f'strawberry-perl-{PERL_VERSION}-64bit-portable.zip'
PERL_SHA = '6a081a811781c30aca51dbc036afd93092af91e3297901f02c17043795a10690'
PERL_URL = 'https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54231_64bit/' + PERL_ZIP


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def download(url, path, expected):
    if not path.exists():
        print('Downloading build dependency: ' + path.name, flush=True)
        part = path.with_suffix('.part')
        with urllib.request.urlopen(url, timeout=30) as incoming, part.open('wb') as outgoing:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
        if digest(part) != expected:
            raise RuntimeError('Dependency SHA-256 mismatch: ' + path.name)
        part.replace(path)
    if digest(path) != expected:
        raise RuntimeError('Dependency SHA-256 mismatch: ' + path.name)


def main():
    DEPS.mkdir(parents=True, exist_ok=True)
    source_archive = ROOT / 'third_party/openssl' / META['archive']
    if digest(source_archive) != META['sha256']:
        raise RuntimeError('Bundled OpenSSL source SHA-256 mismatch')
    prefix = DEPS / 'openssl-install'
    stamp = prefix / 'scau-build.json'
    options = ['VC-WIN64A', 'no-asm', 'no-shared', 'no-tests', 'no-apps', 'no-docs', 'no-makedepend',
               'no-module', 'no-engine', 'no-dso', 'no-comp', 'no-legacy', 'no-quic',
               'no-ml-dsa', 'no-ml-kem', 'no-slh-dsa']
    identity = {'version': META['version'], 'sourceSha256': META['sha256'], 'configure': options}
    if stamp.exists() and json.loads(stamp.read_text(encoding='utf-8')) == identity:
        if (prefix / 'include/openssl/ssl.h').is_file() and any((prefix / 'lib').glob('*ssl*.lib')):
            print('OpenSSL ' + META['version'] + ' native libraries are up to date.', flush=True)
            return
    source = DEPS / ('openssl-' + META['version'])
    if not (source / 'Configure').exists():
        with tarfile.open(source_archive) as archive:
            archive.extractall(DEPS, filter='data')
    perl_root = DEPS / ('strawberry-perl-' + PERL_VERSION)
    perl = perl_root / 'perl/bin/perl.exe'
    if not perl.exists():
        perl_archive = DEPS / PERL_ZIP
        download(PERL_URL, perl_archive, PERL_SHA)
        with zipfile.ZipFile(perl_archive) as archive:
            for item in archive.infolist():
                # Compiler tools are unnecessary. Keep Perl and its runtime DLLs.
                if item.filename.startswith('perl/') or (item.filename.startswith('c/bin/') and item.filename.endswith('.dll')):
                    target = (perl_root / item.filename).resolve()
                    if not target.is_relative_to(perl_root.resolve()):
                        raise RuntimeError('Unsafe portable tool archive path')
                    archive.extract(item, perl_root)
    vswhere = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    install = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
                                       'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'],
                                      text=True).strip()
    vcvars = Path(install) / 'VC/Auxiliary/Build/vcvars64.bat'
    if not vcvars.is_file():
        raise RuntimeError('Visual Studio C++ build environment is unavailable')
    log = DEPS / 'openssl-build.log'
    command = DEPS / 'build-openssl.cmd'
    configure = ' '.join(options + ['--libdir=lib', '"--prefix=' + str(prefix) + '"'])
    command.write_text(
        '@echo off\n'
        f'call "{vcvars}" > nul\n'
        'if errorlevel 1 exit /b 1\n'
        f'set "PATH={perl.parent};{perl_root / "c/bin"};%PATH%"\n'
        f'cd /d "{source}"\n'
        f'"{perl}" Configure {configure} > "{log}" 2>&1\n'
        'if errorlevel 1 exit /b 1\n'
        f'nmake /nologo build_libs >> "{log}" 2>&1\n'
        'if errorlevel 1 exit /b 1\n'
        f'nmake /nologo install_dev >> "{log}" 2>&1\n'
        'exit /b %errorlevel%\n', encoding='utf-8')
    print('Building native OpenSSL ' + META['version'] + '; log: ' + str(log), flush=True)
    result = subprocess.run([os.environ.get('COMSPEC', r'C:\Windows\System32\cmd.exe'), '/d', '/c', str(command)])
    if result.returncode:
        print('\n'.join(log.read_text(encoding='utf-8', errors='replace').splitlines()[-35:]))
        raise RuntimeError('Native OpenSSL build failed')
    stamp.write_text(json.dumps(identity, indent=2) + '\n', encoding='utf-8')
    print('Native OpenSSL build completed.', flush=True)


if __name__ == '__main__':
    main()
