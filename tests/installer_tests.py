"""Exercise an isolated setup build: custom Unicode path, upgrade and uninstall.

No normal application is launched. Only the QA AppId/startup key is changed;
the production startup value and user's own settings must remain unchanged.
"""
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
import winreg

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.search(r'project\(ScauNativeAuth VERSION ([\d.]+)',
                   (ROOT/'CMakeLists.txt').read_text(encoding='utf-8')).group(1)
UNINSTALL = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\SCAULink.InstallerTest.v1_is1'
QA_RUN = r'Software\SCAULink\InstallerTests\Run'
QA_VALUE = 'SCAULinkInstallerTest'
REAL_RUN = r'Software\Microsoft\Windows\CurrentVersion\Run'
MUTEX = r'Local\SCAULink.InstallerTest.v1'
checks = []

def require(condition, name):
    if not condition: raise AssertionError(name)
    checks.append(dict(name=name, passed=True))

def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()

def query(key, value):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,key,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as handle:
            return winreg.QueryValueEx(handle,value)
    except FileNotFoundError: return None

def set_qa(value):
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,QA_RUN,0,winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key,QA_VALUE,0,winreg.REG_SZ,value)

def own_data():
    folder=Path(os.environ['LOCALAPPDATA'])/'ScauLink'
    return {name:sha(folder/name) if (folder/name).is_file() else None
            for name in ['settings.ini','accounts.dat','profile.scau']}

def run(exe, args):
    return subprocess.run([str(exe),'/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',*args],
                          creationflags=subprocess.CREATE_NO_WINDOW,timeout=90).returncode

def mutex():
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.LPCWSTR]
    kernel.CreateMutexW.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.CreateMutexW(None,False,MUTEX)
    if not handle or ctypes.get_last_error()==183: raise RuntimeError('QA mutex already held')
    return kernel,handle

def uninstall_path(area):
    raw=query(UNINSTALL,'UninstallString')[0]
    if not (raw.startswith('"') and raw.endswith('"')): raise RuntimeError('Unexpected QA uninstall command')
    path=Path(raw[1:-1]).resolve()
    if not path.is_relative_to(area) or not re.fullmatch(r'unins\d+\.exe',path.name):
        raise RuntimeError('QA uninstaller escaped the test area')
    return path

def main():
    metadata=json.loads((ROOT/'out'/f'installer-{VERSION}-test.json').read_text(encoding='utf-8'))
    setup=Path(metadata['installer'])
    require(metadata['installerTest'] is True and sha(setup)==metadata['sha256'], 'verified-isolated-test-installer')
    require(query(UNINSTALL,'UninstallString') is None and query(QA_RUN,QA_VALUE) is None,
            'qa-registry-namespace-unused')
    startup_before=query(REAL_RUN,'SCAULink')
    data_before=own_data()
    area=(ROOT/'build/installer-tests'/uuid.uuid4().hex).resolve()
    require(area.is_relative_to((ROOT/'build/installer-tests').resolve()), 'test-path-confined-to-workspace')
    target=area/'中文路径 带空格'/'校园网 客户端'
    target.mkdir(parents=True)
    sentinel=target/'用户自己的文件.txt'
    sentinel.write_text('Preserve unrelated files.\n',encoding='utf-8')
    kernel,held=mutex()
    try:
        blocked=run(setup,['/DIR='+str(target),'/NOICONS','/TASKS=', '/LOG='+str(area/'blocked-install.log')])
    finally: kernel.CloseHandle(held)
    require(blocked!=0 and not (target/'SCAU-Link.exe').exists(), 'running-app-mutex-blocks-install-without-closing-app')
    flags=['/DIR='+str(target),'/NOICONS','/TASKS=']
    require(run(setup,flags+['/LOG='+str(area/'install.log')])==0,'custom-unicode-and-space-path-install')
    require((target/'SCAU-Link.exe').is_file() and not (target/'SCAU Link/SCAU-Link.exe').exists(),
            'chosen-directory-used-exactly-without-appending-another-folder')
    for name,digest in metadata['applicationHashes'].items():
        require(sha(target/name)==digest,'installed-release-hash-'+name)
    for name,details in metadata['runtime']['files'].items():
        require(sha(target/name)==details['sha256'],'app-local-runtime-'+name)
    require(sha(target/'docs/source.zip')==metadata['sourceArchiveSha256'],'corresponding-source-installed')
    require(query(UNINSTALL,'InstallLocation')[0].rstrip('\\')==str(target),'uninstall-registration-points-to-custom-directory')
    require(query(QA_RUN,QA_VALUE) is None,'fresh-install-does-not-enable-startup')
    previous='"'+str(area/'old portable/SCAU-Link.exe')+'" --startup'
    set_qa(previous)
    require(run(setup,flags+['/LOG='+str(area/'upgrade.log')])==0,'same-path-upgrade')
    require(query(QA_RUN,QA_VALUE)[0]=='"'+str(target/'SCAU-Link.exe')+'" --startup',
            'known-enabled-startup-command-relocated-in-isolated-key')
    uninstaller=uninstall_path(area)
    require(uninstaller.is_file(),'native-uninstaller-created')
    kernel,held=mutex()
    try:
        blocked=run(uninstaller,['/LOG='+str(area/'blocked-uninstall.log')])
    finally: kernel.CloseHandle(held)
    require(blocked!=0 and (target/'SCAU-Link.exe').exists(), 'running-app-mutex-also-blocks-uninstall')
    require(run(uninstaller,['/LOG='+str(area/'uninstall.log')])==0,'uninstall-succeeds-without-app-running')
    require(not (target/'SCAU-Link.exe').exists() and not (target/'scau-auth.exe').exists(),
            'uninstall-removes-only-installed-application')
    require(sentinel.read_text(encoding='utf-8')=='Preserve unrelated files.\n','unrelated-files-preserved')
    require(query(UNINSTALL,'UninstallString') is None and query(QA_RUN,QA_VALUE) is None,
            'own-uninstall-and-startup-registration-removed')
    # An unrelated command under the QA startup value must survive both paths.
    foreign='"'+str(area/'other-app.exe')+'" --startup'
    set_qa(foreign)
    require(run(setup,flags+['/LOG='+str(area/'foreign-install.log')])==0,'install-with-unrelated-startup-value')
    require(query(QA_RUN,QA_VALUE)[0]==foreign,'unrelated-startup-command-not-rewritten')
    uninstaller=uninstall_path(area)
    require(run(uninstaller,['/LOG='+str(area/'foreign-uninstall.log')])==0,'uninstall-with-unrelated-startup-value')
    require(query(QA_RUN,QA_VALUE)[0]==foreign,'unrelated-startup-command-not-deleted')
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,QA_RUN,0,winreg.KEY_SET_VALUE) as key:
        winreg.DeleteValue(key,QA_VALUE)
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER,QA_RUN)
    require(query(REAL_RUN,'SCAULink')==startup_before and own_data()==data_before,
            'production-startup-and-own-account-settings-untouched')
    result=dict(version=VERSION,status='passed',passed=len(checks),total=len(checks),checks=checks,
                qaInstallerSha256=metadata['sha256'],qaOnly=True,customDirectory=str(target),
                testDirectoryOnNonSystemDrive=target.drive.lower()!=Path(os.environ['LOCALAPPDATA']).drive.lower(),
                applicationLaunched=False,realAuthenticationChanged=False,networkDriverInstalled=False,
                productionRegistryChanged=False,settingsAndAccountsPreserved=True,
                logs=str(area),checkedAt=datetime.now(timezone.utc).isoformat())
    (ROOT/'docs'/f'installer-tests-{VERSION}.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ['checks','customDirectory','logs']},ensure_ascii=False))

if __name__=='__main__': main()
