"""Windows-only, non-UI operations used by the offline network experiment.

No account/password retrieval, packet capture, adapter disabling, service changes,
location requests, system TLS changes, or unbound connectivity probes.
"""
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time

NO_WINDOW = 0x08000000
if os.name == "nt":
    K = C.WinDLL("kernel32", use_last_error=True)
    K.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    K.OpenProcess.restype = W.HANDLE
    K.CloseHandle.argtypes = [W.HANDLE]
    K.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    K.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
    K.GetProcessTimes.argtypes = [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4
    K.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
    K.OpenEventW.argtypes = [W.DWORD, W.BOOL, W.LPCWSTR]
    K.OpenEventW.restype = W.HANDLE
    K.SetEvent.argtypes = [W.HANDLE]


def same_path(a, b):
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def identity(pid, handle=None):
    owned = handle is None
    handle = handle or K.OpenProcess(0x1000 | 0x100000, False, int(pid))
    if not handle:
        return None
    try:
        if K.WaitForSingleObject(handle, 0) != 258:
            return None
        text, size = C.create_unicode_buffer(32768), W.DWORD(32768)
        times = [W.FILETIME() for _ in range(4)]
        if not K.QueryFullProcessImageNameW(handle, 0, text, C.byref(size)):
            if K.WaitForSingleObject(handle, 0) != 258:
                return None
            raise RuntimeError("process_identity_unavailable")
        if not K.GetProcessTimes(handle, *[C.byref(t) for t in times]):
            if K.WaitForSingleObject(handle, 0) != 258:
                return None
            raise RuntimeError("process_creation_time_unavailable")
        return {"pid": int(pid), "path": text.value,
                "born": (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime}
    finally:
        if owned:
            K.CloseHandle(handle)


def matches(expected, actual):
    return bool(expected and actual and expected["pid"] == actual["pid"]
                and expected["born"] == actual["born"]
                and same_path(expected["path"], actual["path"]))


def alive(expected):
    return bool(expected and matches(expected, identity(expected["pid"])))


def terminate(expected):
    """Check creation time AND image path on the very handle being terminated."""
    handle = K.OpenProcess(0x1000 | 0x100000 | 1, False, int(expected["pid"]))
    if not handle:
        return False
    try:
        if not matches(expected, identity(expected["pid"], handle)):
            return False
        if not K.TerminateProcess(handle, 90):
            raise RuntimeError("owned_process_termination_failed")
        if K.WaitForSingleObject(handle, 7000) != 0:
            raise RuntimeError("owned_process_exit_timeout")
        return True
    finally:
        K.CloseHandle(handle)


def can_control(expected):
    handle = K.OpenProcess(0x1000 | 0x100000 | 1, False, int(expected["pid"]))
    if not handle:
        return False
    try:
        return matches(expected, identity(expected["pid"], handle))
    finally:
        K.CloseHandle(handle)


def signal_stop(event):
    if not event or not re.fullmatch(r"Local\\ScauAuthSupervisor-\d+-[a-f0-9]{64}", event):
        return False
    handle = K.OpenEventW(2, False, event)
    if not handle:
        return False
    try:
        return bool(K.SetEvent(handle))
    finally:
        K.CloseHandle(handle)


def ps_json(body, timeout=15):
    # Neither stderr nor arbitrary PowerShell text is copied into public logs.
    prefix = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
    exe = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    result = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", prefix + body],
                            capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
    if result.returncode:
        raise RuntimeError("windows_inventory_failed")
    return json.loads(result.stdout.decode("utf-8-sig"))


def context():
    return ps_json("[pscustomobject]@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
                   "local=[Environment]::GetFolderPath('LocalApplicationData');elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}|ConvertTo-Json -Compress")


def ip_snapshot(index):
    if not isinstance(index, int) or not 0 < index < 65536:
        raise ValueError('invalid_interface')
    return ps_json(r"""$a=Get-NetAdapter -Physical|Where-Object {$_.ifIndex -eq """ + str(index) + r""" -and $_.NdisPhysicalMedium -eq 9};if(@($a).Count -ne 1){throw 'interface'}
    $p='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+[string]$a.InterfaceGuid
    $r=Get-ItemProperty -LiteralPath $p
    $manual=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.PrefixOrigin -eq 'Manual'}|Select-Object IPAddress,PrefixLength,SkipAsSource)
    [pscustomobject]@{index=[int]$a.ifIndex;guid=[string]$a.InterfaceGuid;dhcp=[int]$r.EnableDHCP;dns=@([string]$r.NameServer -split '[,; ]+'|Where-Object {$_});manual=$manual}|ConvertTo-Json -Depth 5 -Compress""")


def configure_test_ip(snapshot_path, restore=False):
    # Only read this locally-created backup, never interpolate addresses or DNS
    # strings into command text. Interface GUID + physical Wi-Fi type are pinned.
    literal = "'" + str(snapshot_path).replace("'", "''") + "'"
    prefix = "$s=Get-Content -LiteralPath " + literal + " -Raw|ConvertFrom-Json;"
    prefix += r"""$a=Get-NetAdapter -Physical|Where-Object {$_.ifIndex -eq $s.index -and $_.NdisPhysicalMedium -eq 9 -and [string]$_.InterfaceGuid -eq [string]$s.guid};if(@($a).Count -ne 1){throw 'interface_changed'};"""
    if not restore:
        body = r"""$stage='dhcp_enable';Set-NetIPInterface -InterfaceIndex $s.index -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
        $stage='dns_enable';
        Set-DnsClientServerAddress -InterfaceIndex $s.index -ResetServerAddresses -ErrorAction Stop
        [pscustomobject]@{ok=$true}|ConvertTo-Json -Compress"""
    else:
        body = r"""if($s.dhcp -eq 0){
          $stage='dhcp_disable';
          Set-NetIPInterface -InterfaceIndex $s.index -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
          $stage='lease_cleanup';
          foreach($lease in @(Get-NetIPAddress -InterfaceIndex $s.index -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.PrefixOrigin -eq 'Dhcp'})){
            try{$lease|Remove-NetIPAddress -Confirm:$false -ErrorAction Stop}catch{if(@(Get-NetIPAddress -InterfaceIndex $s.index -AddressFamily IPv4 -IPAddress $lease.IPAddress -ErrorAction SilentlyContinue).Count){throw}}
          }
        }else{$stage='dhcp_restore';Set-NetIPInterface -InterfaceIndex $s.index -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop}
        $stage='static_ip_restore';
        foreach($ip in $s.manual){if(-not @(Get-NetIPAddress -InterfaceIndex $s.index -AddressFamily IPv4 -IPAddress $ip.IPAddress -ErrorAction SilentlyContinue).Count){New-NetIPAddress -InterfaceIndex $s.index -AddressFamily IPv4 -IPAddress $ip.IPAddress -PrefixLength $ip.PrefixLength -SkipAsSource ([bool]$ip.SkipAsSource) -ErrorAction Stop|Out-Null}}
        $stage='dns_restore';
        if(@($s.dns).Count){Set-DnsClientServerAddress -InterfaceIndex $s.index -ServerAddresses @($s.dns) -ErrorAction Stop}else{Set-DnsClientServerAddress -InterfaceIndex $s.index -ResetServerAddresses -ErrorAction Stop}
        $stage='final_dhcp_restore';
        if($s.dhcp -eq 0){Set-NetIPInterface -InterfaceIndex $s.index -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop}else{Set-NetIPInterface -InterfaceIndex $s.index -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop}
        $stage='verification';
        for($i=0;$i -lt 10;$i++){$r=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+[string]$a.InterfaceGuid);if([int]$r.EnableDHCP -eq [int]$s.dhcp){break};Start-Sleep -Milliseconds 200}
        if($s.dhcp -eq 0 -and [int]$r.EnableDHCP -ne 0 -and @($s.manual).Count -eq 0){
          $stage='native_dhcp_disable';
          & ($env:SystemRoot+'\System32\netsh.exe') interface ipv4 set address ('name='+[string]$s.index) source=static store=persistent 2>$null|Out-Null
          Start-Sleep -Milliseconds 300
          $r=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+[string]$a.InterfaceGuid)
          if([int]$r.EnableDHCP -ne 0){
            # Windows rejects an empty static address via netsh. Restore this
            # pre-existing disabled/empty configuration exactly, on this pinned
            # interface only; do not invent a dummy static IP or gateway.
            $stage='empty_static_configuration_restore';
            Set-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+[string]$a.InterfaceGuid) -Name EnableDHCP -Type DWord -Value 0 -ErrorAction Stop
            Set-NetIPInterface -InterfaceIndex $s.index -AddressFamily IPv4 -PolicyStore ActiveStore -Dhcp Disabled -ErrorAction Stop
            $r=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+[string]$a.InterfaceGuid)
          }
        }
        [pscustomobject]@{ok=([int]$r.EnableDHCP -eq [int]$s.dhcp);stage=$stage;requested_dhcp=[int]$s.dhcp;observed_dhcp=[int]$r.EnableDHCP}|ConvertTo-Json -Compress"""
    body = "$stage='interface_guard';try{" + prefix + body + "}catch{[pscustomobject]@{ok=$false;stage=$stage;hresult=[long]$_.Exception.HResult}|ConvertTo-Json -Compress}"
    value = ps_json(body, timeout=25)
    if not value.get('ok'):
        error = RuntimeError('wireless_ip_configuration_failed')
        error.diagnostic = {k: value[k] for k in ('stage','hresult','requested_dhcp','observed_dhcp') if k in value}
        raise error


def processes():
    return ps_json(r"""$items=@(Get-CimInstance Win32_Process -Filter "Name='SCAU-Link.exe' OR Name='scau-auth.exe' OR Name='8021x.exe' OR Name='network-backend-probe.exe' OR Name='network-delivery-probe.exe' OR Name='wlan-credential-probe.exe'"|ForEach-Object {
        $stop=[regex]::Match([string]$_.CommandLine,'--stop-event"?\s+"?(Local\\ScauAuthSupervisor-[0-9]+-[a-f0-9]{64})').Groups[1].Value
        [pscustomobject]@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;path=$_.ExecutablePath;stop=$stop}
    });ConvertTo-Json -InputObject $items -Compress""")


def start_desktop_unelevated(executable, arguments=None):
    path = "'" + str(executable).replace("'", "''") + "'"
    folder = "'" + str(Path(executable).parent).replace("'", "''") + "'"
    args = "'" + subprocess.list2cmdline(arguments or ['--silent']).replace("'", "''") + "'"
    started = time.time()
    ps_json("$s=New-Object -ComObject Shell.Application;$h=0;$d=$s.Windows().FindWindowSW(0,0,8,[ref]$h,1);if(-not $d){throw 'desktop'};"
            "$d.Document.Application.ShellExecute(" + path + "," + args + "," + folder + ",'open',0);$true|ConvertTo-Json -Compress")
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        for p in processes():
            if p.get('path') and same_path(p['path'], executable):
                item = identity(p['pid'])
                if item and item['born'] / 10000000 - 11644473600 >= started - 1:
                    return item
        time.sleep(.1)
    raise RuntimeError('desktop_launch_not_observed')


def adapters():
    return ps_json(r"""$items=@(Get-NetAdapter -Physical|Where-Object {$_.NdisPhysicalMedium -in @(9,14)}|ForEach-Object {
      $a=$_;$ips=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*'})
      $dns=Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
      $ipif=Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
      $config=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+[string]$a.InterfaceGuid) -ErrorAction SilentlyContinue
      [pscustomobject]@{index=[int]$a.ifIndex;medium=[int]$a.NdisPhysicalMedium;status=[string]$a.Status;address=($ips|Select-Object -First 1).IPAddress;dns=@($dns.ServerAddresses);dhcp=[string]$ipif.Dhcp;ip_state=[string]$ipif.ConnectionState;configured_dhcp=$config.EnableDHCP}
    });ConvertTo-Json -InputObject $items -Compress""")


def probe(index):
    # Reuse the existing bounded DNS decoder and Windows interface binding.
    from probe_ethernet import bound_socket, resolve_direct, HOST
    begin = time.monotonic()
    result = {"ok": False, "interface": index, "interface_bound": True}
    stage = "adapter_configuration"
    try:
        found = [a for a in adapters() if a["index"] == index]
        if len(found) == 1:
            a = found[0]
            result.update(adapter_state=a['status'], ip_state=a['ip_state'], dhcp=a['dhcp'],
                          configured_dhcp=a.get('configured_dhcp'), preferred_ipv4=bool(a.get('address')), dns_count=len(a.get('dns') or []))
        if len(found) != 1 or found[0]['status'] != 'Up' or not found[0].get("address") or not found[0].get("dns"):
            raise ValueError()
        config = found[0]
        # Bound the work regardless of how many DNS answers/servers are returned.
        config["dns"] = config["dns"][:2]
        stage = "direct_dns"
        addresses = resolve_direct(config)[:2]
        stage = "direct_http"
        for address in addresses:
            try:
                with bound_socket(config, socket.SOCK_STREAM) as sock:
                    sock.connect((address, 80))
                    sock.sendall(f"GET /connecttest.txt HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode("ascii"))
                    response = b""
                    # Bound total response time, not merely each recv call.
                    end = time.monotonic() + 5
                    while len(response) < 8192 and time.monotonic() < end:
                        sock.settimeout(max(.1, min(2, end - time.monotonic())))
                        data = sock.recv(min(4096, 8192 - len(response)))
                        if not data:
                            break
                        response += data
                header, separator, body = response.partition(b"\r\n\r\n")
                status = header.split(b"\r\n", 1)[0].split(b" ")
                if separator and len(status) > 1 and status[1] == b"200" and body.strip() == b"Microsoft Connect Test":
                    result.update(ok=True, dns_direct=True, http_verified=True)
                    break
            except OSError:
                continue
        if not result["ok"]:
            raise ValueError()
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        result["failed_stage"] = stage
    result["duration_ms"] = round((time.monotonic() - begin) * 1000)
    return result


def wlan_diagnostics(since):
    """Numeric failure fields only; no rendered event messages/identities/XML."""
    if not re.fullmatch(r"[0-9T:.+Z-]+", since):
        raise ValueError("invalid_diagnostic_time")
    return ps_json(r"""$start=[DateTimeOffset]::Parse('""" + since + r"""').LocalDateTime
    $items=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational';StartTime=$start} -MaxEvents 80 -ErrorAction SilentlyContinue|ForEach-Object {
      [xml]$xml=$_.ToXml();$fields=@{};foreach($d in $xml.Event.EventData.Data){if($d.Name -in @('ReasonCode','ErrorCode','FailureReason','EapReasonCode','EapErrorCode') -and [string]$d.'#text' -match '^\d+$'){$fields[[string]$d.Name]=[string]$d.'#text'}}
      if($fields.Count){[pscustomobject]@{event_id=$_.Id;time=$_.TimeCreated.ToUniversalTime().ToString('o');codes=$fields}}
    });ConvertTo-Json -InputObject $items -Compress""")


# Profile inventory/deletion does not retrieve profile XML, keys, identities or
# BSSIDs. A deletion requires BOTH our random name and exact custom ownership tag.
class GUID(C.Structure):
    _fields_ = [("data", C.c_ubyte * 16)]


class Interface(C.Structure):
    _fields_ = [("guid", GUID), ("description", W.WCHAR * 256), ("state", W.DWORD)]


class Profile(C.Structure):
    _fields_ = [("name", W.WCHAR * 256), ("flags", W.DWORD)]


def stable_wlan_profiles(index, restore=None):
    """Public XML only, for the two exact campus names on the pinned NIC.

    No EAP user data, keys or password export. Backups stay in the run's private
    directory. The guardian can restore after a crashed native test process.
    """
    adapter = ps_json('Get-NetAdapter -Physical|Where-Object {$_.ifIndex -eq '+str(int(index))+
                      ' -and $_.NdisPhysicalMedium -eq 9}|Select-Object InterfaceGuid|ConvertTo-Json -Compress')
    if not adapter:
        raise RuntimeError('stable_profile_interface_missing')
    guid = GUID()
    ole = C.OleDLL('ole32')
    ole.CLSIDFromString.argtypes = [W.LPCWSTR, C.POINTER(GUID)]
    if ole.CLSIDFromString(adapter['InterfaceGuid'], C.byref(guid)):
        raise RuntimeError('stable_profile_interface_invalid')
    wlan = C.WinDLL('wlanapi')
    wlan.WlanOpenHandle.argtypes = [W.DWORD,C.c_void_p,C.POINTER(W.DWORD),C.POINTER(W.HANDLE)]
    wlan.WlanCloseHandle.argtypes = [W.HANDLE,C.c_void_p]
    wlan.WlanFreeMemory.argtypes = [C.c_void_p]
    wlan.WlanGetProfile.argtypes = [W.HANDLE,C.POINTER(GUID),W.LPCWSTR,C.c_void_p,C.POINTER(C.c_void_p),C.POINTER(W.DWORD),C.POINTER(W.DWORD)]
    wlan.WlanSetProfile.argtypes = [W.HANDLE,C.POINTER(GUID),W.DWORD,W.LPCWSTR,W.LPCWSTR,W.BOOL,C.c_void_p,C.POINTER(W.DWORD)]
    wlan.WlanDeleteProfile.argtypes = [W.HANDLE,C.POINTER(GUID),W.LPCWSTR,C.c_void_p]
    wlan.WlanGetProfileCustomUserData.argtypes = [W.HANDLE,C.POINTER(GUID),W.LPCWSTR,C.c_void_p,C.POINTER(W.DWORD),C.POINTER(C.c_void_p)]
    version,handle=W.DWORD(),W.HANDLE()
    if wlan.WlanOpenHandle(2,None,C.byref(version),C.byref(handle)):
        raise RuntimeError('stable_profile_service_unavailable')
    def read(name):
        raw,flags,access=C.c_void_p(),W.DWORD(),W.DWORD()
        status=wlan.WlanGetProfile(handle,C.byref(guid),name,None,C.byref(raw),C.byref(flags),C.byref(access))
        try:
            if status==1168:return None
            if status or not raw:raise RuntimeError('stable_profile_read_failed')
            xml=C.wstring_at(raw)
            if len(xml)>65536:raise RuntimeError('stable_profile_xml_too_large')
            return {'xml':xml,'flags':flags.value & 2}
        finally:
            if raw:wlan.WlanFreeMemory(raw)
    try:
        names=('SCAUNET','SCAUNET_1x')
        if restore is None:
            return {'guid':adapter['InterfaceGuid'],'profiles':{name:read(name) for name in names}}
        if adapter['InterfaceGuid'].lower()!=restore['guid'].lower() or set(restore['profiles'])!=set(names):
            raise RuntimeError('stable_profile_restore_context_changed')
        for name in names:
            before=restore['profiles'][name]
            if read(name)==before:continue
            if before is None:
                size,raw=W.DWORD(),C.c_void_p()
                code=wlan.WlanGetProfileCustomUserData(handle,C.byref(guid),name,None,C.byref(size),C.byref(raw))
                try:
                    tag=b'SCAULink.WLAN8021X.v1\0'
                    if code or not raw or size.value!=len(tag) or C.string_at(raw,size.value)!=tag:
                        raise RuntimeError('stable_profile_new_owner_unconfirmed')
                finally:
                    if raw:wlan.WlanFreeMemory(raw)
                if wlan.WlanDeleteProfile(handle,C.byref(guid),name,None):
                    raise RuntimeError('stable_profile_delete_failed')
            else:
                reason=W.DWORD()
                if wlan.WlanSetProfile(handle,C.byref(guid),int(before['flags']),before['xml'],None,True,None,C.byref(reason)):
                    raise RuntimeError('stable_profile_restore_failed')
            if read(name)!=before:raise RuntimeError('stable_profile_restore_mismatch')
        return True
    finally:
        wlan.WlanCloseHandle(handle,None)


def owned_profiles(delete_except=None):
    wlan = C.WinDLL("wlanapi")
    wlan.WlanOpenHandle.argtypes = [W.DWORD, C.c_void_p, C.POINTER(W.DWORD), C.POINTER(W.HANDLE)]
    wlan.WlanCloseHandle.argtypes = [W.HANDLE, C.c_void_p]
    wlan.WlanFreeMemory.argtypes = [C.c_void_p]
    wlan.WlanEnumInterfaces.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(C.c_void_p)]
    wlan.WlanGetProfileList.argtypes = [W.HANDLE, C.POINTER(GUID), C.c_void_p, C.POINTER(C.c_void_p)]
    wlan.WlanGetProfileCustomUserData.argtypes = [W.HANDLE, C.POINTER(GUID), W.LPCWSTR, C.c_void_p, C.POINTER(W.DWORD), C.POINTER(C.c_void_p)]
    wlan.WlanDeleteProfile.argtypes = [W.HANDLE, C.POINTER(GUID), W.LPCWSTR, C.c_void_p]
    version, handle = W.DWORD(), W.HANDLE()
    if wlan.WlanOpenHandle(2, None, C.byref(version), C.byref(handle)):
        raise RuntimeError("wlan_inventory_unavailable")
    found, interfaces = [], C.c_void_p()
    try:
        if wlan.WlanEnumInterfaces(handle, None, C.byref(interfaces)) or not interfaces:
            raise RuntimeError("wlan_interface_inventory_unavailable")
        count = C.cast(interfaces, C.POINTER(W.DWORD))[0]
        if count > 128:
            raise RuntimeError("wlan_inventory_invalid")
        for i in range(count):
            interface = Interface.from_address(interfaces.value + 8 + i * C.sizeof(Interface))
            profiles = C.c_void_p()
            if wlan.WlanGetProfileList(handle, C.byref(interface.guid), None, C.byref(profiles)):
                raise RuntimeError("wlan_profile_inventory_unavailable")
            try:
                number = C.cast(profiles, C.POINTER(W.DWORD))[0]
                if number > 4096:
                    raise RuntimeError("wlan_inventory_invalid")
                for j in range(number):
                    p = Profile.from_address(profiles.value + 8 + j * C.sizeof(Profile))
                    if not re.fullmatch(r"SCAU-Link-(?:SCAUNET_1x|SCAUNET)-[0-9a-f]{32}", p.name) or p.flags not in (0, 2):
                        continue
                    size, raw = W.DWORD(), C.c_void_p()
                    code = wlan.WlanGetProfileCustomUserData(handle, C.byref(interface.guid), p.name, None, C.byref(size), C.byref(raw))
                    try:
                        tag = b"SCAULink.WLAN8021X.v1\0"
                        if code or size.value != len(tag) or not raw or C.string_at(raw, size.value) != tag:
                            continue
                    finally:
                        if raw:
                            wlan.WlanFreeMemory(raw)
                    key = bytes(interface.guid.data).hex() + ":" + p.name
                    found.append(key)
                    if delete_except is not None and key not in delete_except:
                        if wlan.WlanDeleteProfile(handle, C.byref(interface.guid), p.name, None):
                            raise RuntimeError("owned_wlan_profile_cleanup_failed")
            finally:
                if profiles:
                    wlan.WlanFreeMemory(profiles)
        return found
    finally:
        if interfaces:
            wlan.WlanFreeMemory(interfaces)
        wlan.WlanCloseHandle(handle, None)
