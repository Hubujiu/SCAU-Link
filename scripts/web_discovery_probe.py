"""Explicit local SCAUNET discovery, no credentials and no login requests.

Run only under network_lab's independent watchdog. Raw intercepted pages stay
in this run's private directory; public records contain origin/path shapes only.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import ipaddress
import http.client
import json
from pathlib import Path
import re
import secrets
import socket
import subprocess
import time
import urllib.parse

import network_lab as lab
import network_lab_windows as win
import probe_ethernet as direct_dns
from probe_ethernet import bound_socket


def main(run):
    cfg = lab.read(run / 'config.json')
    snap = lab.read(run / 'snapshot.json')
    index = snap['wifiIndex']
    name = 'SCAU-Link-SCAUNET-' + secrets.token_hex(16)
    private = run / 'private'
    private.mkdir(exist_ok=True)
    xml = ('<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
           '<name>'+name+'</name><SSIDConfig><SSID><name>SCAUNET</name></SSID></SSIDConfig>'
           '<connectionType>ESS</connectionType><connectionMode>manual</connectionMode><MSM><security>'
           '<authEncryption><authentication>open</authentication><encryption>none</encryption>'
           '<useOneX>false</useOneX></authEncryption></security></MSM>')
    if cfg.get('freshWirelessIdentity'):
        xml += ('<MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">'
                '<enableRandomization>true</enableRandomization><randomizeEveryday>false</randomizeEveryday>'
                '<randomizationSeed>'+str(secrets.randbelow(2**31))+'</randomizationSeed></MacRandomization>')
    else:
        xml += ('<MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">'
                '<enableRandomization>false</enableRandomization></MacRandomization>')
    xml += '</WLANProfile>'
    path = private / 'open-wifi.xml'
    path.write_text(xml, encoding='utf-8')
    adapter = win.ps_json('Get-NetAdapter -Physical|Where-Object {$_.ifIndex -eq '+str(index)+
                         '}|Select-Object Name,InterfaceGuid|ConvertTo-Json -Compress')
    netsh = str(Path(__import__('os').environ['SystemRoot']) / 'System32/netsh.exe')
    def command(*args):
        result = subprocess.run([netsh, 'wlan', *args], capture_output=True, timeout=15, creationflags=win.NO_WINDOW)
        if result.returncode:
            raise RuntimeError('wlan_diagnostic_command_failed')
    result = {'associated': False, 'addressReady': False, 'pages': [], 'profileStore':'all-user-network'}
    started = lab.utc()
    created = False
    try:
        scan = subprocess.run([netsh, 'wlan', 'show', 'networks', 'mode=bssid', 'interface='+adapter['Name']],
                              capture_output=True, timeout=15, creationflags=win.NO_WINDOW)
        result['visible'] = {'commandOk': scan.returncode == 0,
                             'SCAUNET': bool(re.search(rb'SCAUNET\s*(?:\r?\n|$)', scan.stdout)),
                             'SCAUNET_1x': b'SCAUNET_1x' in scan.stdout}
        existing = subprocess.run([netsh, 'wlan', 'show', 'profile', 'name=SCAUNET', 'interface='+adapter['Name']],
                                  capture_output=True, timeout=15, creationflags=win.NO_WINDOW)
        if not cfg.get('freshWirelessIdentity') and existing.returncode == 0:
            name = 'SCAUNET'
            result['reusedExistingProfile'] = True
        else:
            command('add', 'profile', 'filename='+str(path), 'interface='+adapter['Name'], 'user=all')
            created = True
        wlan = C.WinDLL('wlanapi')
        wlan.WlanOpenHandle.argtypes = [W.DWORD, C.c_void_p, C.POINTER(W.DWORD), C.POINTER(W.HANDLE)]
        wlan.WlanSetProfileCustomUserData.argtypes = [W.HANDLE, C.POINTER(win.GUID), W.LPCWSTR, W.DWORD, C.c_void_p, C.c_void_p]
        wlan.WlanCloseHandle.argtypes = [W.HANDLE, C.c_void_p]
        guid = win.GUID()
        ole = C.OleDLL('ole32')
        ole.CLSIDFromString.argtypes = [W.LPCWSTR, C.POINTER(win.GUID)]
        if ole.CLSIDFromString(adapter['InterfaceGuid'], C.byref(guid)):
            raise RuntimeError('invalid_diagnostic_interface')
        version, handle = W.DWORD(), W.HANDLE()
        if wlan.WlanOpenHandle(2, None, C.byref(version), C.byref(handle)):
            raise RuntimeError('wlan_diagnostic_open_failed')
        try:
            tag = C.create_string_buffer(b'SCAULink.WLAN8021X.v1\0', 22)
            if created and wlan.WlanSetProfileCustomUserData(handle, C.byref(guid), name, 22, tag, None):
                raise RuntimeError('wlan_diagnostic_tag_failed')
        finally:
            wlan.WlanCloseHandle(handle, None)
        command('connect', 'name='+name, 'ssid=SCAUNET', 'interface='+adapter['Name'])
        deadline = time.monotonic() + 50
        current = None
        while time.monotonic() < deadline:
            current = next((a for a in win.adapters() if a['index'] == index), None)
            if current and current['status'] == 'Up': result['associated'] = True
            if current and current['status'] == 'Up' and current.get('address') and current.get('dns'):
                result['addressReady'] = True
                break
            time.sleep(1)
        if not result['addressReady']:
            raise RuntimeError('diagnostic_wifi_address_unavailable')
        # Read-only current-session schema, including when the NAS already
        # allows this MAC and therefore no longer emits a portal redirect.
        try:
            with bound_socket(current,socket.SOCK_STREAM) as connection:
                connection.connect(('192.168.253.3',80))
                connection.sendall(b'POST /eportal/InterFace.do?method=getOnlineUserInfo HTTP/1.1\r\n'
                    b'Host: 192.168.253.3\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) SCAU-Link/0.12.0\r\n'
                    b'Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: 10\r\n'
                    b'Connection: close\r\n\r\nuserIndex=')
                response=http.client.HTTPResponse(connection);response.begin();raw=response.read(262144)
            (private/'online-schema.private').write_bytes(raw)
            value=json.loads(raw)
            result['onlineSchema']={'http':response.status,'keys':list(value),'result':value.get('result'),
                                    'hasIndex':bool(value.get('userIndex'))}
        except Exception as error:
            result['onlineSchema']={'failure':type(error).__name__}
        urls = ['http://neverssl.com/', 'http://www.baidu.com/', 'http://example.com/',
                'http://1.1.1.1/', 'http://www.msftconnecttest.com/connecttest.txt']
        seen = set()
        portal_target = None
        for number in range(12):
            if number >= len(urls): break
            url = urls[number]
            if url in seen: continue
            seen.add(url)
            parsed = urllib.parse.urlsplit(url)
            if parsed.path == '/eportal/index.jsp' and parsed.query:
                portal_target = url
            if parsed.scheme != 'http' or parsed.username or parsed.password: continue
            host = parsed.hostname
            if re.fullmatch(r'[0-9.]+', host or ''):
                addresses = [host]
            else:
                direct_dns.HOST = host
                try: addresses = direct_dns.resolve_direct(current)
                except (OSError, ValueError):
                    result['pages'].append({'host':host,'failure':'bound_dns_unavailable'})
                    continue
            for address in addresses[:2]:
                try:
                    ipaddress.IPv4Address(address)
                    with bound_socket(current, socket.SOCK_STREAM) as connection:
                        connection.connect((address, parsed.port or 80))
                        target = urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
                        connection.sendall(('GET '+target+' HTTP/1.1\r\nHost: '+parsed.netloc+
                                            '\r\nConnection: close\r\n\r\n').encode('ascii'))
                        raw = b''
                        while len(raw) < 262144:
                            block = connection.recv(min(8192, 262144-len(raw)))
                            if not block: break
                            raw += block
                    (private / ('web-'+str(number)+'.bin')).write_bytes(raw)
                    text = raw.decode('utf-8', errors='replace')
                    location = re.search(r'(?im)^Location:\s*(\S+)', text)
                    redirects = ([location.group(1)] if location else []) + re.findall(r'''(?:location\.href|location)\s*=\s*["']([^"']+)["']''', text)
                    scripts = re.findall(r'''(?i)<script[^>]+src=["']([^"']+)["']''', text)
                    for value in redirects[:2] + scripts[:6]:
                        full = urllib.parse.urljoin(url, value)
                        p = urllib.parse.urlsplit(full)
                        if p.scheme == 'http' and p.hostname and not p.username and len(full) < 16384 and len(urls) < 16:
                            urls.append(full)
                    result['pages'].append({'origin':parsed.scheme+'://'+parsed.netloc,'path':parsed.path,
                        'status':int(text.split(' ',2)[1]),'bytes':len(raw),
                        'queryKeys':list(urllib.parse.parse_qs(parsed.query))[:32],
                        'redirects':[{'origin':urllib.parse.urlsplit(urllib.parse.urljoin(url,v)).netloc,
                                      'path':urllib.parse.urlsplit(urllib.parse.urljoin(url,v)).path} for v in redirects[:2]],
                        'apiFamilies':sorted(set(re.findall(r'(?:InterFace\.do|authAPI|drcom|eportal|/api/v[0-9]+)',text)))})
                    break
                except (OSError, ValueError):
                    continue
        if portal_target:
            target = urllib.parse.urlsplit(portal_target)
            for port in (80, 8080):
                for kind in ('authAPI', 'InterFace'):
                    body = json.dumps({'queryString':target.query,'userAgent':'PC','userip':current['address']}) if kind == 'authAPI' else 'queryString='+urllib.parse.quote(urllib.parse.quote(target.query,safe=''),safe='')
                    path = '/eportal/inferface/authAPI/pageInfo' if kind == 'authAPI' else '/eportal/InterFace.do?method=pageInfo'
                    mime = 'application/json' if kind == 'authAPI' else 'application/x-www-form-urlencoded; charset=UTF-8'
                    try:
                        with bound_socket(current,socket.SOCK_STREAM) as connection:
                            connection.connect((target.hostname,port))
                            connection.sendall(('POST '+path+' HTTP/1.1\r\nHost: '+target.hostname+':'+str(port)+
                                '\r\nContent-Type: '+mime+'\r\nContent-Length: '+str(len(body.encode()))+
                                '\r\nConnection: close\r\n\r\n'+body).encode())
                            response=http.client.HTTPResponse(connection);response.begin();raw=response.read(262144)
                        (private/('api-'+str(port)+'-'+kind+'.private')).write_bytes(raw)
                        value=json.loads(raw)
                        result.setdefault('apiProbes',[]).append({'port':port,'kind':kind,'status':response.status,
                            'keys':list(value)[:40],'result':value.get('result'),
                            'passwordEncrypt':value.get('passwordEncrypt'),
                            'publicExponent':value.get('publicKeyExponent'),
                            'publicModulusLength':len(value.get('publicKeyModulus','')),
                            'services':len(value.get('service',[]))})
                    except Exception as error:
                        result.setdefault('apiProbes',[]).append({'port':port,'kind':kind,'failure':type(error).__name__})
        result['passed'] = bool(result['pages'])
    except Exception as error:
        result.update(passed=False, failure=type(error).__name__)
        if isinstance(error, RuntimeError) and str(error) in {
                'diagnostic_wifi_address_unavailable', 'wlan_diagnostic_command_failed',
                'invalid_diagnostic_interface', 'wlan_diagnostic_open_failed', 'wlan_diagnostic_tag_failed'}:
            result['reason'] = str(error)
    finally:
        try: command('disconnect', 'interface='+adapter['Name'])
        except Exception: result['disconnectUnconfirmed'] = True
        if created:
            try: command('delete', 'profile', 'name='+name, 'interface='+adapter['Name'])
            except Exception: result['cleanupUnconfirmed'] = True
        try: result['windowsEvents'] = win.wlan_diagnostics(started)
        except Exception: result['windowsEventsUnavailable'] = True
        lab.atomic(run / 'web-discovery.json', result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    main(parser.parse_args().run.resolve(strict=True))
