"""Print only public EAP/cipher parameters from an existing Windows profile."""
import ctypes as C
from ctypes import wintypes as W
import json
import uuid
import xml.etree.ElementTree as ET
from network_lab_windows import GUID, ps_json

def inspect():
    item = ps_json("$a=@(Get-NetAdapter -Physical|Where-Object NdisPhysicalMedium -eq 9);if($a.Count -ne 1){throw 'adapter'};[string]$a[0].InterfaceGuid|ConvertTo-Json -Compress")
    guid = GUID()
    for i, b in enumerate(uuid.UUID(item.strip('{}')).bytes_le):
        guid.data[i] = b
    api = C.WinDLL('wlanapi')
    api.WlanOpenHandle.argtypes = [W.DWORD,C.c_void_p,C.POINTER(W.DWORD),C.POINTER(W.HANDLE)]
    api.WlanGetProfile.argtypes = [W.HANDLE,C.POINTER(GUID),W.LPCWSTR,C.c_void_p,C.POINTER(C.c_void_p),C.POINTER(W.DWORD),C.POINTER(W.DWORD)]
    api.WlanFreeMemory.argtypes = [C.c_void_p]
    api.WlanCloseHandle.argtypes = [W.HANDLE,C.c_void_p]
    handle, version, raw, flags, access = W.HANDLE(), W.DWORD(), C.c_void_p(), W.DWORD(), W.DWORD()
    if api.WlanOpenHandle(2,None,C.byref(version),C.byref(handle)):
        raise RuntimeError('wlan_unavailable')
    try:
        status = api.WlanGetProfile(handle,C.byref(guid),'SCAUNET_1x',None,C.byref(raw),C.byref(flags),C.byref(access))
        if status:
            return dict(error=status)
        text = C.wstring_at(raw)
        if len(text) > 262144:
            raise RuntimeError('profile_size_invalid')
        root = ET.fromstring(text)
        values = []
        safe = {'authentication','encryption','useOneX','authMode','cacheUserData','Type','VendorId','VendorType','AuthorId','DisableUserPromptForServerValidation','FastReconnect','InnerEapOptional','UseWinLogonCredentials','EnableQuarantineChecks','RequireCryptoBinding','PerformServerValidation','AcceptServerName','IdentityPrivacy','AllowPromptingWhenServerCANotFound','enableRandomization','FIPSMode'}
        for e in root.iter():
            tag = e.tag.rsplit('}',1)[-1]
            if tag in safe:
                value = (e.text or '').strip()
                # These are protocol fields; retain only short alphanumeric values.
                if len(value) <= 64 and all(c.isalnum() or c in '-_' for c in value):
                    values.append(dict(field=tag,value=value))
        return dict(protocol=values)
    finally:
        if raw:
            api.WlanFreeMemory(raw)
        api.WlanCloseHandle(handle,None)

if __name__ == '__main__':
    print(json.dumps(inspect(),ensure_ascii=True,indent=2))
