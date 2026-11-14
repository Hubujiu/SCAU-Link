#pragma once
#include <windows.h>
inline int probe_token_elevated() noexcept {
    HANDLE token{};TOKEN_ELEVATION elevation{};DWORD size=sizeof(elevation);
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return -1;
    const bool ok=GetTokenInformation(token,TokenElevation,&elevation,size,&size)!=FALSE;
    CloseHandle(token);return ok?int(elevation.TokenIsElevated):-1;
}
