#include "updates.hpp"
#include <shellapi.h>
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    int argc{};auto** argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    const int result=argv?scau::desktop::updates::apply_update(argc,argv):ERROR_INVALID_PARAMETER;
    if(argv)LocalFree(argv);
    return result;
}
