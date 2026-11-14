#include "desktop/updates.hpp"
#include "update_fixture.hpp"
#include <shellapi.h>
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
    int argc{};auto** argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    const int result=argv?scau::desktop::updates::apply_update(argc,argv,update_fixture_public):ERROR_INVALID_PARAMETER;
    if(argv)LocalFree(argv);return result;
}
