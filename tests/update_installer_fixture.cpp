#include <windows.h>
#include <shellapi.h>
#include <filesystem>
#include <fstream>
#include <string_view>
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
    int argc{};auto** argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    std::filesystem::path directory;
    for(int i=1;argv&&i<argc;++i) {
        const std::wstring_view argument(argv[i]);
        if(argument.starts_with(L"/DIR="))directory=std::wstring(argument.substr(5));
    }
    if(argv)LocalFree(argv);
    if(!directory.is_absolute()||!std::filesystem::exists(directory/L"parent-exiting.ok"))return 99;
    std::ofstream(directory/L"installer-ran.ok")<<"parent exited before installer\n";
    return std::filesystem::exists(directory/L"fail-install")?1603:0;
}
