#include "desktop/updates.hpp"
#include "release_config.hpp"
#include <fstream>
#include <iostream>
using namespace scau::desktop::updates;
int wmain(int argc,wchar_t** argv) {
    if(argc!=4)return 2;
    const std::filesystem::path directory(argv[1]);
    if(!directory.is_absolute())return 2;
    Options options;options.directory=directory;options.installation=std::filesystem::current_path();
    options.current=argv[2];options.public_key=signing_public_key;
    const bool download=std::wstring_view(argv[3])==L"download";
    if(!download&&std::wstring_view(argv[3])!=L"check")return 2;
    HANDLE token{};TOKEN_ELEVATION elevation{};DWORD bytes{};
    const bool observed=OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)&&
        GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes);
    if(token)CloseHandle(token);
    std::filesystem::create_directories(directory);
    std::ofstream log(directory/L"public-result.json");
    unsigned phase=0,error=0;bool passed=false;
    try {
        Manager manager(std::move(options));manager.check_now();const auto end=GetTickCount64()+240000;
        while(GetTickCount64()<end) {
            const auto state=manager.snapshot();phase=unsigned(state.phase);error=state.error;
            if(state.phase==Phase::Failed)break;
            if(state.phase==Phase::Current){passed=!download;break;}
            if(state.phase==Phase::Available) {
                if(download)manager.download_now();else{passed=true;break;}
            }
            if(state.phase==Phase::Ready){passed=download;break;}
            Sleep(100);
        }
    }catch(...){error=ERROR_INVALID_DATA;}
    log<<"{\"passed\":"<<(passed?"true":"false")<<",\"elevationObserved\":"<<(observed?"true":"false")
       <<",\"elevated\":"<<(elevation.TokenIsElevated?"true":"false")<<",\"phase\":"<<phase<<",\"error\":"<<error
       <<",\"downloadRequested\":"<<(download?"true":"false")<<",\"installerExecuted\":false}\n";
    return passed?0:1;
}
