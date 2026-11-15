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
    const bool offline=std::wstring_view(argv[3])==L"apply-live-offline";
    const bool apply_live=std::wstring_view(argv[3])==L"apply-live"||offline;
    const bool download=std::wstring_view(argv[3])==L"download"||apply_live;
    if(!download&&std::wstring_view(argv[3])!=L"check")return 2;
    if(offline)options.fetch=[](auto,auto,const auto&,const auto&){return unsigned(ERROR_NETWORK_UNREACHABLE);};
    HANDLE token{};TOKEN_ELEVATION elevation{};DWORD bytes{};
    const bool observed=OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)&&
        GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes);
    if(token)CloseHandle(token);
    std::filesystem::create_directories(directory);
    std::ofstream log(directory/L"public-result.json");
    unsigned phase=0,error=0;bool passed=false;
    try {
        Manager manager(std::move(options));
        bool requested=!apply_live;if(requested)manager.check_now();
        const auto start=GetTickCount64(),end=start+240000;
        while(GetTickCount64()<end) {
            const auto state=manager.snapshot();phase=unsigned(state.phase);error=state.error;
            if(!requested&&!offline&&state.phase==Phase::Idle&&GetTickCount64()>start+500){manager.check_now();requested=true;}
            if(state.phase==Phase::Failed)break;
            if(state.phase==Phase::Current){passed=!download;break;}
            if(state.phase==Phase::Available) {
                if(download)manager.download_now();else{passed=true;break;}
            }
            if(state.phase==Phase::Ready){
                if(apply_live) {
                    if(state.impact!=Impact::PreserveConnection){error=ERROR_REVISION_MISMATCH;break;}
                    manager.install_now();
                }else{passed=download;break;}
            }
            if(state.phase==Phase::Applied){passed=apply_live;break;}
            Sleep(100);
        }
    }catch(...){error=ERROR_INVALID_DATA;}
    log<<"{\"passed\":"<<(passed?"true":"false")<<",\"elevationObserved\":"<<(observed?"true":"false")
       <<",\"elevated\":"<<(elevation.TokenIsElevated?"true":"false")<<",\"phase\":"<<phase<<",\"error\":"<<error
       <<",\"downloadRequested\":"<<(download?"true":"false")<<",\"installerExecuted\":false,\"liveApplied\":"<<(apply_live&&passed?"true":"false")<<"}\n";
    log.flush();
    if(apply_live&&passed) {
        // Test-only probe stays mapped until its ordinary-user controller confirms
        // the original process and mapped core both survived the replacement.
        const auto end=GetTickCount64()+30000;
        while(GetTickCount64()<end&&!std::filesystem::exists(directory/L"release-probe.ok"))Sleep(100);
    }
    return passed?0:1;
}
