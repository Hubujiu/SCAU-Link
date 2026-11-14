// Explicit local live experiment. Passwords never enter command lines or logs.
#include "desktop/wlan_8021x.hpp"
#include "desktop/accounts.hpp"
#include <atomic>
#include <chrono>
#include <fstream>
#include <mutex>
#include <string_view>
#include <thread>
#include <objbase.h>

int wmain(int argc,wchar_t** argv) {
    if(argc!=4 || std::wstring_view(argv[1])!=L"--live-test" ||
       (std::wstring_view(argv[2])!=L"--current-user" && std::wstring_view(argv[2])!=L"--all-user"))return 2;
    CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    std::ofstream log(std::filesystem::path(argv[3]),std::ios::app);
    if(!log)return 3;
    const auto emit=[&](const char* name,int value=0){log<<"{\"event\":\""<<name<<"\",\"value\":"<<value<<"}\n"<<std::flush;};
    std::atomic_bool cancel=false,online=false,finished=false;
    std::atomic<ULONGLONG> online_at=0;
    const auto started=GetTickCount64();
    std::thread timer([&]{while(!finished && !cancel){
        if(GetTickCount64()-started>65000 || (online_at && GetTickCount64()-online_at>12000)){cancel=true;break;}
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }});
    int result=4;
    try {
        scau::desktop::AccountStore store(scau::desktop::data_directory());
        auto catalog=store.load();
        if(catalog.entries.empty())throw std::runtime_error("no_saved_account");
        scau::desktop::Credential credential;
        if(!store.read(catalog.entries.front(),credential))throw std::runtime_error("credential_unavailable");
        scau::desktop::Wlan8021xOptions options;
        options.profile_id=scau::desktop::new_account_id();options.cancel=&cancel;
        options.stable_profile=false;
        options.per_user_profile=std::wstring_view(argv[2])==L"--current-user";
        options.connect_timeout=std::chrono::seconds(55);
        scau::desktop::WirelessCallbacks callbacks;
        callbacks.online=[&]{online=true;online_at=GetTickCount64();emit("probe_authenticated",1);};
        callbacks.recovering=[&]{emit("probe_recovering");};
        callbacks.event=[&](std::string_view name){log<<"{\"event\":\""<<name<<"\"}\n"<<std::flush;};
        std::string failure;
        emit("probe_started",options.per_user_profile?2:0);
        result=scau::desktop::run_wlan_8021x_session(credential,options,callbacks,&failure);
        // The module emits only fixed local messages and numeric Windows codes.
        log<<"{\"event\":\"probe_reason\",\"fixed_reason\":\""<<failure<<"\"}\n"<<std::flush;
        emit("probe_terminal",result);
        emit("probe_success",online?1:0);
    }catch(...){emit("probe_environment_failed",4);}
    finished=true;timer.join();CoUninitialize();
    return online?0:result?result:4;
}
