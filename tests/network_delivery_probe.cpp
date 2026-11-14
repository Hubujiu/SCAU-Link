// Explicit local hardware probe. Not registered with CTest; no production
// account/settings writes. Only availability and numeric errors are recorded.
#include "desktop/accounts.hpp"
#include "desktop/package_query.hpp"
#include "desktop/wlan_8021x.hpp"
#include "desktop/wireless_session.hpp"
#include "desktop/campus_wifi.hpp"
#include "probe_context.hpp"
#include <roapi.h>
#include <fstream>
#include <mutex>
#include <thread>
#include <bcrypt.h>
#include <objbase.h>

using namespace scau::desktop;
int wmain(int argc,wchar_t** argv) {
    if(argc!=4 || std::wstring_view(argv[1])!=L"--live-test")return 2;
    const std::wstring_view mode(argv[2]);
    const bool web=mode==L"--wireless-web" || mode==L"--fresh-wireless-web";
    if(!web && mode!=L"--wireless-8021x" && mode!=L"--package")return 2;
    const auto initialized=RoInitialize(RO_INIT_MULTITHREADED);
    if(FAILED(initialized))return 3;
    const auto trace=std::filesystem::absolute(argv[3]);
    std::ofstream log(trace,std::ios::app);if(!log){RoUninitialize();return 3;}
    std::mutex logging;
    const auto emit=[&](std::string_view event,long long value=0) {
        std::lock_guard lock(logging);
        log<<"{\"event\":\""<<event<<"\",\"value\":"<<value<<"}\n"<<std::flush;
    };
    std::atomic_bool cancel=false,finished=false,usable=false,balance=false;
    emit("probe_elevated",probe_token_elevated());
    std::atomic<ULONGLONG> usable_at=0;
    const auto began=GetTickCount64();
    std::jthread timer([&](std::stop_token stop){
        while(!stop.stop_requested() && !finished) {
            if(GetTickCount64()-began>110000 || (usable_at && GetTickCount64()-usable_at>40000)){cancel=true;break;}
            Sleep(50);
        }
    });
    int result=4;
    try {
        AccountStore source(data_directory());const auto catalog=source.load();Credential saved;
        const auto* first=catalog.first_account();
        if(!first || !source.read(*first,saved))throw std::runtime_error("saved_credential_unavailable");
        const auto fresh=trace.parent_path()/L"first-run";
        const auto prefix=L"SCAULink/DeliveryLab/"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(began);
        AccountStore target(fresh,prefix,prefix+L"/unused-legacy");AccountCatalog seeded;
        const auto id=target.save(seeded,{},saved);saved.clear();
        struct Erase {
            AccountStore& store;AccountCatalog& catalog;std::string id;
            ~Erase(){try{store.remove(catalog,id);}catch(...){}}
        } erase{target,seeded,id};
        // Reopen the new catalog exactly as a subsequent launch would. It has
        // never had connection.scau, wireless.ini or a self-service cookie.
        const auto reopened=target.load();Credential credential;
        if(!reopened.first_account() || !target.read(*reopened.first_account(),credential))
            throw std::runtime_error("fresh_store_read_failed");
        emit("probe_fresh_account_saved",1);
        emit("probe_no_imported_configuration",!std::filesystem::exists(fresh/L"connection.scau") &&
            !std::filesystem::exists(fresh/L"wireless.ini"));
        const auto package=[&] {
            const auto network=current_wireless_network();
            const auto index=mode==L"--package"?0u:network.index;
            PackageDiagnostics diagnostics;
            const auto info=query_package(credential,{},&diagnostics,nullptr,&cancel,{},index);
            emit("probe_package_state",int(info.state));
            emit("probe_package_http",diagnostics.http_status);
            emit("probe_package_transport",diagnostics.transport_error);
            emit("probe_package_balance",info.balance.has_value());
            emit("probe_package_fee",package_fee(info).has_value());
            emit("probe_package_next_charge",info.next_charge.has_value() || estimate_next_charge(info,
                std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now())).has_value());
            balance=info.balance.has_value();
        };
        if(mode==L"--package") {package();result=balance?0:4;}
        else {
            WirelessCallbacks callbacks;
            callbacks.online=[&]{usable=true;usable_at=GetTickCount64();emit("probe_authenticated",1);package();};
            callbacks.network_available=[&]{usable=true;usable_at=GetTickCount64();emit("probe_network_available",1);package();};
            callbacks.recovering=[&]{emit("probe_recovering");};
            callbacks.event=[&](std::string_view name){emit(name);};
            std::string failure;
            if(web) {
                if(mode==L"--fresh-wireless-web") {
                    {auto created=make_scau_web_wifi();}
                    const auto network=current_wireless_network();GUID guid{};
                    for(const auto& adapter:connection_adapters())if(adapter.index==network.index) {
                        if(FAILED(CLSIDFromString(utf8_to_wide(adapter.id).c_str(),&guid)))throw std::runtime_error("bad_adapter");
                    }
                    DWORD version{},reason{},seed{};HANDLE handle{};
                    if(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&seed),sizeof(seed),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0 ||
                       WlanOpenHandle(2,nullptr,&version,&handle))throw std::runtime_error("profile_prepare_failed");
                    struct Close {HANDLE value;~Close(){WlanCloseHandle(value,nullptr);}} close{handle};
                    const auto xml=std::wstring(LR"(<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>SCAUNET</name><SSIDConfig><SSID><hex>534341554E4554</hex><name>SCAUNET</name></SSID></SSIDConfig><connectionType>ESS</connectionType><connectionMode>manual</connectionMode><MSM><security><authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM><MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3"><enableRandomization>true</enableRandomization><randomizeEveryday>false</randomizeEveryday><randomizationSeed>)")+
                        std::to_wstring(seed & 0x7fffffff)+L"</randomizationSeed></MacRandomization></WLANProfile>";
                    const auto status=WlanSetProfile(handle,&guid,0,xml.c_str(),nullptr,TRUE,nullptr,&reason);
                    emit("probe_fresh_wifi_profile_status",status);
                    if(status)throw std::runtime_error("fresh_wifi_profile_failed");
                }
                WirelessSessionOptions options;options.directory=fresh;options.cancel=&cancel;options.manage_wifi=true;
                options.transport=[&](const portal::Request& request,const portal::Options& policy) {
                    auto response=portal::send_winhttp(request,policy);
                    emit(request.method=="POST"?"probe_portal_post_http":"probe_portal_get_http",response.status);
                    emit("probe_portal_state",int(response.state));emit("probe_portal_transport",response.error);
                    emit("probe_portal_body_bytes",response.body.size());
                    if(request.method=="POST" && request.url.ends_with("/login")) {
                        std::filesystem::create_directories(trace.parent_path()/L"private");
                        std::ofstream body(trace.parent_path()/L"private/portal-login-response.private",std::ios::binary);
                        body.write(response.body.data(),response.body.size());
                        emit("probe_login_parse_state",int(portal::parse_login(response.body).state));
                    }
                    if(request.method=="POST" && (request.url.find("method=keepalive")!=request.url.npos ||
                        request.url.ends_with("/getOnlineUserInfo"))) {
                        std::filesystem::create_directories(trace.parent_path()/L"private");
                        std::ofstream body(trace.parent_path()/L"private/portal-status-response.private",std::ios::binary);
                        body.write(response.body.data(),response.body.size());
                    }
                    if(request.url=="https://example.com/") {
                        std::filesystem::create_directories(trace.parent_path()/L"private");
                        std::ofstream body(trace.parent_path()/L"private/tls-network-probe.private",std::ios::binary);
                        body.write(response.body.data(),response.body.size());
                    }
                    return response;
                };
                result=run_wireless_session(credential,options,callbacks,&failure);
            } else {
                Wlan8021xOptions options;options.profile_id=new_account_id();options.cancel=&cancel;
                result=run_wlan_8021x_session(credential,options,callbacks,&failure);
            }
            if(!failure.empty()) {
                std::filesystem::create_directories(trace.parent_path()/L"private");
                std::ofstream reason(trace.parent_path()/L"private/failure.private",std::ios::binary);
                reason.write(failure.data(),failure.size());
            }
            emit("probe_terminal",result);
        }
        emit("probe_success",result==0 && (mode==L"--package"?bool(balance):bool(usable)) && balance);
    }catch(...){emit("probe_environment_failed",4);}
    finished=true;timer.request_stop();timer.join();RoUninitialize();
    return result;
}
