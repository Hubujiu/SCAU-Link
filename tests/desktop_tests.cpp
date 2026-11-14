#include "desktop/platform.hpp"
#include "desktop/spring.hpp"
#include <shellapi.h>
#include <cmath>
#include <iostream>
#include <fstream>
#include <stdexcept>

using namespace scau::desktop;
void require(bool value,const char* why){if(!value)throw std::runtime_error(why);}
int wmain(){try{
    Spring a,b;a.enter(18);b.enter(18);double minimum=0;
    for(int i=0;i<120;++i){a.step(1./60);minimum=std::min(minimum,a.value());}
    for(int i=0;i<240;++i)b.step(1./120);
    require(!a.active()&&!b.active(),"A settled spring must stop scheduling frames");
    require(std::abs(a.value()-b.value())<.001,"Spring must not depend on frame rate");require(minimum<-.2,"Spring must have a damped overshoot");
    a.enter(18);a.step(.04);const auto position=a.value(),velocity=a.velocity();a.move_to(6);
    require(a.value()==position&&a.velocity()==velocity,"Retarget must preserve current position and velocity");
    for(int i=0;i<150;++i)a.step(1./60);require(!a.active()&&std::abs(a.value()-6)<.01,"Interrupted transition must settle to new target");
    a.enter(20);a.snap(0);require(!a.active(),"Reduced motion must have no active spring");
    a.enter(0,240);b.enter(0,240);double previous=0;
    for(int i=0;i<120;++i){a.step_critical(1./60);require(a.value()>=previous&&a.value()<=240,"Scroll spring must not rebound");previous=a.value();}
    for(int i=0;i<240;++i)b.step_critical(1./120);
    require(!a.active()&&!b.active()&&std::abs(a.value()-b.value())<.001,"Scroll spring must settle independently of frame rate");
    auto silent=startup_policy(true,true);require(!silent.show_window&&!silent.notify&&silent.auto_login,"Silent startup must login with no window or notification");
    silent=startup_policy(true,false);require(!silent.show_window&&!silent.notify&&!silent.auto_login,"Missing credentials cannot break silent startup");
    auto normal=startup_policy(false,true);require(normal.show_window&&normal.notify&&normal.auto_login,"Normal startup must auto login");
    wchar_t temp[MAX_PATH]{};GetTempPathW(MAX_PATH,temp);const auto log_dir=std::filesystem::path(temp)/(L"scau-link-log-test-"+std::to_wstring(GetCurrentProcessId()));std::filesystem::create_directories(log_dir);
    struct RemoveLog {std::filesystem::path path;~RemoveLog(){std::error_code e;std::filesystem::remove(path/L"settings.ini",e);std::filesystem::remove(path/L"desktop.jsonl",e);std::filesystem::remove(path,e);}} remove_log{log_dir};
    Settings settings;settings.mode=ConnectionMode::Wireless8021x;
    require(startup_connection_modes(settings)==std::vector<ConnectionMode>{ConnectionMode::Wireless8021x},
        "Unconfigured startup must follow the last user-selected mode");
    settings.startup_modes={ConnectionMode::WirelessWeb,ConnectionMode::Wired,ConnectionMode::Wireless8021x};
    save_settings(log_dir,settings);
    auto loaded=load_settings(log_dir);
    require(loaded.startup_modes==settings.startup_modes && loaded.mode==settings.mode,
        "Ordered startup choices must persist independently of the last connection mode");
    for(auto invalid:{L"0,0",L"0,1,2,0",L"3",L"2,",L"1;2",L"0,,1",L"last,1"})
        require(parse_startup_modes(invalid).empty(),"Malformed startup order must fall back to last selection");
    settings.startup_modes={ConnectionMode::Wired,ConnectionMode::Wired};settings.mini=true;
    bool rejected=false;try{save_settings(log_dir,settings);}catch(const std::invalid_argument&){rejected=true;}
    require(rejected && load_settings(log_dir).startup_modes==loaded.startup_modes && !load_settings(log_dir).mini,
        "Reject an invalid startup plan before changing stored settings");
    settings.startup_modes.clear();settings.mini=false;save_settings(log_dir,settings);
    require(load_settings(log_dir).startup_modes.empty(),"Following the last mode must survive restart");
    {std::ofstream log(log_dir/L"desktop.jsonl");log<<"{\"time\":\"2026-11-12T10:00:00.000Z\",\"event\":\"credentials_saved\",\"password\":\"MUST-NOT-RENDER\"}\n";log<<"{\"time\":\"2026-11-12T10:01:00.000Z\",\"event\":\"worker_authenticated\"}\n";log<<"{\"time\":\"2026-11-12T10:02:00.000Z\",\"event\":\"unknown\",\"detail\":\"MUST-NOT-RENDER\"}\n";}
    const auto rows=read_recent_logs(log_dir);require(rows.size()==2&&rows[0].find(L"连接成功")!=std::wstring::npos,"Recent records must be sorted and translated");for(const auto& row:rows)require(row.find(L"MUST-NOT-RENDER")==std::wstring::npos,"Opaque log payloads must never be rendered");
    const std::filesystem::path exe=L"C:\\Program Files\\SCAU Link\\SCAU-Link.exe";const auto command=startup_command(exe);int argc=0;auto args=CommandLineToArgvW(command.c_str(),&argc);require(args&&argc==2&&args[0]==exe.wstring()&&std::wstring(args[1])==L"--startup","Startup command must survive spaces without shell expansion");LocalFree(args);
    const auto target=L"SCAULink/Tests/"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());CredentialStore store(target);
    struct Cleanup {CredentialStore& store;~Cleanup(){try{store.erase();}catch(...){}}} cleanup{store};
    Credential first;first.username=L"test-only-account";first.password=L"test-only-password";store.write(first);Credential second;require(store.read(second)&&second.username==first.username&&second.password==first.password,"Windows credential round trip must preserve values");store.erase();require(!store.read(second),"Removing test credential must not leave state");
    std::cout<<"PASS: spring continuity/settling, silent startup, startup quoting, isolated Windows credential persistence\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
