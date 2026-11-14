// Opt-in hardware integration: real Backend -> supervisor -> real worker.
// A fresh account catalog is seeded locally; production data stays untouched.
#include "desktop/backend.hpp"
#include "desktop/package_query.hpp"
#include "probe_context.hpp"
#include <roapi.h>
#include <tlhelp32.h>
#include <fstream>

using namespace scau::desktop;
struct Probe {
    HWND window{};std::unique_ptr<Backend> backend;std::ofstream log;
    std::string account;ConnectionMode expected{};
    Status status=Status::Loading;
    unsigned online_count=0;bool balance=false,billing=false,selected=false,failed=false;
    ULONGLONG online_at=0,recovered_at=0;
    scau::Mac first_mac{};
    void emit(std::string_view name,long long value=0) {
        log<<"{\"event\":\""<<name<<"\",\"value\":"<<value<<"}\n"<<std::flush;
    }
    void event(const Event& event) {
        if(event.kind==EventKind::Initialized) {
            emit("probe_initialized",event.credentials && event.profile);
            backend->connect(true);
        } else if(event.kind==EventKind::ModeSelected) {
            selected=event.connection_mode==expected;emit("probe_startup_mode",int(event.connection_mode));
        } else if(event.kind==EventKind::State) {
            const auto previous=status;status=event.status;
            if(status==Status::Error){failed=true;emit("probe_state_error");}
            if(status==Status::Recovering)emit("probe_recovering");
            if(status==Status::Online && previous!=Status::Online) {
                if(!event.network_only && event.account_id!=account){failed=true;emit("probe_wrong_account");}
                ++online_count;online_at=GetTickCount64();
                const auto network=current_wireless_network();
                if(online_count==1)first_mac=network.mac;
                else emit("probe_adapter_identity_preserved",first_mac==network.mac);
                emit(online_count==1?(event.network_only?"probe_network_available":"probe_authenticated"):
                    (event.network_only?"probe_connection_recovered":"probe_reauthenticated"),1);
                if(online_count>1)recovered_at=online_at;
                backend->request_packages(account);
            }
        } else if(event.kind==EventKind::Package && event.account_id==account && event.package.balance) {
            balance=true;emit("probe_package_balance",1);emit("probe_package_fee",package_fee(event.package).has_value());
            const bool next=event.package.next_charge.has_value() || estimate_next_charge(event.package,
                std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now())).has_value();
            emit("probe_package_next_charge",next);billing=package_fee(event.package).has_value() && next;
        }
    }
    static LRESULT CALLBACK proc(HWND window,UINT message,WPARAM w,LPARAM l) {
        auto* self=reinterpret_cast<Probe*>(GetWindowLongPtrW(window,GWLP_USERDATA));
        if(message==WM_NCCREATE){self=static_cast<Probe*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);
            SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self));}
        if(message==backend_message){std::unique_ptr<Event> event(reinterpret_cast<Event*>(l));if(self)self->event(*event);return 0;}
        return DefWindowProcW(window,message,w,l);
    }
    void pump(){MSG m{};while(PeekMessageW(&m,window,0,0,PM_REMOVE))DispatchMessageW(&m);}
    bool crash_own_worker() {
        const auto expected_path=executable_path().parent_path()/L"scau-auth.exe";
        HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(snapshot==INVALID_HANDLE_VALUE)return false;
        PROCESSENTRY32W entry{sizeof(entry)};bool killed=false;
        if(Process32FirstW(snapshot,&entry))do {
            if(entry.th32ParentProcessID!=GetCurrentProcessId() || _wcsicmp(entry.szExeFile,L"scau-auth.exe"))continue;
            HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|PROCESS_TERMINATE,FALSE,entry.th32ProcessID);
            if(!process)continue;
            wchar_t name[32768]{};DWORD length=std::size(name);
            if(QueryFullProcessImageNameW(process,0,name,&length) && !_wcsicmp(name,expected_path.c_str()) &&
                WaitForSingleObject(process,0)==WAIT_TIMEOUT)killed=TerminateProcess(process,0xc0000005)!=FALSE;
            CloseHandle(process);if(killed)break;
        }while(Process32NextW(snapshot,&entry));
        CloseHandle(snapshot);return killed;
    }
};
int wmain(int argc,wchar_t** argv) {
    if(argc!=4 || std::wstring_view(argv[1])!=L"--live-test")return 2;
    const std::wstring_view mode(argv[2]);
    if(mode!=L"--backend-web" && mode!=L"--backend-1x")return 2;
    if(FAILED(RoInitialize(RO_INIT_MULTITHREADED)))return 3;
    Probe probe;probe.log.open(std::filesystem::path(argv[3]),std::ios::app);if(!probe.log){RoUninitialize();return 3;}
    probe.emit("probe_elevated",probe_token_elevated());
    int result=4;
    try {
        const auto fresh=std::filesystem::absolute(argv[3]).parent_path()/L"desktop-first-run";
        AccountStore source(data_directory());const auto original=source.load();Credential credential;
        if(!original.first_account() || !source.read(*original.first_account(),credential))throw std::runtime_error("missing_saved_account");
        AccountStore target(fresh);AccountCatalog catalog;probe.account=target.save(catalog,{},credential);credential.clear();
        struct Erase {AccountStore& store;AccountCatalog& catalog;std::string id;~Erase(){try{store.remove(catalog,id);}catch(...){}}} erase{target,catalog,probe.account};
        probe.emit("probe_fresh_account_saved",1);probe.emit("probe_no_imported_configuration",1);
        Settings settings;settings.mode=ConnectionMode::WirelessWeb;
        probe.expected=mode==L"--backend-web"?ConnectionMode::WirelessWeb:ConnectionMode::Wireless8021x;
        if(mode==L"--backend-1x")settings.startup_modes={ConnectionMode::Wireless8021x,ConnectionMode::WirelessWeb};
        save_settings(fresh,settings);
        WNDCLASSW wc{};wc.hInstance=GetModuleHandleW(nullptr);wc.lpfnWndProc=Probe::proc;wc.lpszClassName=L"ScauLink.NativeBackendProbe";
        RegisterClassW(&wc);probe.window=CreateWindowExW(0,wc.lpszClassName,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,wc.hInstance,&probe);
        if(!probe.window)throw std::runtime_error("probe_window_failed");
        BackendOptions options;options.directory=fresh;
        probe.backend=std::make_unique<Backend>(probe.window,options);probe.backend->initialize();
        const auto deadline=GetTickCount64()+180000;bool crashed=false;ULONGLONG next_package=0;
        while(GetTickCount64()<deadline && !probe.failed) {
            probe.pump();
            if(probe.status==Status::Online && !probe.billing && GetTickCount64()>=next_package) {
                probe.backend->request_packages(probe.account);next_package=GetTickCount64()+3000;
            }
            if(!crashed && probe.online_at && GetTickCount64()-probe.online_at>=8000) {
                crashed=probe.crash_own_worker();if(crashed)probe.emit("probe_crash_injected",1);
            }
            if(probe.recovered_at && probe.balance && probe.billing && GetTickCount64()-probe.recovered_at>=35000) {
                result=probe.selected && crashed?0:4;break;
            }
            Sleep(15);
        }
        probe.backend->disconnect();const auto stopped=GetTickCount64()+12000;
        while(probe.backend->running() && GetTickCount64()<stopped){probe.pump();Sleep(15);}
        if(probe.backend->running())result=4;
        const auto after=load_settings(fresh);
        probe.emit("probe_startup_last_mode_preserved",after.mode==settings.mode && after.startup_modes==settings.startup_modes);
        probe.backend.reset();probe.pump();DestroyWindow(probe.window);
    }catch(...){probe.failed=true;probe.emit("probe_environment_failed",4);probe.backend.reset();}
    probe.emit("probe_terminal",result);probe.emit("probe_success",result==0 && !probe.failed);
    RoUninitialize();return result;
}
