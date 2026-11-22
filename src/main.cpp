#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wincred.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <powrprof.h>
#include <bcrypt.h>
#include <roapi.h>
#include "protocol.hpp"
#include "profile_store.hpp"
#include "observation.hpp"
#include "maintenance.hpp"
#include "recovery.hpp"
#include "failure.hpp"
#include "auth_result.hpp"
#include "exchange.hpp"
#include "supervisor.hpp"
#include "pcap_capture.hpp"
#include "sam_runtime.hpp"
#include "sam_udp.hpp"
#include "desktop/platform.hpp"
#include "desktop/wireless_session.hpp"
#include "desktop/wlan_8021x.hpp"
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace {
using namespace scau;
using Clock=std::chrono::steady_clock;
std::atomic<bool> interrupted=false;
BOOL WINAPI console_signal(DWORD) { interrupted=true; return TRUE; }
std::string escape(std::string_view value) {
    std::string result;
    for(const unsigned char ch:value) {
        if(ch=='"' || ch=='\\') {result+='\\';result+=char(ch);}
        else if(ch=='\n')result+="\\n";
        else if(ch>=32)result+=char(ch);
    }
    return result;
}
std::string timestamp() {
    SYSTEMTIME time{};GetSystemTime(&time);char text[40]{};
    sprintf_s(text,"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",time.wYear,time.wMonth,time.wDay,time.wHour,time.wMinute,time.wSecond,time.wMilliseconds);
    return text;
}
struct Logger {
    std::ofstream file;std::mutex lock;
    explicit Logger(const std::filesystem::path& path) {if(!path.empty()){file.open(path,std::ios::app);if(!file)throw std::runtime_error("Cannot open event log");}}
    void event(std::string_view name,std::string_view detail={},long long value=-1) {
        std::lock_guard guard(lock);
        std::ostringstream output;output<<"{\"time\":\""<<timestamp()<<"\",\"event\":\""<<escape(name)<<'"';
        if(!detail.empty())output<<",\"detail\":\""<<escape(detail)<<'"';
        if(value>=0)output<<",\"value\":"<<value;
        output<<"}\n";std::cout<<output.str()<<std::flush;
        if(file)file<<output.str()<<std::flush;
    }
};
struct Handle {
    HANDLE value=nullptr;
    ~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
};
using Credentials=SessionCredentials;
// The callback only records events. The single authentication loop owns all
// driver handles, protocol state and transmissions, including after resume.
class PowerNotifications {
    std::atomic<unsigned> pending_{};
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS parameters_{};
    HPOWERNOTIFY registration_{};
    static ULONG CALLBACK changed(void* context,ULONG type,void*) {
        auto& pending=static_cast<PowerNotifications*>(context)->pending_;
        if(type==PBT_APMSUSPEND)pending.fetch_or(1);
        else if(type==PBT_APMRESUMESUSPEND || type==PBT_APMRESUMEAUTOMATIC)pending.fetch_or(2);
        return ERROR_SUCCESS;
    }
public:
    PowerNotifications() {
        parameters_.Callback=changed;parameters_.Context=this;
        if(PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK,&parameters_,&registration_)!=ERROR_SUCCESS)
            throw std::runtime_error("Cannot register Windows suspend/resume notifications");
    }
    ~PowerNotifications(){if(registration_)PowerUnregisterSuspendResumeNotification(registration_);}
    PowerNotifications(const PowerNotifications&)=delete;
    PowerNotifications& operator=(const PowerNotifications&)=delete;
    unsigned take(){return pending_.exchange(0);}
};
std::string narrow(const wchar_t* text) {
    const int size=WideCharToMultiByte(936,WC_NO_BEST_FIT_CHARS,text,-1,nullptr,0,nullptr,nullptr);
    if(size<=0)throw std::runtime_error("Cannot encode credentials");
    std::string result(size,'\0');BOOL replaced=FALSE;
    WideCharToMultiByte(936,WC_NO_BEST_FIT_CHARS,text,-1,result.data(),size,nullptr,&replaced);
    if(replaced)throw std::runtime_error("Credential characters cannot be encoded as GBK");
    result.pop_back();return result;
}
void prompt(Credentials& credentials,std::string_view username) {
    wchar_t user[CREDUI_MAX_USERNAME_LENGTH+1]{},password[CREDUI_MAX_PASSWORD_LENGTH+1]{};
    struct WipePassword {wchar_t* data;std::size_t bytes;~WipePassword(){SecureZeroMemory(data,bytes);}} wipe{password,sizeof(password)};
    MultiByteToWideChar(936,0,username.data(),int(username.size()),user,CREDUI_MAX_USERNAME_LENGTH);
    CREDUI_INFOW info{sizeof(info)};
    info.pszCaptionText=L"SCAU 原生认证";
    info.pszMessageText=L"请输入校园网账号与密码。凭据仅保留在本次会话内存中，核心异常退出后会自动重连；关闭会话后清除，不保存到磁盘。";
    BOOL save=FALSE;
    const auto status=CredUIPromptForCredentialsW(&info,L"SCAU native authentication",nullptr,0,
        user,DWORD(std::size(user)),password,DWORD(std::size(password)),&save,
        CREDUI_FLAGS_GENERIC_CREDENTIALS|CREDUI_FLAGS_ALWAYS_SHOW_UI|CREDUI_FLAGS_DO_NOT_PERSIST|CREDUI_FLAGS_EXCLUDE_CERTIFICATES);
    if(status!=NO_ERROR){SecureZeroMemory(password,sizeof(password));throw std::runtime_error(status==ERROR_CANCELLED?"Credential entry cancelled":"Windows credential prompt failed");}
    credentials.username=narrow(user);credentials.password=narrow(password);SecureZeroMemory(password,sizeof(password));
    if(credentials.username.empty() || credentials.username.size()>256 || credentials.password.empty() || credentials.password.size()>256)throw std::runtime_error("Invalid credential length");
}
struct Adapter {
    std::string name;Mac mac{};ULONG index{};Profile profile;
    NET_LUID luid{};
    bool link_up=false,ipv4_ready=false;
};
std::optional<Adapter> inspect_adapter(Profile profile) {
    ULONG length=16384;Bytes buffer(length);
    auto status=GetAdaptersAddresses(AF_INET,GAA_FLAG_INCLUDE_GATEWAYS,nullptr,reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()),&length);
    if(status==ERROR_BUFFER_OVERFLOW){buffer.resize(length);status=GetAdaptersAddresses(AF_INET,GAA_FLAG_INCLUDE_GATEWAYS,nullptr,reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()),&length);}
    if(status!=NO_ERROR)throw std::runtime_error("Cannot enumerate network adapters");
    for(auto* adapter=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());adapter;adapter=adapter->Next) {
        if(adapter->PhysicalAddressLength!=6 || !std::equal(profile.local.begin(),profile.local.end(),adapter->PhysicalAddress))continue;
        if(adapter->IfType!=IF_TYPE_ETHERNET_CSMACD)continue;
        MIB_IF_ROW2 row{};row.InterfaceLuid=adapter->Luid;
        if(GetIfEntry2(&row)!=NO_ERROR)throw std::runtime_error("Cannot inspect the selected physical adapter");
        if(!row.InterfaceAndOperStatusFlags.HardwareInterface)continue;
        Adapter output;output.name=adapter->AdapterName;output.mac=profile.local;output.index=adapter->IfIndex;output.luid=adapter->Luid;output.profile=profile;
        output.link_up=adapter->OperStatus==IfOperStatusUp;
        // Refresh only the selected physical adapter. A new index after device
        // re-enumeration must never make us choose the system's VPN/TUN route.
        std::fill(output.profile.network.begin()+5,output.profile.network.begin()+21,Byte{0});
        for(auto* unicast=adapter->FirstUnicastAddress;unicast;unicast=unicast->Next) {
            if(unicast->Address.lpSockaddr->sa_family!=AF_INET || unicast->DadState==IpDadStateTentative || unicast->DadState==IpDadStateDuplicate)continue;
            const auto* address=reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
            if(!address->sin_addr.s_addr)continue;
            std::memcpy(output.profile.network.data()+5,&address->sin_addr,4);
            const auto prefix=unicast->OnLinkPrefixLength;
            if(prefix>32)throw std::runtime_error("Invalid IPv4 prefix on the selected adapter");
            const auto mask=htonl(prefix?0xffffffffu<<(32-prefix):0);
            std::memcpy(output.profile.network.data()+9,&mask,4);output.ipv4_ready=true;break;
        }
        if(adapter->FirstGatewayAddress && adapter->FirstGatewayAddress->Address.lpSockaddr->sa_family==AF_INET) {
            const auto* gateway=reinterpret_cast<sockaddr_in*>(adapter->FirstGatewayAddress->Address.lpSockaddr);std::memcpy(output.profile.network.data()+13,&gateway->sin_addr,4);
        }
        if(adapter->FirstDnsServerAddress && adapter->FirstDnsServerAddress->Address.lpSockaddr->sa_family==AF_INET) {
            const auto* dns=reinterpret_cast<sockaddr_in*>(adapter->FirstDnsServerAddress->Address.lpSockaddr);std::memcpy(output.profile.network.data()+17,&dns->sin_addr,4);
        }
        const auto checksum=crc16(std::span(output.profile.network).first(21));output.profile.network[21]=Byte(checksum>>8);output.profile.network[22]=Byte(checksum);
        return output;
    }
    return std::nullopt;
}
Adapter find_adapter(Profile profile) {
    auto adapter=inspect_adapter(std::move(profile));
    if(!adapter)throw std::runtime_error("The physical adapter in the capture profile was not found");
    if(!adapter->link_up)throw std::runtime_error("The selected Ethernet link is down");
    return std::move(*adapter);
}
bool original_client_running() {
    Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)};
    if(snapshot.value==INVALID_HANDLE_VALUE)return true;
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);
    if(Process32FirstW(snapshot.value,&entry))do{if(_wcsicmp(entry.szExeFile,L"8021x.exe")==0)return true;}while(Process32NextW(snapshot.value,&entry));
    return false;
}
struct PcapHeader {long seconds,microseconds;unsigned captured,original;};
struct BpfProgram {unsigned length;void* instructions;};
struct TransportError:std::runtime_error {using std::runtime_error::runtime_error;};
struct CaptureOpenError:std::runtime_error {
    CaptureOpenError():std::runtime_error("无法打开有线网卡：请检查 Npcap/WinPcap 驱动状态、网卡绑定和访问权限。") {}
};
class Transport {
    HMODULE module=nullptr;void* handle=nullptr;
    using Open=void* (__cdecl*)(const char*,int,int,int,char*);
    using Close=void (__cdecl*)(void*);
    using Send=int (__cdecl*)(void*,const unsigned char*,int);
    using Next=int (__cdecl*)(void*,PcapHeader**,const unsigned char**);
    Close close=nullptr;Send send_packet=nullptr;Next next=nullptr;
    template<class T>T symbol(const char* name) {auto result=reinterpret_cast<T>(GetProcAddress(module,name));if(!result)throw std::runtime_error("Required packet capture API is missing");return result;}
public:
    explicit Transport(const Adapter& adapter) {
        wchar_t system[MAX_PATH]{};GetSystemDirectoryW(system,MAX_PATH);
        auto path=std::filesystem::path(system)/L"Npcap"/L"wpcap.dll";
        if(!std::filesystem::exists(path))path=std::filesystem::path(system)/L"wpcap.dll";
        module=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
        if(!module)throw std::runtime_error("Installed Npcap/WinPcap library is unavailable");
        try {
            auto open=symbol<Open>("pcap_open_live");close=symbol<Close>("pcap_close");send_packet=symbol<Send>("pcap_sendpacket");next=symbol<Next>("pcap_next_ex");
            char error[256]{};const auto device="\\Device\\NPF_"+adapter.name;handle=open(device.c_str(),65535,0,250,error);
            if(!handle)throw CaptureOpenError();
            BpfProgram filter{};
            auto compile=symbol<int (__cdecl*)(void*,BpfProgram*,const char*,int,unsigned)>("pcap_compile");
            auto set=symbol<int (__cdecl*)(void*,BpfProgram*)>("pcap_setfilter");
            auto free_filter=symbol<void (__cdecl*)(BpfProgram*)>("pcap_freecode");
            if(compile(handle,&filter,"ether proto 0x888e or ether proto 0x8100 or ether proto 0x88a8",1,0xffffffff)!=0)throw std::runtime_error("Cannot compile the EAPOL capture filter");
            const auto filter_status=set(handle,&filter);free_filter(&filter);
            if(filter_status!=0)throw std::runtime_error("Cannot install the EAPOL filter");
            if(symbol<int (__cdecl*)(void*,int,char*)>("pcap_setnonblock")(handle,1,error)!=0)throw std::runtime_error("Cannot enable nonblocking capture");
        } catch(...) {if(handle)close(handle);FreeLibrary(module);throw;}
    }
    ~Transport(){if(handle)close(handle);if(module)FreeLibrary(module);}
    Transport(const Transport&)=delete;
    Transport& operator=(const Transport&)=delete;
    void send(std::span<const Byte> frame){if(send_packet(handle,frame.data(),int(frame.size()))!=0)throw TransportError("Raw Ethernet transmission failed");}
    Bytes receive() {
        PcapHeader* header=nullptr;const unsigned char* data=nullptr;const auto status=next(handle,&header,&data);
        if(status<0)throw TransportError("Packet capture failed");
        if(status==0)return {};
        if(header->captured>65535)throw TransportError("Invalid packet length from capture driver");
        if(header->captured<header->original)return {}; // A truncated input cannot terminate the authenticator.
        return Bytes(data,data+header->captured);
    }
};

bool internet_probe() {
    struct Internet {HINTERNET value=nullptr;~Internet(){if(value)WinHttpCloseHandle(value);}};
    Internet session{WinHttpOpen(L"SCAU-Native-Auth/0.3",WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0)};
    if(!session.value)return false;WinHttpSetTimeouts(session.value,3000,3000,3000,3000);
    Internet connection{WinHttpConnect(session.value,L"www.msftconnecttest.com",INTERNET_DEFAULT_HTTP_PORT,0)};
    if(!connection.value)return false;
    Internet request{WinHttpOpenRequest(connection.value,L"GET",L"/connecttest.txt",nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0)};
    if(!request.value)return false;
    DWORD policy=WINHTTP_OPTION_REDIRECT_POLICY_NEVER;WinHttpSetOption(request.value,WINHTTP_OPTION_REDIRECT_POLICY,&policy,sizeof(policy));
    if(!WinHttpSendRequest(request.value,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0) || !WinHttpReceiveResponse(request.value,nullptr))return false;
    DWORD code=0,length=sizeof(code);if(!WinHttpQueryHeaders(request.value,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&code,&length,WINHTTP_NO_HEADER_INDEX) || code!=200)return false;
    char text[128]{};DWORD read=0;if(!WinHttpReadData(request.value,text,127,&read))return false;
    return std::string_view(text,read).find("Microsoft Connect Test")!=std::string_view::npos;
}
struct Options {
    std::filesystem::path profile,log,capture,export_profile,state_directory;
    std::wstring gate,stop;
    unsigned duration=1800;
    bool connect=false,wireless_web=false,wireless_8021x=false;
    std::string wlan_profile_id;
    bool disconnect_after_test=false;
    HANDLE worker_input=nullptr,worker_output=nullptr;
    std::uint64_t recovery_attempt{};
    bool worker() const noexcept {return worker_input || worker_output;}
};
HANDLE inherited_handle(const wchar_t* text) {
    const std::wstring value=text;
    if(value.empty() || value.front()==L'-')throw std::runtime_error("Invalid inherited worker handle");
    std::size_t end{};const auto number=std::stoull(value,&end);
    if(end!=value.size() || !number || number>UINTPTR_MAX || number==UINTPTR_MAX)throw std::runtime_error("Invalid inherited worker handle");
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(number));
}
Options options(int argc,wchar_t** argv) {
    Options output;
    for(int i=1;i<argc;++i) {
        const std::wstring name=argv[i];
        if(name==L"--connect")output.connect=true;
        else if(name==L"--wireless-web")output.wireless_web=true;
        else if(name==L"--wireless-8021x")output.wireless_8021x=true;
        else if(i+1<argc && name==L"--wlan-profile-id") {
            const std::wstring_view id=argv[++i];
            if(id.size()!=32 || !std::all_of(id.begin(),id.end(),[](wchar_t ch){return (ch>=L'0'&&ch<=L'9')||(ch>=L'a'&&ch<=L'f');}))
                throw std::runtime_error("Invalid private WLAN profile identifier");
            for(const auto ch:id)output.wlan_profile_id.push_back(static_cast<char>(ch));
        }
        else if(name==L"--probe")output.connect=false;
        else if(name==L"--disconnect-after-test")output.disconnect_after_test=true;
        else if(i+1<argc && name==L"--profile")output.profile=argv[++i];
        else if(i+1<argc && name==L"--state-directory")output.state_directory=argv[++i];
        else if(i+1<argc && name==L"--export-profile")output.export_profile=argv[++i];
        else if(i+1<argc && name==L"--log")output.log=argv[++i];
        else if(i+1<argc && name==L"--capture")output.capture=argv[++i];
        else if(i+1<argc && name==L"--gate-event")output.gate=argv[++i];
        else if(i+1<argc && name==L"--stop-event")output.stop=argv[++i];
        else if(i+1<argc && name==L"--duration")output.duration=std::stoul(argv[++i]);
        else if(i+1<argc && name==L"--worker-input")output.worker_input=inherited_handle(argv[++i]);
        else if(i+1<argc && name==L"--worker-output")output.worker_output=inherited_handle(argv[++i]);
        else if(i+1<argc && name==L"--recovery-attempt")output.recovery_attempt=std::stoull(argv[++i]);
        else throw std::runtime_error("Usage: scau-auth --profile eapol-only.pcapng [--probe | --connect] [--duration observation-seconds] [--disconnect-after-test] [--log path] [--capture path]");
    }
    if((!output.wireless_web && !output.wireless_8021x && output.profile.empty()) || output.duration<10 || output.duration>86400)throw std::runtime_error("A profile and duration between 10 and 86400 seconds are required");
    if(!output.export_profile.empty() && (output.connect || output.worker()))throw std::runtime_error("Profile export is an offline operation");
    if((output.worker() && (!output.worker_input || !output.worker_output || !output.connect)) || (output.recovery_attempt && !output.worker()))throw std::runtime_error("A worker requires its private inherited channel");
    if((output.wireless_web || output.wireless_8021x) && (!output.connect || !output.worker_input || !output.worker_output ||
        !output.profile.empty() || !output.capture.empty() || !output.export_profile.empty() || output.disconnect_after_test))
        throw std::runtime_error("Wireless authentication requires its private worker channel");
    if((output.wireless_web && output.wireless_8021x) || (output.wireless_8021x != !output.wlan_profile_id.empty()))
        throw std::runtime_error("Wireless modes and their private profile identifiers must match");
    if(!output.state_directory.empty() && (!output.worker() || !output.state_directory.is_absolute() ||
        !std::filesystem::is_directory(output.state_directory)))throw std::runtime_error("Invalid private worker state directory");
    return output;
}

// An event watcher can cancel an outstanding asynchronous WinHTTP operation.
// Its completion event and joined destructor keep the worker's handles private
// and prevent a thread from surviving the routine it observes.
class WorkerStopWatcher {
    Handle finished_;
    std::thread thread_;
public:
    explicit WorkerStopWatcher(HANDLE stop) {
        if(!stop)return;
        finished_.value=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if(!finished_.value)throw std::runtime_error("Cannot create the worker completion event");
        thread_=std::thread([stop,finished=finished_.value]{
            HANDLE events[]{stop,finished};
            const auto result=WaitForMultipleObjects(2,events,FALSE,INFINITE);
            if(result==WAIT_OBJECT_0 || result==WAIT_FAILED)interrupted=true;
        });
    }
    ~WorkerStopWatcher(){if(thread_.joinable()){SetEvent(finished_.value);thread_.join();}}
    WorkerStopWatcher(const WorkerStopWatcher&)=delete;
    WorkerStopWatcher& operator=(const WorkerStopWatcher&)=delete;
};
class RuntimeApartment {
    bool initialized_=false;
public:
    RuntimeApartment(){const auto result=RoInitialize(RO_INIT_MULTITHREADED);if(FAILED(result))throw std::runtime_error("Cannot initialize the wireless worker runtime");initialized_=true;}
    ~RuntimeApartment(){if(initialized_)RoUninitialize();}
};
void decode_worker_gbk(std::string_view input,std::wstring& output) {
    if(input.empty() || input.size()>256 || input.find('\0')!=input.npos)throw std::runtime_error("Invalid private worker credential encoding");
    const auto size=MultiByteToWideChar(936,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),nullptr,0);
    if(size<=0)throw std::runtime_error("Invalid private worker credential encoding");
    output.resize(size);
    if(!MultiByteToWideChar(936,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),output.data(),size))
        throw std::runtime_error("Invalid private worker credential encoding");
}
void wireless_failure_text(std::string& failure) {
    using namespace scau::desktop;
    if(failure==wireless_origin_unconfirmed)failure="请先确认当前无线网络的学校认证页面。";
    else if(failure==wireless_origin_changed)failure="无线认证页面地址已改变，请重新确认后连接。";
    else if(failure==wireless_portal_unsupported)failure="当前无线认证页面的协议尚不支持。";
    else if(failure==wireless_service_ambiguous)failure="学校返回多个认证服务，暂时无法自动选择。";
    else if(failure==wireless_login_uncertain)failure="无线登录结果未确认，已停止自动重发，请检查网络状态。";
    else if(failure=="wireless_auth_rejected")failure="学校服务器拒绝了无线认证，未提供具体原因。";
    else if(failure=="wireless_adapter_missing")failure="未找到可用的无线网卡。";
    else if(failure=="wireless_discovery_failed")failure="未找到学校无线认证页面，请先连接 SCAUNET。";
    else if(failure=="wireless_status_unavailable")failure="无法读取无线认证状态，请稍后重试。";
    else if(failure=="wireless_page_info_failed")failure="无法获取学校无线认证服务。";
    else if(failure=="wireless_runtime_error")failure="无线认证环境异常，请检查网络连接。";
}
int run_wireless_worker(const Options& config,Logger& logger,Credentials& supplied,WorkerChannel& channel,
                        std::string& terminal_failure) {
    if(!channel.ready())throw std::runtime_error("The native supervisor is unavailable");
    Handle stop;
    if(!config.stop.empty()) {
        stop.value=CreateEventW(nullptr,TRUE,FALSE,config.stop.c_str());
        if(!stop.value)throw std::runtime_error("Cannot create the wireless stop event");
    }
    WorkerStopWatcher watcher(stop.value);
    Handle gate;
    if(!config.gate.empty()) {
        gate.value=CreateEventW(nullptr,TRUE,FALSE,config.gate.c_str());
        if(!gate.value)throw std::runtime_error("Cannot create the authentication gate");
        const auto deadline=GetTickCount64()+300000;
        while(WaitForSingleObject(gate.value,50)!=WAIT_OBJECT_0) {
            if(interrupted)return 0;
            if(GetTickCount64()>=deadline)throw std::runtime_error("Timed out waiting for the authentication gate");
        }
    }
    if(interrupted)return 0;
    const auto selected=scau::desktop::current_wireless_network();
    if(!selected.found)throw std::runtime_error("A physical WiFi adapter was not found");
    constexpr wchar_t hex[]=L"0123456789abcdef";
    std::wstring instance_name=L"Local\\ScauWirelessAuth-";
    for(auto byte:selected.mac){instance_name+=hex[byte>>4];instance_name+=hex[byte&15];}
    Handle instance;
    instance.value=CreateMutexW(nullptr,FALSE,instance_name.c_str());
    if(!instance.value || GetLastError()==ERROR_ALREADY_EXISTS)throw std::runtime_error("A wireless worker already owns this adapter");
    RuntimeApartment apartment;
    scau::desktop::Credential credential;
    decode_worker_gbk(supplied.username,credential.username);
    decode_worker_gbk(supplied.password,credential.password);
    supplied.clear();
    scau::desktop::WirelessSessionOptions session_options;
    session_options.directory=config.state_directory.empty()?scau::desktop::data_directory():config.state_directory;
    session_options.cancel=&interrupted;
    session_options.preferred_mac=selected.mac;
    session_options.manage_wifi=true;
    const auto environment=[&]{
        if(original_client_running()) {
            logger.event("authenticator_conflict");
            throw std::runtime_error("Original authenticator active during wireless worker session");
        }
    };
    session_options.environment_ready=environment;
    session_options.network_provider=[&](const Mac& preferred){
        environment(); // Rechecked before submission and during link monitoring.
        return scau::desktop::current_wireless_network(preferred);
    };
    scau::desktop::WirelessCallbacks callbacks;
    callbacks.online=[&]{if(!channel.authenticated())throw std::runtime_error("The native supervisor is unavailable");};
    callbacks.network_available=[&]{if(!channel.network_available())throw std::runtime_error("The native supervisor is unavailable");};
    callbacks.recovering=[&]{if(!channel.unauthenticated())throw std::runtime_error("The native supervisor is unavailable");};
    callbacks.event=[&](std::string_view name){logger.event(name);};
    logger.event("wireless_preflight_ok");
    int result=0;
    if(config.wireless_8021x) {
        scau::desktop::Wlan8021xOptions wlan_options;
        wlan_options.profile_id=config.wlan_profile_id;wlan_options.cancel=&interrupted;
        wlan_options.preferred_mac=selected.mac;wlan_options.environment_ready=environment;
        result=scau::desktop::run_wlan_8021x_session(credential,wlan_options,callbacks,&terminal_failure);
    } else result=scau::desktop::run_wireless_session(credential,session_options,callbacks,&terminal_failure);
    wireless_failure_text(terminal_failure);
    logger.event("wireless_terminal",{},result);
    return result;
}
// Recognize the selected interface's inbound EAPOL before the strict parser,
// so the diagnostic capture also retains private types and malformed frames.
bool selected_eapol(std::span<const Byte> packet,const Mac& local) {
    if(packet.size()<18 || std::equal(local.begin(),local.end(),packet.begin()+6))return false;
    const Mac pae{1,0x80,0xc2,0,0,3};
    if(!std::equal(local.begin(),local.end(),packet.begin()) && !std::equal(pae.begin(),pae.end(),packet.begin()))return false;
    std::size_t offset=12;
    auto word=[&](std::size_t at){return (unsigned(packet[at])<<8)|packet[at+1];};
    auto type=word(offset);
    while(type==0x8100 || type==0x88a8 || type==0x9100) {
        offset+=4;if(offset+2>packet.size())return false;type=word(offset);
    }
    return type==0x888e && offset+6<=packet.size();
}
int run(const Options& config,Logger& logger,Credentials* supplied=nullptr,WorkerChannel* channel=nullptr,
        std::string* terminal_failure=nullptr) {
    if(terminal_failure)terminal_failure->clear();
    const auto base_profile=load_profile(config.profile);
    auto adapter=find_adapter(base_profile);
    auto transport=std::make_unique<Transport>(adapter);
    auto transport_adapter_name=adapter.name;
    auto transport_adapter_index=adapter.index;
    PowerNotifications power;
    logger.event("preflight_ok","Native C++ 0.3.0; installed capture driver; SAM and worker supervision");
    if(!config.connect)return 0;
    Handle instance;
    const auto name=L"Local\\ScauNativeAuth-"+std::wstring(adapter.name.begin(),adapter.name.end());
    instance.value=CreateMutexW(nullptr,FALSE,name.c_str());
    if(!instance.value || GetLastError()==ERROR_ALREADY_EXISTS)throw std::runtime_error("A native authenticator already owns this adapter");
    Credentials local_credentials;
    auto& credentials=supplied?*supplied:local_credentials;
    if(!supplied)prompt(credentials,adapter.profile.username);
    Handle stop;
    if(!config.stop.empty()){stop.value=CreateEventW(nullptr,TRUE,FALSE,config.stop.c_str());if(!stop.value)throw std::runtime_error("Cannot create the stop event");}
    auto stopped=[&]{return interrupted || (stop.value && WaitForSingleObject(stop.value,0)==WAIT_OBJECT_0);};
    Handle gate;
    if(!config.gate.empty()) {gate.value=CreateEventW(nullptr,TRUE,FALSE,config.gate.c_str());if(!gate.value)throw std::runtime_error("Cannot create the authentication gate");}
    if(stopped())return 2;
    logger.event("credentials_ready");
    if(channel && !channel->ready())throw std::runtime_error("The native supervisor is unavailable");
    if(gate.value) {
        const auto deadline=GetTickCount64()+300000;
        while(WaitForSingleObject(gate.value,50)!=WAIT_OBJECT_0) {
            if(stopped())return 2;
            if(GetTickCount64()>=deadline)throw std::runtime_error("Timed out waiting for the original client to close");
        }
    }
    if(stopped())return 2;
    const auto original_deadline=Clock::now()+std::chrono::seconds(15);
    while(original_client_running() && Clock::now()<original_deadline){if(stopped())return 2;Sleep(100);}
    if(original_client_running())throw std::runtime_error("Close the original 8021x.exe before starting independent authentication");
    Capture capture(config.capture,config.recovery_attempt!=0);
    if(capture.recovered_bytes())logger.event("capture_tail_recovered",{},static_cast<long long>(capture.recovered_bytes()));
    bool sam_termination_confirmed=false;
    auto send=[&](const Bytes& packet,bool disconnect=false){
        if(!disconnect && (stopped() || sam_termination_confirmed))return false;
        if(!transport)throw TransportError("The selected transport is closed");
        transport->send(packet);capture.packet(packet);return true;
    };
    // This cleanup belongs only to an explicit initial connection switch.
    // Retry, observation, probe failure and suspend never send Logoff.
    if(auto cleanup=initial_logoff(adapter.profile,config.recovery_attempt!=0)) {
        if(!send(*cleanup))return 2;Sleep(300);
    }
    if(stopped())return 2;
    for(unsigned i=0;i<512 && !transport->receive().empty();++i){}
    const Mac multicast{1,0x80,0xc2,0,0,3};
    Mac server=adapter.profile.server;
    bool terminal_error=false,logoff_sent=false;
    int terminal_result=scau::auth_rejected;
    bool all_maintenance_supported=true;
    ExchangeTracker exchange;
    MaintenanceParameters maintenance{};
    SamRuntime sam;
    std::unique_ptr<SamUdpTransport> sam_transport;
    SamEndpoint sam_local{},sam_server{};
    SamSeed md5_seed{};bool md5_seed_ready=false;
    std::uint64_t sam_open_at{};
    bool sam_open_failure_reported=false;
    std::optional<std::uint64_t> next_echo;
    std::uint32_t echo_sequence=0;
    std::mt19937 random(std::random_device{}());
    std::uniform_int_distribution<unsigned> jitter(0,19),initial_sequence(0x1001,0x2001);
    RecoveryController controller;
    ObservationWindow observation(config.duration,config.disconnect_after_test);
    std::atomic<bool> online=false;
    std::atomic<unsigned> probes=0,probe_failures=0,probe_epoch=0;
    auto online_since=GetTickCount64(),last_sample=online_since,last_link_poll=online_since,last_conflict_check=online_since;
    auto last_state=RecoveryState::Idle;
    std::jthread probe_thread([&](std::stop_token token){
        while(!token.stop_requested()) {
            if(!online.load()){Sleep(100);continue;}
            const auto epoch=probe_epoch.load();
            const bool success=internet_probe();
            if(!token.stop_requested() && online.load() && epoch==probe_epoch.load()) {
                ++probes;if(!success)++probe_failures;
                logger.event(success?"internet_probe_ok":"internet_probe_failed");
            }
            for(int i=0;i<300 && !token.stop_requested() && epoch==probe_epoch.load();++i)Sleep(100);
        }
    });
    auto clear_maintenance=[&] {
        // A link/resume/driver event can abandon an outstanding SAM ACK. It
        // must never abandon the already verified server's terminal intent.
        if(sam_termination_confirmed && !stopped() && !terminal_error) {
            terminal_result=scau::auth_server_terminated;terminal_error=true;logger.event("sam_termination_ack_interrupted");
        }
        sam.stop();sam_transport.reset();sam_open_at=0;sam_open_failure_reported=false;
        SecureZeroMemory(&maintenance,sizeof(maintenance));next_echo.reset();
    };
    auto clear_exchange=[&] {exchange.reset();clear_maintenance();sam_clear_secret(md5_seed);md5_seed_ready=false;};
    auto sync_state=[&] {
        const bool connected=controller.connected();
        if(connected!=online.load()) {
            online=connected;++probe_epoch;
            if(channel && !(connected?channel->authenticated():channel->unauthenticated()))throw std::runtime_error("The native supervisor is unavailable");
            if(connected){online_since=GetTickCount64();last_sample=online_since;probes=0;probe_failures=0;logger.event("online_observation_started");}
            else if(!observation.reported())logger.event("online_observation_reset");
        }
        if(controller.state()!=last_state) {
            logger.event("connection_state",recovery_state_name(controller.state()),connected?1:0);
            last_state=controller.state();
        }
    };
    auto enact=[&](RecoveryTransition next) {
        while(next) {
            const auto action=*next; next.reset();
            const auto now=GetTickCount64();
            if(terminal_error && action.kind!=RecoveryActionKind::Rejected && action.kind!=RecoveryActionKind::Stopped)break;
            try {
                switch(action.kind) {
                case RecoveryActionKind::BeginExchange: {
                    clear_exchange();
                    if(terminal_error)break;
                    auto selected=inspect_adapter(base_profile);
                    if(!selected || !selected->link_up){transport.reset();next=controller.link_changed(now,false);break;}
                    if(selected->name!=transport_adapter_name || selected->index!=transport_adapter_index){transport.reset();next=controller.transport_error(now);break;}
                    adapter=std::move(*selected);
                    if(!adapter.ipv4_ready)logger.event("network_profile_pending","Authenticating at Ethernet layer with current zero IPv4 fields");
                    if(!send(make_simple(adapter.mac,multicast,1))){next=controller.stop(now);break;}
                    logger.event("start_sent");break;
                }
                case RecoveryActionKind::RetryStart:
                    if(!send(make_simple(adapter.mac,multicast,1))){next=controller.stop(now);break;}
                    logger.event("start_retry",{},controller.start_attempts());break;
                case RecoveryActionKind::ReopenTransport: {
                    clear_exchange();if(terminal_error)break;transport.reset();
                    try {
                        auto selected=inspect_adapter(base_profile);
                        if(!selected || !selected->link_up){next=controller.link_changed(now,false);break;}
                        adapter=std::move(*selected);transport=std::make_unique<Transport>(adapter);
                        transport_adapter_name=adapter.name;transport_adapter_index=adapter.index;
                        logger.event("transport_reopened");next=controller.transport_ready(GetTickCount64());
                    }catch(const std::exception&){logger.event("transport_open_failed");next=controller.transport_error(GetTickCount64());}
                    break;
                }
                case RecoveryActionKind::Connected:
                    if(terminal_failure)terminal_failure->clear();
                    logger.event(controller.successful_exchanges()==1?"authentication_success":"reauthentication_success");break;
                case RecoveryActionKind::Rejected:
                    terminal_error=true;clear_exchange();logger.event("authentication_stopped",recovery_reason_name(action.reason));break;
                case RecoveryActionKind::Waiting:
                    if(!controller.connected()) {
                        if(controller.state()==RecoveryState::TransientBackoff){exchange.expire_pending();clear_maintenance();}
                        else clear_exchange();
                    }
                    logger.event("recovery_wait",recovery_reason_name(action.reason),action.deadline_ms?static_cast<long long>(*action.deadline_ms>now?*action.deadline_ms-now:0):-1);break;
                case RecoveryActionKind::Stopped:
                    clear_exchange();
                    if(transport && adapter.link_up && !logoff_sent && unicast_mac(server)) {
                        send(make_simple(adapter.mac,server,2),true);logoff_sent=true;logger.event("logoff_sent");
                    }
                    break;
                }
            }catch(const TransportError&) {
                transport.reset();clear_exchange();logger.event("transport_lost");next=controller.transport_error(GetTickCount64());
            }
        }
        sync_state();
    };
    auto sam_time=[] {
        const auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        return SamTime{GetTickCount64(),static_cast<std::uint64_t>(seconds)};
    };
    SamRuntime::Sender sam_send=[&](const SamDatagram& packet) {
        if(stopped())return SamSendResult::cancelled;
        if(!sam_transport)return SamSendResult::would_block;
        try{return sam_transport->send(packet)?SamSendResult::sent:SamSendResult::would_block;}
        catch(const SamSocketError&) {
            sam_transport.reset();sam_open_at=GetTickCount64()+2000;
            all_maintenance_supported=false;logger.event("sam_transport_lost");
            return SamSendResult::would_block;
        }
    };
    auto sam_result=[&](const SamRuntimeOutput& output) {
        if(output.server_termination || (sam.configured() && !sam.active())){sam_termination_confirmed=true;terminal_result=scau::auth_server_terminated;}
        for(const auto& notice:output.notices) {
            const char* event=nullptr;
            switch(notice.kind) {
            case SamRuntimeNoticeKind::server_message:event="sam_verified_server_message";break;
            case SamRuntimeNoticeKind::server_termination:event="sam_server_termination_received";break;
            case SamRuntimeNoticeKind::send_confirmed:event="sam_send_confirmed";break;
            case SamRuntimeNoticeKind::send_failed:event="sam_send_failed";all_maintenance_supported=false;break;
            case SamRuntimeNoticeKind::packet_expired:event="sam_packet_expired";all_maintenance_supported=false;break;
            case SamRuntimeNoticeKind::queue_full:event="sam_queue_full";all_maintenance_supported=false;break;
            }
            if(event)logger.event(event,{},notice.command);
        }
        // The runtime flushes the authenticated ACK before returning this
        // terminal event; an unavailable UDP port can defer it for at most 5 s.
        if(output.server_termination){logger.event("sam_server_termination");enact(controller.server_terminated(GetTickCount64()));}
        else if(output.cancelled)enact(controller.stop(GetTickCount64()));
    };
    if(stopped())return 2;
    enact(controller.start(GetTickCount64(),true));
    while(!terminal_error && !controller.stopped()) {
        auto now=GetTickCount64();
        if(interrupted || (stop.value && WaitForSingleObject(stop.value,0)==WAIT_OBJECT_0)) {
            logger.event("disconnect_requested");enact(controller.stop(now));break;
        }
        const auto power_events=power.take();
        if(power_events&1){logger.event("system_suspended");transport.reset();enact(controller.suspend(now));}
        if(power_events&2){logger.event("system_resumed");enact(controller.resume(now));}
        if(terminal_error){enact(controller.server_terminated(GetTickCount64()));break;}
        if(now-last_link_poll>=1000) {
            try {
                auto selected=inspect_adapter(base_profile);
                const bool up=selected && selected->link_up;
                if(up!=controller.link_up()) {
                    logger.event(up?"link_up":"link_down");
                    transport.reset();enact(controller.link_changed(now,up));
                }else if(up && transport && (selected->name!=transport_adapter_name || selected->index!=transport_adapter_index ||
                    (controller.connected() && !std::equal(selected->profile.network.begin()+5,selected->profile.network.begin()+9,adapter.profile.network.begin()+5)))) {
                    // A device can disappear and reappear between polls. Keep
                    // the open handle's identity separate from current metadata.
                    logger.event("adapter_or_ipv4_changed");transport.reset();clear_exchange();
                    enact(controller.transport_error(now));
                }
                if(selected)adapter=std::move(*selected);
            }catch(const std::exception&){logger.event("adapter_query_failed");}
            last_link_poll=now;
        }
        if(terminal_error){enact(controller.server_terminated(GetTickCount64()));break;}
        if(now-last_conflict_check>=5000) {
            if(original_client_running()){logger.event("authenticator_conflict","Original client appeared; native transmissions stopped");terminal_result=scau::auth_environment_error;terminal_error=true;break;}
            last_conflict_check=now;
        }
        if(sam.configured()) {
            if(!sam_transport && now>=sam_open_at) {
                try {
                    sam_transport=std::make_unique<SamUdpTransport>(sam_local,sam_server,adapter.index);
                    sam_open_failure_reported=false;logger.event("sam_transport_ready");
                }catch(const SamSocketError&) {
                    sam_open_at=now+2000;
                    if(!sam_open_failure_reported){logger.event("sam_transport_pending","Bound UDP port or physical route unavailable");sam_open_failure_reported=true;}
                }
            }
            sam_result(sam.poll(sam_time(),sam_send));
            if(sam_transport && sam.configured()) {
                try {
                    for(unsigned count=0;count<32 && sam_transport && sam.configured();++count) {
                        auto datagram=sam_transport->receive();if(!datagram)break;
                        sam_result(sam.receive(*datagram,sam_time(),sam_send));
                    }
                }catch(const SamSocketError&) {
                    sam_transport.reset();sam_open_at=GetTickCount64()+2000;
                    all_maintenance_supported=false;logger.event("sam_transport_lost");
                }
            }
        }
        const bool sam_terminating=sam.configured() && !sam.active();
        if(!sam_terminating)enact(controller.tick(GetTickCount64(),jitter(random)));
        if(terminal_error || controller.stopped())break;
        if(controller.connected()) {
            const auto decision=controller.reauth_pending()?ObservationDecision{}:observation.advance(std::chrono::seconds((now-online_since)/1000));
            if(decision.report_result) {
                if(sam.configured() && !sam_transport)all_maintenance_supported=false;
                logger.event("online_test_completed",{},config.duration);
                logger.event("probe_count",{},probes.load());logger.event("probe_failure_count",{},probe_failures.load());
                logger.event("reauthentication_count",{},static_cast<long long>(controller.successful_exchanges()-1));
                logger.event("maintenance_supported",{},all_maintenance_supported?1:0);
                if(decision.disconnect){logger.event("disconnect_after_test_requested");enact(controller.stop(now));break;}
                logger.event("online_test_holding_connection");
            }
            if(now-last_sample>=10000){logger.event("online_sample",{},(now-online_since)/1000);last_sample=now;}
        }
        if(transport && controller.connected() && !controller.reauth_pending() && !sam_terminating && next_echo && now>=*next_echo) {
            try {
                ++echo_sequence;
                if(!send(make_echo(adapter.mac,server,maintenance.echo_key,echo_sequence))){enact(controller.stop(now));continue;}
                logger.event("legacy_echo_sent");
                next_echo=now+std::uint64_t(maintenance.echo_interval_seconds)*1000;
            }catch(const TransportError&){transport.reset();clear_exchange();logger.event("transport_lost");enact(controller.transport_error(now));}
        }
        if(!transport){Sleep(25);continue;}
        try {
            auto packet=transport->receive();
            if(packet.empty()){Sleep(25);continue;}
            if(!selected_eapol(packet,adapter.mac))continue;
            capture.packet(packet);
            if(sam_terminating)continue;
            Frame frame;try{frame=parse_frame(packet);}catch(const std::runtime_error&){logger.event("invalid_eapol_ignored");continue;}
            if(frame.type!=0 || (frame.source[0]&1))continue;
            const auto state=controller.state();
            if(state==RecoveryState::TransientBackoff) {
                if(exchange.accepts_failure(frame,false) && failure_reason(frame.eap)!=FailureReason::empty) {
                    if(terminal_failure)*terminal_failure=failure_message(frame.eap,credentials.username,credentials.password);
                    terminal_result=failure_reason(frame.eap)==FailureReason::present?scau::auth_rejected:scau::auth_protocol_unsupported;
                    logger.event("late_server_rejection");enact(controller.failure(now,true));
                }
                continue;
            }
            if(state!=RecoveryState::Connecting && state!=RecoveryState::Authenticating && state!=RecoveryState::Connected && state!=RecoveryState::NoServerWait)continue;
            if(!exchange.accepts_peer(frame))continue;
            if(frame.code==1) {
                if(frame.method!=1 && frame.method!=4){terminal_result=scau::auth_protocol_unsupported;logger.event("unsupported_eap_method",{},frame.method);enact(controller.failure(now,true));continue;}
                const bool duplicate=exchange.duplicate_request(frame);
                if(controller.state()==RecoveryState::Connected){clear_maintenance();sam_clear_secret(md5_seed);md5_seed_ready=false;}
                enact(controller.request(now,frame.method==4));
                if(controller.state()!=RecoveryState::Authenticating)continue;
                server=frame.source;
                const bool phase=frame.method==4;
                if(phase && frame.eap[5]!=16){terminal_result=scau::auth_protocol_unsupported;logger.event("unsupported_md5_challenge");enact(controller.failure(now,true));continue;}
                if(phase){md5_seed=sam_seed_for_wired_md5(frame.eap.subspan(6,16));md5_seed_ready=true;}
                if(duplicate) {
                    if(!send(exchange.cached_response())){enact(controller.stop(now));continue;}
                    exchange.repeated_request_answered(frame);
                    logger.event("duplicate_request_answered");continue;
                }
                const auto seed=phase?frame.eap.subspan(6,16):std::span<const Byte>{};
                auto response=make_response(adapter.profile,server,frame.identifier,credentials.username,credentials.password,seed,phase);
                if(!send(response)){enact(controller.stop(now));continue;}
                exchange.record_response(frame,std::move(response));
                logger.event(phase?"md5_response_sent":"identity_response_sent",{},frame.identifier);
            }else if(frame.code==3 && exchange.accepts_success(frame)) {
                clear_maintenance();
                try{maintenance=parse_success_maintenance(packet);}catch(const std::runtime_error&){
                    terminal_result=scau::auth_protocol_unsupported;logger.event("invalid_maintenance_parameters");enact(controller.failure(now,true));continue;
                }
                const bool supported=maintenance.echo_capability()!=MaintenanceCapability::unsupported && maintenance.sam_capability()!=MaintenanceCapability::unsupported;
                all_maintenance_supported=all_maintenance_supported && supported;
                if(!supported)logger.event("unsupported_maintenance","Invalid or incomplete negotiated maintenance parameters");
                logger.event("server_reauth_interval_seconds",{},maintenance.reauth_interval_seconds);
                logger.event("legacy_echo_negotiated",{},maintenance.echo_enabled?1:0);
                logger.event("sam_hello_interval_seconds",{},maintenance.sam_hello_interval_seconds);
                enact(controller.success(now,std::uint64_t(maintenance.reauth_interval_seconds)*1000));
                exchange.completed();
                if(controller.connected() && maintenance.echo_capability()==MaintenanceCapability::supported) {
                    echo_sequence=initial_sequence(random);next_echo=now;
                }
                if(controller.connected() && maintenance.sam_capability()==MaintenanceCapability::supported) {
                    SamConfig parameters;
                    struct WipeSamConfig {SamConfig& p;~WipeSamConfig(){sam_clear_secret(p.key);sam_clear_secret(p.iv);sam_clear_secret(p.integrity_seed);sam_clear_secret({reinterpret_cast<Byte*>(p.username.data()),p.username.size()});}} wipe{parameters};
                    std::copy_n(adapter.profile.network.begin()+5,4,parameters.local.address.begin());
                    parameters.local.port=static_cast<std::uint16_t>(maintenance.sam_client_port);
                    parameters.server={maintenance.sam_server_ipv4,static_cast<std::uint16_t>(maintenance.sam_server_port)};
                    parameters.local_mac=adapter.mac;parameters.username=credentials.username;
                    parameters.key=maintenance.sam_key;parameters.iv=maintenance.sam_iv;
                    parameters.version=std::min<Byte>(maintenance.direct_communication_version,2);
                    parameters.server_utc=maintenance.sam_server_utc;
                    parameters.hello_interval_seconds=maintenance.sam_hello_interval_seconds;
                    parameters.append_integrity_attribute=maintenance.direct_heartbeat_flags==1;
                    parameters.integrity_seed=md5_seed;
                    if(!adapter.ipv4_ready || parameters.username.size()>255 || (parameters.append_integrity_attribute && !md5_seed_ready)) {
                        all_maintenance_supported=false;logger.event("sam_configuration_unavailable");
                    }else {
                        sam.configure(parameters,sam_time());sam_local=parameters.local;sam_server=parameters.server;sam_open_at=0;
                        logger.event("sam_channel_configured",{},parameters.version);
                    }
                }
            }else if(frame.code==4 && exchange.accepts_failure(frame,controller.connected())) {
                const auto reason=failure_reason(frame.eap);
                if(terminal_failure)*terminal_failure=failure_message(frame.eap,credentials.username,credentials.password);
                terminal_result=reason==FailureReason::unrecognized||reason==FailureReason::malformed?scau::auth_protocol_unsupported:scau::auth_rejected;
                logger.event(reason==FailureReason::empty?"server_failure_empty_reason":reason==FailureReason::present?"server_failure_with_reason":"server_failure_unrecognized");
                enact(controller.failure(now,reason!=FailureReason::empty));
            }
        }catch(const TransportError&){transport.reset();clear_exchange();logger.event("transport_lost");enact(controller.transport_error(GetTickCount64()));}
    }
    online=false;probe_thread.request_stop();probe_thread.join();clear_exchange();
    if(terminal_error)return terminal_result;
    if(!observation.reported()){logger.event("online_test_cancelled");return 2;}
    return probes>0 && probe_failures==0 && all_maintenance_supported?0:3;
}
}
int wmain(int argc,wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);SetConsoleCtrlHandler(console_signal,TRUE);
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    std::unique_ptr<Logger> logger;
    std::unique_ptr<scau::WorkerChannel> channel;
    try {
        const auto config=options(argc,argv);
        if(!config.export_profile.empty()){scau::save_native_profile(config.export_profile,scau::load_profile(config.profile));std::cout<<"Native profile exported without credentials or captured exchanges.\n";return 0;}
        auto log_path=config.log;
        if(config.connect && !config.worker() && !log_path.empty())log_path+=L".supervisor.jsonl";
        if(config.worker()) {
            channel=std::make_unique<scau::WorkerChannel>(config.worker_input,config.worker_output);
            scau::SessionCredentials credentials;
            if(!channel->read_credentials(credentials))throw std::runtime_error("Cannot read the private worker session");
            logger=std::make_unique<Logger>(log_path);
            std::string failure;
            const int result=(config.wireless_web || config.wireless_8021x)?run_wireless_worker(config,*logger,credentials,*channel,failure):
                run(config,*logger,&credentials,channel.get(),&failure);
            const bool show_failure=result==scau::auth_rejected || result==scau::auth_protocol_unsupported ||
                ((config.wireless_web || config.wireless_8021x) && result==scau::auth_environment_error);
            if(!channel->finish(result,show_failure?failure:std::string_view{}))return scau::supervisor_error;
            return result;
        }
        logger=std::make_unique<Logger>(log_path);
        if(!config.connect)return run(config,*logger);
        const auto profile=scau::load_profile(config.profile);
        const auto adapter=find_adapter(profile);
        Handle supervisor_instance;
        const auto instance_name=L"Local\\ScauNativeSessionSupervisor-"+std::wstring(adapter.name.begin(),adapter.name.end());
        supervisor_instance.value=CreateMutexW(nullptr,FALSE,instance_name.c_str());
        if(!supervisor_instance.value || GetLastError()==ERROR_ALREADY_EXISTS)throw std::runtime_error("A native session supervisor already owns this adapter");
        Handle stop_holder;
        if(!config.stop.empty()) {
            stop_holder.value=CreateEventW(nullptr,TRUE,FALSE,config.stop.c_str());
            if(!stop_holder.value)throw std::runtime_error("Cannot retain the session stop control");
        }
        auto session_stopped=[&]{return interrupted || (stop_holder.value && WaitForSingleObject(stop_holder.value,0)==WAIT_OBJECT_0);};
        if(session_stopped())return 0;
        auto preflight=config;preflight.connect=false;run(preflight,*logger);
        Credentials credentials;prompt(credentials,profile.username);
        if(session_stopped())return 0;
        scau::EncryptedSessionSecret secret(credentials.username,credentials.password);credentials.clear();
        // Keep an external switch gate alive across worker crashes. Otherwise
        // its last worker handle could vanish and recreate it unsignalled.
        Handle gate_holder;
        if(!config.gate.empty()) {
            gate_holder.value=CreateEventW(nullptr,TRUE,FALSE,config.gate.c_str());
            if(!gate_holder.value)throw std::runtime_error("Cannot retain the authentication gate");
        }
        std::array<wchar_t,32768> executable{};
        const auto length=GetModuleFileNameW(nullptr,executable.data(),static_cast<DWORD>(executable.size()));
        if(!length || length>=executable.size())throw std::runtime_error("Cannot locate the native worker executable");
        scau::SupervisorConfig supervision;
        supervision.executable=std::filesystem::path(executable.data());supervision.stop_event=config.stop;
        for(int i=1;i<argc;++i)supervision.arguments.emplace_back(argv[i]);
        return scau::supervise_worker(supervision,secret,interrupted,[&](std::string_view event,long long value){logger->event(event,{},value);});
    }catch(const std::exception& error){
        const bool capture_error=dynamic_cast<const CaptureOpenError*>(&error)!=nullptr;
        if(logger)logger->event(capture_error?"capture_adapter_open_failed":"error",error.what());else std::cerr<<error.what()<<'\n';
        // Only a fixed, credential-free diagnostic crosses the private channel.
        if(channel)channel->finish(scau::auth_environment_error,capture_error?error.what():"");
        return channel?scau::auth_environment_error:1;
    }
}
