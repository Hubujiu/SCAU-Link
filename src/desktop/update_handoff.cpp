#include "updates.hpp"
#include "release_config.hpp"
#include <bcrypt.h>
#include <objbase.h>
#include <charconv>
#include <fstream>
#include <memory>
#include <vector>

namespace scau::desktop::updates {
namespace {
struct Handle {
    HANDLE value{};
    ~Handle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
};
std::wstring quote(std::wstring_view text) {
    std::wstring out=L"\"";unsigned slashes=0;
    for(wchar_t ch:text) {
        if(ch==L'\\'){++slashes;continue;}
        out.append(slashes*(ch==L'"'?2:1),L'\\');slashes=0;
        if(ch==L'"')out+=L'\\';out+=ch;
    }
    out.append(slashes*2,L'\\');return out+L'"';
}
std::string read(const std::filesystem::path& file,std::size_t limit) {
    const auto size=std::filesystem::file_size(file);if(size>limit)throw ERROR_INVALID_DATA;
    std::ifstream in(file,std::ios::binary);std::string out(static_cast<std::size_t>(size),0);
    if(!in.read(out.data(),static_cast<std::streamsize>(out.size())))throw ERROR_READ_FAULT;
    return out;
}
std::wstring random_name() {
    std::array<unsigned char,16> bytes{};
    if(BCryptGenRandom(nullptr,bytes.data(),DWORD(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw ERROR_GEN_FAILURE;
    constexpr wchar_t hex[]=L"0123456789abcdef";std::wstring out;
    for(auto ch:bytes){out+=hex[ch>>4];out+=hex[ch&15];}return out;
}
std::vector<unsigned char> sid(HANDLE process) {
    Handle token;if(!OpenProcessToken(process,TOKEN_QUERY,&token.value))return {};
    DWORD size{};GetTokenInformation(token.value,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> info(size);
    if(!size||!GetTokenInformation(token.value,TokenUser,info.data(),size,&size))return {};
    auto* user=reinterpret_cast<TOKEN_USER*>(info.data());
    if(!IsValidSid(user->User.Sid))return {};
    std::vector<unsigned char> result(GetLengthSid(user->User.Sid));
    if(!CopySid(DWORD(result.size()),result.data(),user->User.Sid))return {};return result;
}
bool parent_matches(HANDLE process,const std::filesystem::path& installation) {
    if(!GetProcessId(process)||GetProcessId(process)==GetCurrentProcessId())return false;
    std::wstring path(32768,0);DWORD length=DWORD(path.size());
    if(!QueryFullProcessImageNameW(process,0,path.data(),&length))return false;path.resize(length);
    if(!std::filesystem::equivalent(std::filesystem::path(path),installation/L"SCAU-Link.exe"))return false;
    auto caller=sid(GetCurrentProcess()),parent=sid(process);
    return !caller.empty()&&!parent.empty()&&EqualSid(caller.data(),parent.data());
}
std::optional<Manifest> cached_manifest(const std::filesystem::path& cache,std::string_view key) {
    const auto body=read(cache/L"SCAU-Link-update.json",8192),signature=read(cache/L"SCAU-Link-update.sig",64);
    // The tag supplied here is not trusted: verify_manifest independently binds it
    // to the signed version/channel. Try the only two canonical channels.
    for(bool preview:{true,false}) {
        // Parse a bounded version token without interpreting unverified paths.
        for(std::size_t i=0;i<body.size();++i) {
            if(body[i]!='"')continue;
            const auto end=body.find('"',i+1);if(end==body.npos)break;
            const auto value=std::string_view(body).substr(i+1,end-i-1);i=end;
            if(value.empty()||value.size()>32)continue;
            const std::wstring version(value.begin(),value.end());
            if(!parse_version(version))continue;
            const auto tag=L"v"+version+(preview?L"-preview":L"");
            if(auto result=verify_manifest(body,signature,tag,true,key))return result;
        }
    }
    return {};
}
HANDLE number(std::wstring_view text) {
    if(text.empty()||text.size()>20)return nullptr;
    std::uintptr_t result=0;
    for(auto ch:text) {
        if(ch<L'0'||ch>L'9'||result>(UINTPTR_MAX-9)/10)return nullptr;
        result=result*10+ch-L'0';
    }
    return reinterpret_cast<HANDLE>(result);
}
bool create(const std::filesystem::path& exe,std::wstring arguments,PROCESS_INFORMATION& process) {
    std::wstring command=quote(exe.native())+L" "+arguments;
    STARTUPINFOW info{sizeof(info)};
    return CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,
        nullptr,exe.parent_path().c_str(),&info,&process)!=FALSE;
}
void outcome(const std::filesystem::path& cache,unsigned code) {
    std::ofstream out(cache/L"install-result.json",std::ios::binary|std::ios::trunc);
    out<<"{\"exitCode\":"<<code<<",\"succeeded\":"<<(code==0?"true":"false")<<"}\n";
}
} // namespace

bool start_install_helper(const Options& options,const Manifest&,const std::filesystem::path& cache,
                          const std::atomic_bool& cancelled) {
    try {
        if(cancelled)return false;
        const auto runner=options.directory/L"runners"/random_name();
        std::filesystem::create_directories(runner);
        std::filesystem::copy_file(options.installation/L"scau-update.exe",runner/L"scau-update.exe");
        for(const auto* name:{L"msvcp140.dll",L"msvcp140_atomic_wait.dll",L"vcruntime140.dll",L"vcruntime140_1.dll"})
            if(std::filesystem::exists(options.installation/name))std::filesystem::copy_file(options.installation/name,runner/name);
        SECURITY_ATTRIBUTES security{sizeof(security),nullptr,TRUE};
        Handle ready{CreateEventW(&security,TRUE,FALSE,nullptr)};
        Handle parent{OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,TRUE,GetCurrentProcessId())};
        if(!ready.value||!parent.value)return false;
        SIZE_T size{};InitializeProcThreadAttributeList(nullptr,1,0,&size);
        std::vector<unsigned char> memory(size);
        auto* attributes=reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(memory.data());
        if(!InitializeProcThreadAttributeList(attributes,1,0,&size))return false;
        struct Cleanup {PPROC_THREAD_ATTRIBUTE_LIST p;~Cleanup(){DeleteProcThreadAttributeList(p);}} cleanup{attributes};
        HANDLE inherited[]{parent.value,ready.value};
        if(!UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr))return false;
        STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=attributes;
        const auto helper=runner/L"scau-update.exe";
        std::wstring command=quote(helper.native())+L" --apply "+std::to_wstring(reinterpret_cast<std::uintptr_t>(parent.value))+
            L" "+std::to_wstring(reinterpret_cast<std::uintptr_t>(ready.value))+L" "+quote(options.installation.native())+
            L" "+quote(cache.native())+(options.restart_silent?L" 1":L" 0");
        PROCESS_INFORMATION process{};
        if(!CreateProcessW(helper.c_str(),command.data(),nullptr,nullptr,TRUE,
            CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,runner.c_str(),&startup.StartupInfo,&process))return false;
        Handle child{process.hProcess},thread{process.hThread};
        const auto end=GetTickCount64()+10000;
        do {
            HANDLE events[]{ready.value,child.value};
            const DWORD wait=WaitForMultipleObjects(2,events,FALSE,100);
            if(wait==WAIT_OBJECT_0)return true;
            if(wait==WAIT_OBJECT_0+1||wait==WAIT_FAILED)return false;
        }while(!cancelled&&GetTickCount64()<end);
        return false;
    }catch(...){return false;}
}
int apply_update(int argc,wchar_t** argv,std::string_view trusted_key) {
    const HRESULT initialized=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    struct Apartment {HRESULT value;~Apartment(){if(SUCCEEDED(value))CoUninitialize();}} apartment{initialized};
    if(argc!=7||std::wstring_view(argv[1])!=L"--apply")return ERROR_INVALID_PARAMETER;
    if(trusted_key.empty())trusted_key=signing_public_key;
    Handle parent{number(argv[2])},ready{number(argv[3])};
    if(!parent.value||!ready.value)return ERROR_INVALID_HANDLE;
    const std::filesystem::path installation(argv[4]),cache(argv[5]);
    const std::wstring_view silent(argv[6]);
    try {
        if(!installation.is_absolute()||!cache.is_absolute()||(silent!=L"0"&&silent!=L"1")||
           !parent_matches(parent.value,installation))return ERROR_ACCESS_DENIED;
        const auto manifest=cached_manifest(cache,trusted_key);
        const auto current=parse_version(current_version);
        if(!manifest||!current||*parse_version(manifest->version)<*current)return int(invalid_signature);
        const auto installer=cache/manifest->filename;
        // Deny modification/deletion while verifying and running this image.
        Handle locked{CreateFileW(installer.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};
        if(locked.value==INVALID_HANDLE_VALUE||!verify_installer(installer,*manifest))return int(invalid_signature);
        if(!SetEvent(ready.value))return ERROR_INVALID_HANDLE;
        // Never terminate the parent or apply an update while it is alive.
        if(WaitForSingleObject(parent.value,120000)!=WAIT_OBJECT_0)return ERROR_TIMEOUT;
        PROCESS_INFORMATION setup{};
        unsigned code=ERROR_INSTALL_FAILURE;
        if(create(installer,installer_arguments(installation),setup)) {
            Handle process{setup.hProcess},thread{setup.hThread};
            if(WaitForSingleObject(process.value,1200000)==WAIT_OBJECT_0) {
                DWORD exit{};if(GetExitCodeProcess(process.value,&exit))code=exit;
            }
        }
        outcome(cache,code);
        PROCESS_INFORMATION restarted{};
        if(create(installation/L"SCAU-Link.exe",silent==L"1"?L"--startup --silent":L"--startup",restarted)) {
            CloseHandle(restarted.hThread);CloseHandle(restarted.hProcess);
        }
        return int(code);
    }catch(...){return ERROR_INVALID_DATA;}
}
} // namespace scau::desktop::updates
