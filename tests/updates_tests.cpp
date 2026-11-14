#include "desktop/updates.hpp"
#include "release_config.hpp"
#include "update_fixture.hpp"
#include <openssl/evp.h>
#include <objbase.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

using namespace scau::desktop::updates;
namespace {
unsigned checks=0;
void require(bool value,const char* message){++checks;if(std::getenv("SCAU_UPDATE_TEST_TRACE"))std::cout<<checks<<" "<<message<<'\n'<<std::flush;if(!value)throw std::runtime_error(message);}
std::string hex(const unsigned char* bytes,std::size_t count){constexpr char digits[]="0123456789abcdef";std::string out;for(std::size_t i=0;i<count;++i){out+=digits[bytes[i]>>4];out+=digits[bytes[i]&15];}return out;}
std::string sha(std::string_view bytes){unsigned char digest[32];unsigned size{};EVP_Digest(bytes.data(),bytes.size(),digest,&size,EVP_sha256(),nullptr);return hex(digest,size);}
std::string read(const std::filesystem::path& path){std::ifstream in(path,std::ios::binary);return std::string(std::istreambuf_iterator<char>(in),{});}
void write(const std::filesystem::path& path,std::string_view data){std::ofstream out(path,std::ios::binary);out.write(data.data(),data.size());}
std::string sign(std::string_view payload) {
    std::array<unsigned char,32> seed{};
    for(unsigned i=0;i<32;++i){unsigned value{};sscanf_s(update_fixture_seed+i*2,"%2x",&value);seed[i]=static_cast<unsigned char>(value);}
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed.data(),seed.size()),EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    require(key&&ctx&&EVP_DigestSignInit(ctx.get(),nullptr,nullptr,nullptr,key.get())==1,"fixture signing init");
    std::string out(64,0);std::size_t size=out.size();
    require(EVP_DigestSign(ctx.get(),reinterpret_cast<unsigned char*>(out.data()),&size,reinterpret_cast<const unsigned char*>(payload.data()),payload.size())==1&&size==64,"fixture signing");return out;
}
std::string manifest(std::string_view binary,std::string version="0.14.0",bool preview=true) {
    const auto suffix=preview?"-preview":"";
    const auto tag="v"+version+suffix;
    const auto filename="SCAU-Link-"+version+"-Setup-x64"+suffix+".exe";
    return "{\"schema\":1,\"architecture\":\"x64\",\"channel\":\""+std::string(preview?"preview":"stable")+"\",\"version\":\""+version+
        "\",\"tag\":\""+tag+"\",\"filename\":\""+filename+"\",\"size\":"+std::to_string(binary.size())+
        ",\"sha256\":\""+sha(binary)+"\",\"url\":\"https://github.com/Hubujiu/SCAU-Link/releases/download/"+tag+"/"+filename+"\"}";
}
std::string release(std::string version="0.14.0",bool preview=true) {
    const std::string tag="v"+version+(preview?"-preview":"");
    std::string out="{\"draft\":false,\"prerelease\":"+std::string(preview?"true":"false")+",\"tag_name\":\""+tag+"\",\"assets\":[";
    for(const auto* name:{"SCAU-Link-update.json","SCAU-Link-update.sig"}) {
        if(out.back()!='[')out+=',';
        out+="{\"state\":\"uploaded\",\"name\":\""+std::string(name)+"\",\"browser_download_url\":\"https://github.com/Hubujiu/SCAU-Link/releases/download/"+tag+"/"+name+"\"}";
    }
    return out+"]}";
}
struct Temp {
    std::filesystem::path path;
    Temp(){path=std::filesystem::temp_directory_path()/(L"scau-update-test-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64()));require(!std::filesystem::exists(path),"fresh test directory");std::filesystem::create_directories(path);}
    ~Temp(){
        const auto parent=std::filesystem::weakly_canonical(std::filesystem::temp_directory_path());
        if(path.parent_path()!=parent||!path.filename().native().starts_with(L"scau-update-test-"))return;
        std::error_code error;
        for(unsigned i=0;i<30;++i){std::filesystem::remove_all(path,error);if(!error)return;Sleep(100);}
    }
};
bool wait_for(const std::function<bool()>& condition,unsigned timeout=7000){const auto end=GetTickCount64()+timeout;do{if(condition())return true;Sleep(20);}while(GetTickCount64()<end);return false;}
Snapshot wait(Manager& manager,Phase phase){require(wait_for([&]{return manager.snapshot().phase==phase;}),"manager reaches expected phase");return manager.snapshot();}
Options options(const std::filesystem::path& path,std::string payload,std::string signature,std::string installer,std::atomic<unsigned>& requests,bool corrupt=false) {
    Options out;out.directory=path;out.installation=std::filesystem::current_path();out.current=L"0.13.0";out.public_key=update_fixture_public;
    out.fetch=[=,&requests](std::wstring_view url,std::size_t maximum,const Sink& sink,const std::atomic_bool& cancelled) {
        ++requests;if(cancelled)return unsigned(ERROR_CANCELLED);
        if(url.find(L"api.github.com")!=url.npos)Sleep(20);
        const auto data=url.find(L"api.github.com")!=url.npos?"["+release()+"]":url.ends_with(L".json")?payload:url.ends_with(L".sig")?signature:corrupt?installer+"changed":installer;
        if(data.size()>maximum)return unsigned(ERROR_FILE_TOO_LARGE);
        for(std::size_t offset=0;offset<data.size();offset+=3){const auto size=std::min<std::size_t>(3,data.size()-offset);if(!sink(data.data()+offset,size))return unsigned(ERROR_CANCELLED);}
        return 0u;
    };return out;
}
void primitives(){
    require(parse_version(L"0.13.0")<parse_version(L"0.14.0"),"numeric versions");
    require(parse_version(L"1.10.0")>parse_version(L"1.9.0"),"non-lexicographic versions");
    for(const auto* value:{L"",L"1.2",L"01.2.3",L"1.2.3.4",L"1.2.-3",L"1.65536.0",L"v1.2.3",L"1.2.3-preview"})require(!parse_version(value),"invalid version");
    const std::string binary="signed fixture bytes",payload=manifest(binary),signature=sign(payload);
    auto parsed=verify_manifest(payload,signature,L"v0.14.0-preview",true,update_fixture_public);require(bool(parsed),"valid signed manifest");
    require(!verify_manifest(payload+" ",signature,L"v0.14.0-preview",true,update_fixture_public),"tampered manifest");
    require(!verify_manifest(payload,signature.substr(1),L"v0.14.0-preview",true,update_fixture_public),"short signature");
    require(!verify_manifest(payload,signature,L"v0.15.0-preview",true,update_fixture_public),"tag substitution");
    require(!verify_manifest(payload,signature,L"v0.14.0-preview",false,update_fixture_public),"stable channel rejects preview");
    require(!verify_manifest(payload,signature,L"v0.14.0-preview",true,signing_public_key),"fixture key is not publisher key");
    auto wrong=payload;wrong.replace(wrong.find("https://github.com"),18,"http://evil.test");
    require(!verify_manifest(wrong,sign(wrong),L"v0.14.0-preview",true,update_fixture_public),"signed but wrong origin");
    for(const auto* value:{L"http://github.com/Hubujiu/SCAU-Link/releases/download/a/b",L"https://github.com.evil.test/Hubujiu/SCAU-Link/releases/download/a/b",L"https://user@github.com/Hubujiu/SCAU-Link/releases/download/a/b",L"https://github.com/other/repo/releases/download/a/b",L"https://github.com/Hubujiu/SCAU-Link/releases/download/../b",L"https://release-assets.githubusercontent.com/a"})require(!allowed_download_url(value),"untrusted original URL");
    require(allowed_download_url(L"https://release-assets.githubusercontent.com/a?signature=opaque",true),"GitHub asset redirect");
    require(!allowed_download_url(L"https://untrusted.test/a",true),"redirect outside GitHub");
    require(!select_release("["+release("0.12.0")+"]",L"0.13.0",true),"no downgrade");
    require(!select_release("["+release()+"]",L"0.13.0",false),"stable excludes preview release");
    auto choice=select_release("["+release("0.14.0",false)+","+release("0.15.0")+"]",L"0.13.0",false);
    require(choice&&choice->tag==L"v0.14.0","select stable in mixed releases");
    choice=select_release("["+release("0.13.0",false)+"]",L"0.13.0",true);require(choice&&!choice->preview,"preview to same numeric stable");
    for(bool running:{false,true})for(bool busy:{false,true})for(bool idle:{false,true})require(can_install(running,busy,idle)==(!running&&!busy&&idle),"idle installation gate");
    const auto args=installer_arguments(std::filesystem::path(L"D:\\安装 路径\\SCAU Link"));require(args.find(L"\"/DIR=D:\\安装 路径\\SCAU Link\"")!=args.npos,"quoted native custom directory");
}
void managers(){
    std::cout<<"manager fixtures\n"<<std::flush;
    const std::string binary="real fixture installer bytes",payload=manifest(binary),signature=sign(payload);
    Temp temp;std::atomic<unsigned> requests{};
    const auto cache=temp.path/L"cache";
    {
        Manager manager(options(cache,payload,signature,binary,requests));
        require(manager.check_now(),"manual check queued");require(!manager.check_now(),"duplicate check rejected");
        wait(manager,Phase::Available);const auto before=requests.load();manager.tick(false);Sleep(50);require(requests==before,"not idle does not download");
        manager.tick(true);wait(manager,Phase::Ready);
        require(read(cache/L"pending/SCAU-Link-0.14.0-Setup-x64-preview.exe")==binary,"verified download promoted");
    }
    const auto before=requests.load();
    {Manager restored(options(cache,payload,signature,binary,requests));wait(restored,Phase::Ready);require(requests==before,"cached update verified offline");}
    write(cache/L"pending/SCAU-Link-0.14.0-Setup-x64-preview.exe","tampered");
    {Manager restored(options(cache,payload,signature,binary,requests));wait(restored,Phase::Available);require(!restored.install_now(),"tampered cache cannot install");}
    {Manager bad(options(temp.path/L"bad",payload,signature,binary,requests,true));require(bad.check_now(),"bad download check");wait(bad,Phase::Available);require(bad.download_now(),"bad download queued");wait(bad,Phase::Failed);require(!std::filesystem::exists(temp.path/L"bad/pending/SCAU-Link-0.14.0-Setup-x64-preview.exe"),"bad package not cached");}
    {auto config=options(temp.path/L"failed",payload,signature,binary,requests);config.fetch=[](auto,auto,const auto&,const auto&){return 0x200001adu;};Manager failed(std::move(config));require(failed.check_now(),"failed query queued");require(wait(failed,Phase::Failed).error==0x200001adu,"rate/network error retained");}
}
std::filesystem::path executable(){std::wstring name(32768,0);const auto size=GetModuleFileNameW(nullptr,name.data(),DWORD(name.size()));name.resize(size);return name;}
bool spawn(const std::filesystem::path& app,std::wstring arguments,PROCESS_INFORMATION& process){std::wstring command=L"\""+app.native()+L"\" "+arguments;STARTUPINFOW startup{sizeof(startup)};return CreateProcessW(app.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,app.parent_path().c_str(),&startup,&process)!=FALSE;}
void handoff(bool fail){
    std::cout<<(fail?"failed-install handoff\n":"successful-install handoff\n")<<std::flush;
    Temp temp;const auto installation=temp.path/L"自定义 目录";const auto cache=temp.path/L"updates/pending";
    std::filesystem::create_directories(installation);std::filesystem::create_directories(cache);
    const auto bin=executable().parent_path();
    std::filesystem::copy_file(executable(),installation/L"SCAU-Link.exe");
    std::filesystem::copy_file(bin/L"update-helper-fixture.exe",installation/L"scau-update.exe");
    const auto setup=cache/L"SCAU-Link-0.14.0-Setup-x64-preview.exe";
    std::filesystem::copy_file(bin/L"update-installer-fixture.exe",setup);
    const auto payload=manifest(read(setup));write(cache/L"SCAU-Link-update.json",payload);write(cache/L"SCAU-Link-update.sig",sign(payload));
    if(fail)write(installation/L"fail-install","1");
    PROCESS_INFORMATION parent{};
    require(spawn(installation/L"SCAU-Link.exe",L"--handoff-parent \""+installation.native()+L"\" \""+cache.native()+L"\"",parent),"start isolated parent");
    require(wait_for([&]{return std::filesystem::exists(installation/L"parent-ready.ok");}),"helper readiness handshake");
    require(!std::filesystem::exists(installation/L"installer-ran.ok"),"installer waits for parent exit");
    const auto writable=CreateFileW(setup.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    require(writable==INVALID_HANDLE_VALUE,"verified executable held against writes");if(writable!=INVALID_HANDLE_VALUE)CloseHandle(writable);
    write(installation/L"release-parent.ok","1");
    require(WaitForSingleObject(parent.hProcess,5000)==WAIT_OBJECT_0,"parent exits normally");CloseHandle(parent.hThread);CloseHandle(parent.hProcess);
    require(wait_for([&]{return std::filesystem::exists(installation/L"restarted.ok");},15000),"helper starts app after setup");
    require(std::filesystem::exists(installation/L"installer-ran.ok"),"setup used custom directory");
    require(read(cache/L"install-result.json").find(fail?"\"exitCode\":1603":"\"exitCode\":0")!=std::string::npos,"setup success/failure recorded");
}
} // namespace
int wmain(int argc,wchar_t** argv){
    const HRESULT initialized=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    struct Apartment {HRESULT value;~Apartment(){if(SUCCEEDED(value))CoUninitialize();}} apartment{initialized};
    if(argc==2&&std::wstring_view(argv[1])==L"--startup"){write(std::filesystem::current_path()/L"restarted.ok","1");return 0;}
    if(argc==4&&(std::wstring_view(argv[1])==L"--handoff-parent"||std::wstring_view(argv[1])==L"--handoff-parent-silent")) {
        const std::filesystem::path installation(argv[2]),cache(argv[3]);Options config;config.directory=cache.parent_path();config.installation=installation;
        config.restart_silent=std::wstring_view(argv[1])==L"--handoff-parent-silent";
        std::atomic_bool cancelled=false;Manifest unused;
        if(!start_install_helper(config,unused,cache,cancelled))return 88;
        write(installation/L"parent-ready.ok","1");
        if(!wait_for([&]{return std::filesystem::exists(installation/L"release-parent.ok");},12000))return 89;
        write(installation/L"parent-exiting.ok","1");return 0;
    }
    try{std::cout<<"update primitives\n"<<std::flush;primitives();managers();handoff(false);handoff(true);std::cout<<checks<<" update checks passed\n";return 0;}
    catch(const std::exception& error){std::cerr<<"Update check failed: "<<error.what()<<'\n';return 1;}
}
