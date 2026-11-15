#include "updates.hpp"
#include "release_config.hpp"
#include <winhttp.h>
#include <objbase.h>
#include <bcrypt.h>
#include <openssl/evp.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <vector>

namespace scau::desktop::updates {
namespace {
using namespace winrt::Windows::Data::Json;
constexpr std::size_t metadata_limit = 1024 * 1024;
struct Apartment {
    HRESULT result=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    ~Apartment(){if(SUCCEEDED(result))CoUninitialize();}
};
struct Internet {
    HINTERNET value{};
    ~Internet() { if (value) WinHttpCloseHandle(value); }
};
std::wstring wide(std::string_view value) {
    if (value.size() > metadata_limit) throw ERROR_INVALID_DATA;
    if (value.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,value.data(),int(value.size()),nullptr,0);
    if (!n) throw ERROR_INVALID_DATA;
    std::wstring out(n,0);
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),int(value.size()),out.data(),n);
    return out;
}
std::string narrow(std::wstring_view value) {
    if (value.empty()) return {};
    const int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),int(value.size()),nullptr,0,nullptr,nullptr);
    if (!n) throw ERROR_INVALID_DATA;
    std::string out(n,0);
    WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),int(value.size()),out.data(),n,nullptr,nullptr);
    return out;
}
std::wstring field(const JsonObject& object,const wchar_t* name) {
    if (!object.HasKey(name) || object.GetNamedValue(name).ValueType()!=JsonValueType::String)
        throw ERROR_INVALID_DATA;
    return std::wstring(object.GetNamedString(name));
}
bool boolean(const JsonObject& object,const wchar_t* name) {
    if (!object.HasKey(name) || object.GetNamedValue(name).ValueType()!=JsonValueType::Boolean)
        throw ERROR_INVALID_DATA;
    return object.GetNamedBoolean(name);
}
bool valid_digest(std::string_view value) {
    return value.size()==64&&std::all_of(value.begin(),value.end(),[](char ch){return (ch>='0'&&ch<='9')||(ch>='a'&&ch<='f');});
}
std::wstring prefix() { return std::wstring(repository_url)+L"/releases/download/"; }
std::wstring tag_for(std::wstring_view version,bool preview) {
    return L"v"+std::wstring(version)+(preview?L"-preview":L"");
}
std::wstring filename_for(std::wstring_view version,bool preview) {
    return L"SCAU-Link-"+std::wstring(version)+L"-Setup-x64"+(preview?L"-preview":L"")+L".exe";
}
std::optional<Version> version_from_tag(std::wstring_view tag,bool preview) {
    if (!tag.starts_with(L"v")) return {};
    tag.remove_prefix(1);
    if (preview) {
        if (!tag.ends_with(L"-preview")) return {};
        tag.remove_suffix(8);
    }
    return parse_version(tag);
}
bool newer(const Manifest& manifest,std::wstring_view current,bool current_preview) {
    auto next=parse_version(manifest.version), previous=parse_version(current);
    return next && previous && (*next>*previous || (*next==*previous && current_preview && !manifest.preview));
}
std::vector<unsigned char> unhex(std::string_view text) {
    if (text.size()%2) return {};
    std::vector<unsigned char> out;
    for (std::size_t i=0;i<text.size();i+=2) {
        unsigned value{};
        auto [end,error]=std::from_chars(text.data()+i,text.data()+i+2,value,16);
        if (error!=std::errc{} || end!=text.data()+i+2) return {};
        out.push_back(static_cast<unsigned char>(value));
    }
    return out;
}
std::string hex(const unsigned char* data,std::size_t size) {
    constexpr char digits[]="0123456789abcdef";
    std::string out;
    for (std::size_t i=0;i<size;++i) { out+=digits[data[i]>>4];out+=digits[data[i]&15]; }
    return out;
}
std::uint64_t now() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
std::string read(const std::filesystem::path& file,std::size_t maximum) {
    std::error_code error;
    const auto size=std::filesystem::file_size(file,error);
    if (error || size>maximum) throw ERROR_INVALID_DATA;
    std::ifstream stream(file,std::ios::binary);
    std::string result(static_cast<std::size_t>(size),0);
    if (!stream.read(result.data(),static_cast<std::streamsize>(size))) throw ERROR_READ_FAULT;
    return result;
}
void write(const std::filesystem::path& file,std::string_view data) {
    auto temporary=file; temporary+=L".tmp";
    std::ofstream stream(temporary,std::ios::binary|std::ios::trunc);
    if (!stream.write(data.data(),static_cast<std::streamsize>(data.size())) || !stream.flush()) throw ERROR_WRITE_FAULT;
    stream.close();
    if (!MoveFileExW(temporary.c_str(),file.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) throw GetLastError();
}
std::string get(const Fetch& fetch,std::wstring_view url,std::size_t maximum,const std::atomic_bool& cancel) {
    std::string body;
    const auto status=fetch(url,maximum,[&](const void* data,std::size_t size) {
        if (size>maximum-body.size()) return false;
        body.append(static_cast<const char*>(data),size); return true;
    },cancel);
    if (status) throw status;
    return body;
}
bool busy(Phase p) { return p==Phase::Checking || p==Phase::Downloading || p==Phase::Starting || p==Phase::InstallQueued; }
std::wstring quote(std::wstring_view text) {
    std::wstring out=L"\"";unsigned slashes=0;
    for (wchar_t c:text) {
        if (c==L'\\') {++slashes;continue;}
        out.append(slashes*(c==L'"'?2:1),L'\\');slashes=0;
        if (c==L'"') out+=L'\\';
        out+=c;
    }
    out.append(slashes*2,L'\\');return out+L'"';
}
} // namespace

std::optional<Version> parse_version(std::wstring_view text) {
    if (text.empty() || text.size()>32) return {};
    Version out;
    for (unsigned i=0;i<3;++i) {
        const auto end=text.find(L'.');
        const auto part=text.substr(0,end);
        if (part.empty() || part.size()>5 || (part.size()>1 && part[0]==L'0')) return {};
        unsigned value=0;
        for (wchar_t c:part) { if(c<L'0'||c>L'9')return {};value=value*10+c-L'0'; }
        if(value>65535)return {};
        out.parts[i]=value;
        if(i==2) { if(end!=text.npos)return {}; }
        else { if(end==text.npos)return {};text.remove_prefix(end+1); }
    }
    return out;
}
bool allowed_download_url(std::wstring_view text,bool redirected) {
    if (text.empty() || text.size()>8192 || !text.starts_with(L"https://") ||
        text.find_first_of(L"\r\n\\@#")!=text.npos ||
        std::any_of(text.begin(),text.end(),[](wchar_t c){return c<33||c>126;})) return false;
    auto rest=text.substr(8);const auto end=rest.find_first_of(L"/?");
    const auto host=rest.substr(0,end);
    if (end==rest.npos || rest[end]!=L'/') return false;
    const auto path=rest.substr(end);
    if (host==L"api.github.com") return path==L"/repos/Hubujiu/SCAU-Link/releases?per_page=20";
    if (host==L"github.com") return path.starts_with(L"/Hubujiu/SCAU-Link/releases/download/") && path.find(L"..") ==path.npos;
    return redirected && (host==L"release-assets.githubusercontent.com" || host==L"objects.githubusercontent.com");
}
std::optional<Candidate> select_release(std::string_view json,std::wstring_view current,bool allow_preview) {
    try {
        const auto installed=parse_version(current);if(!installed)return {};
        const auto releases=JsonArray::Parse(wide(json));
        if(releases.Size()>20)return {};
        std::optional<Candidate> best;std::optional<Version> selected;
        for(const auto& raw:releases) {
            try {
                const auto item=raw.GetObject();
                const bool preview=boolean(item,L"prerelease");
                if(boolean(item,L"draft") || (preview&&!allow_preview))continue;
                const auto tag=field(item,L"tag_name");const auto version=version_from_tag(tag,preview);
                if(!version || *version<*installed || (*version==*installed && !(allow_preview&&!preview)))continue;
                if(selected && (*version<*selected || (*version==*selected && (preview || !best->preview))))continue;
                Candidate candidate;candidate.tag=tag;candidate.preview=preview;
                const auto assets=item.GetNamedArray(L"assets");if(assets.Size()>100)continue;
                for(const auto& value:assets) {
                    const auto asset=value.GetObject();
                    if(field(asset,L"state")!=L"uploaded")continue;
                    const auto name=field(asset,L"name");const auto url=field(asset,L"browser_download_url");
                    if(url!=prefix()+tag+L"/"+name)continue;
                    if(name==L"SCAU-Link-update.json")candidate.manifest_url=url;
                    if(name==L"SCAU-Link-update.sig")candidate.signature_url=url;
                    if(name==L"SCAU-Link-live.json")candidate.live_url=url;
                    if(name==L"SCAU-Link-live.sig")candidate.live_signature_url=url;
                }
                if(candidate.manifest_url.empty()||candidate.signature_url.empty())continue;
                selected=version;best=std::move(candidate);
            } catch(...) {continue;}
        }
        return best;
    } catch(...) {return {};}
}
std::optional<Manifest> verify_manifest(std::string_view payload,std::string_view signature,
        std::wstring_view tag,bool allow_preview,std::string_view public_key_hex) {
    try {
        const auto public_key=unhex(public_key_hex);
        if(payload.empty()||payload.size()>8192||signature.size()!=64||public_key.size()!=32)return {};
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(
            EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,nullptr,public_key.data(),public_key.size()),EVP_PKEY_free);
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        if(!key||!context||EVP_DigestVerifyInit(context.get(),nullptr,nullptr,nullptr,key.get())!=1||
           EVP_DigestVerify(context.get(),reinterpret_cast<const unsigned char*>(signature.data()),signature.size(),
               reinterpret_cast<const unsigned char*>(payload.data()),payload.size())!=1)return {};
        const auto object=JsonObject::Parse(wide(payload));
        if(object.Size()!=9||object.GetNamedNumber(L"schema")!=1||field(object,L"architecture")!=L"x64")return {};
        Manifest out;out.version=field(object,L"version");out.tag=field(object,L"tag");
        const auto channel=field(object,L"channel");
        if(channel!=L"preview"&&channel!=L"stable")return {};
        out.preview=channel==L"preview";
        if(!parse_version(out.version)||out.tag!=tag||out.tag!=tag_for(out.version,out.preview)||(out.preview&&!allow_preview))return {};
        out.filename=field(object,L"filename");out.url=field(object,L"url");
        if(out.filename!=filename_for(out.version,out.preview)||out.url!=prefix()+out.tag+L"/"+out.filename)return {};
        out.sha256=narrow(field(object,L"sha256"));
        if(out.sha256.size()!=64||std::any_of(out.sha256.begin(),out.sha256.end(),[](char c){return !(c>='0'&&c<='9')&&!(c>='a'&&c<='f');}))return {};
        const double size=object.GetNamedNumber(L"size");
        if(size<1||size>maximum_installer_size||size!=static_cast<std::uint64_t>(size))return {};
        out.size=static_cast<std::uint64_t>(size);return out;
    } catch(...) {return {};}
}
std::optional<LiveManifest> verify_live_manifest(std::string_view payload,std::string_view signature,
        const Manifest& installer,std::string_view public_key_hex) {
    try {
        const auto public_key=unhex(public_key_hex);
        if(payload.empty()||payload.size()>8192||signature.size()!=64||public_key.size()!=32)return {};
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
            nullptr,public_key.data(),public_key.size()),EVP_PKEY_free);
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        if(!key||!context||EVP_DigestVerifyInit(context.get(),nullptr,nullptr,nullptr,key.get())!=1||
           EVP_DigestVerify(context.get(),reinterpret_cast<const unsigned char*>(signature.data()),signature.size(),
               reinterpret_cast<const unsigned char*>(payload.data()),payload.size())!=1)return {};
        const auto object=JsonObject::Parse(wide(payload));
        if(object.Size()!=9||object.GetNamedNumber(L"schema")!=1||field(object,L"version")!=installer.version||
           field(object,L"tag")!=installer.tag||narrow(field(object,L"installerSha256"))!=installer.sha256)return {};
        LiveManifest out;out.bundle=installer;
        const auto expected=L"SCAU-Link-"+installer.version+L"-Live-x64"+(installer.preview?L"-preview":L"")+L".bin";
        out.bundle.filename=field(object,L"filename");out.bundle.url=field(object,L"url");
        out.bundle.sha256=narrow(field(object,L"sha256"));
        const double size=object.GetNamedNumber(L"size");
        if(out.bundle.filename!=expected||out.bundle.url!=prefix()+installer.tag+L"/"+expected||
           !valid_digest(out.bundle.sha256)||size<12||size>maximum_installer_size||size!=static_cast<std::uint64_t>(size))return {};
        out.bundle.size=static_cast<std::uint64_t>(size);
        const auto protected_values=object.GetNamedObject(L"protected");
        if(protected_values.Size()!=protected_files.size())return {};
        for(std::size_t i=0;i<protected_files.size();++i) {
            out.protected_hashes[i]=narrow(field(protected_values,protected_files[i]));
            if(!valid_digest(out.protected_hashes[i]))return {};
        }
        return out;
    }catch(...){return {};}
}
bool verify_installer(const std::filesystem::path& file,const Manifest& manifest) {
    try {
        if(manifest.size<1||manifest.size>maximum_installer_size||std::filesystem::file_size(file)!=manifest.size)return false;
        std::ifstream stream(file,std::ios::binary);if(!stream)return false;
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        if(!ctx||EVP_DigestInit_ex(ctx.get(),EVP_sha256(),nullptr)!=1)return false;
        std::array<char,65536> buffer{};std::uint64_t count=0;
        while(stream) {stream.read(buffer.data(),buffer.size());const auto n=stream.gcount();count+=n;
            if(n>0&&EVP_DigestUpdate(ctx.get(),buffer.data(),static_cast<std::size_t>(n))!=1)return false;}
        std::array<unsigned char,32> digest{};unsigned size{};
        return stream.eof()&&count==manifest.size&&EVP_DigestFinal_ex(ctx.get(),digest.data(),&size)==1&&
            size==digest.size()&&hex(digest.data(),digest.size())==manifest.sha256;
    } catch(...) {return false;}
}
bool can_install(bool running,bool interaction,bool idle) noexcept {return !running&&!interaction&&idle;}
bool can_install(Impact impact,bool connected,bool authentication_busy,bool interaction,bool idle) noexcept {
    return idle&&!authentication_busy&&!interaction&&(!connected||impact==Impact::PreserveConnection);
}
bool system_idle(DWORD milliseconds) noexcept {
    LASTINPUTINFO info{sizeof(info)};
    return GetLastInputInfo(&info)&&DWORD(GetTickCount()-info.dwTime)>=milliseconds;
}
std::wstring installer_arguments(const std::filesystem::path& directory) {
    if(!directory.is_absolute()||directory.native().find_first_of(L"\r\n\"")!=std::wstring::npos)throw ERROR_INVALID_PARAMETER;
    return L"/CURRENTUSER /VERYSILENT /SUPPRESSMSGBOXES /SP- /NORESTART /NOICONS /TASKS= "+
        quote(L"/DIR="+directory.native());
}
unsigned fetch_https(std::wstring_view original,std::size_t maximum,const Sink& sink,const std::atomic_bool& cancel) {
    if(!maximum||maximum>maximum_installer_size)return ERROR_INVALID_PARAMETER;
    try {
        Internet session{WinHttpOpen(L"SCAU-Link-Updater/1",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0)};
        if(!session.value)return GetLastError();
        WinHttpSetTimeouts(session.value,5000,5000,10000,10000);
        std::wstring url(original);const auto deadline=GetTickCount64()+180000;
        for(unsigned redirects=0;redirects<6;++redirects) {
            if(cancel)return ERROR_CANCELLED;
            if(!allowed_download_url(url,redirects!=0))return ERROR_ACCESS_DENIED;
            URL_COMPONENTS parts{sizeof(parts)};parts.dwHostNameLength=parts.dwUrlPathLength=parts.dwExtraInfoLength=DWORD(-1);
            if(!WinHttpCrackUrl(url.c_str(),0,0,&parts)||parts.nScheme!=INTERNET_SCHEME_HTTPS||parts.nPort!=443)return ERROR_INVALID_PARAMETER;
            std::wstring host(parts.lpszHostName,parts.dwHostNameLength),path(parts.lpszUrlPath,parts.dwUrlPathLength);
            if(parts.dwExtraInfoLength)path.append(parts.lpszExtraInfo,parts.dwExtraInfoLength);
            Internet connection{WinHttpConnect(session.value,host.c_str(),443,0)};if(!connection.value)return GetLastError();
            Internet request{WinHttpOpenRequest(connection.value,L"GET",path.c_str(),nullptr,WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE)};if(!request.value)return GetLastError();
            DWORD disabled=WINHTTP_DISABLE_REDIRECTS|WINHTTP_DISABLE_COOKIES,autologon=WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
            if(!WinHttpSetOption(request.value,WINHTTP_OPTION_DISABLE_FEATURE,&disabled,sizeof(disabled))||
                !WinHttpSetOption(request.value,WINHTTP_OPTION_AUTOLOGON_POLICY,&autologon,sizeof(autologon)))return GetLastError();
            const wchar_t* headers=L"Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n";
            if(!WinHttpSendRequest(request.value,headers,DWORD(-1),WINHTTP_NO_REQUEST_DATA,0,0,0)||
               !WinHttpReceiveResponse(request.value,nullptr))return GetLastError();
            DWORD status{},length=sizeof(status);
            if(!WinHttpQueryHeaders(request.value,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,nullptr,&status,&length,nullptr))return GetLastError();
            if(status==301||status==302||status==303||status==307||status==308) {
                length=0;WinHttpQueryHeaders(request.value,WINHTTP_QUERY_LOCATION,nullptr,nullptr,&length,nullptr);
                if(length<2||length>16384)return ERROR_WINHTTP_INVALID_SERVER_RESPONSE;
                std::wstring location(length/sizeof(wchar_t),0);
                if(!WinHttpQueryHeaders(request.value,WINHTTP_QUERY_LOCATION,nullptr,location.data(),&length,nullptr))return GetLastError();
                location.resize(wcsnlen(location.c_str(),location.size()));url=std::move(location);continue;
            }
            if(status!=200)return 0x20000000u|status;
            std::uint64_t received=0;std::array<char,65536> buffer{};
            for(;;) {
                if(cancel)return ERROR_CANCELLED;
                if(GetTickCount64()>deadline)return ERROR_TIMEOUT;
                DWORD count{};if(!WinHttpReadData(request.value,buffer.data(),DWORD(buffer.size()),&count))return GetLastError();
                if(!count)return 0;
                if(count>maximum-received)return ERROR_FILE_TOO_LARGE;
                received+=count;if(!sink(buffer.data(),count))return ERROR_CANCELLED;
            }
        }
        return ERROR_WINHTTP_REDIRECT_FAILED;
    } catch(...) {return ERROR_INVALID_DATA;}
}
Manager::Manager(Options options):options_(std::move(options)) {
    if(!parse_version(options_.current)||!options_.directory.is_absolute()||!options_.installation.is_absolute())throw std::invalid_argument("update options");
    if(!options_.fetch)options_.fetch=fetch_https;
    next_check_=now()+60;
    worker_=std::thread([this]{work();});
}
Manager::~Manager() {cancel_=true;cv_.notify_all();if(worker_.joinable())worker_.join();}
Snapshot Manager::snapshot() const {std::lock_guard lock(mutex_);return snapshot_;}
std::filesystem::path Manager::cache() const {return options_.directory/L"pending";}
const Manifest& Manager::artifact() const {return impact_==Impact::PreserveConnection?live_->bundle:*manifest_;}
void Manager::set(Phase phase,unsigned error,unsigned progress) {
    {std::lock_guard lock(mutex_);snapshot_.phase=phase;snapshot_.error=error;snapshot_.progress=progress;
        snapshot_.impact=impact_;if(manifest_)snapshot_.version=manifest_->version;}
    if(options_.changed)options_.changed();
}
bool Manager::enqueue(Command command) {
    {std::lock_guard lock(mutex_);
        if(cancel_||command_!=Command::None||busy(snapshot_.phase)||snapshot_.phase==Phase::Applied)return false;
        if(command==Command::Download&&snapshot_.phase!=Phase::Available)return false;
        if(command==Command::Install&&snapshot_.phase!=Phase::Ready)return false;
        command_=command;snapshot_.phase=command==Command::Check?Phase::Checking:
            command==Command::Download?Phase::Downloading:Phase::Starting;snapshot_.error=0;}
    cv_.notify_one();if(options_.changed)options_.changed();return true;
}
bool Manager::check_now(){return enqueue(Command::Check);}
bool Manager::download_now(){return enqueue(Command::Download);}
bool Manager::install_now(){return enqueue(Command::Install);}
void Manager::tick(bool idle) {
    if(!idle)return;
    const auto state=snapshot();
    if(state.phase==Phase::Available)download_now();
    else if(!busy(state.phase)&&state.phase!=Phase::Ready&&state.phase!=Phase::Applied&&now()>=next_check_)check_now();
}
void Manager::work() {
    Apartment apartment;
    cleanup_live_backups(options_.installation);
    // Cache verification is lazy and off the UI thread, including the installer hash.
    try {
        std::filesystem::create_directories(cache());
        try {
            const auto text=read(options_.directory/L"checked-at.txt",32);
            std::uint64_t stamp{};auto [last,error]=std::from_chars(text.data(),text.data()+text.size(),stamp);
            if(error==std::errc{}&&last==text.data()+text.size()&&stamp<=now()+60)next_check_=std::max(next_check_.load(),stamp+21600);
        }catch(...){}
        try {
            payload_=read(cache()/L"SCAU-Link-update.json",8192);signature_=read(cache()/L"SCAU-Link-update.sig",64);
            const auto tag=field(JsonObject::Parse(wide(payload_)),L"tag");
            auto pending=verify_manifest(payload_,signature_,tag,true,options_.public_key);
            if(pending&&(!pending->preview||options_.allow_preview)&&newer(*pending,options_.current,options_.allow_preview)) {
                manifest_=std::move(pending);
                try {
                    live_=verify_live_manifest(read(cache()/L"SCAU-Link-live.json",8192),read(cache()/L"SCAU-Link-live.sig",64),*manifest_,options_.public_key);
                }catch(...){}
                impact_=live_&&live_compatible(options_.installation,*live_)?Impact::PreserveConnection:Impact::MayDisconnect;
                set(verify_installer(cache()/artifact().filename,artifact())?Phase::Ready:Phase::Available);
            } else if(pending) {
                // Remove only filenames authenticated by our own manifest, after an
                // upgrade (or when leaving the preview channel). No recursive deletion.
                std::error_code ignored;
                try {
                    const auto previous=verify_live_manifest(read(cache()/L"SCAU-Link-live.json",8192),
                        read(cache()/L"SCAU-Link-live.sig",64),*pending,options_.public_key);
                    if(previous)std::filesystem::remove(cache()/previous->bundle.filename,ignored);
                }catch(...){}
                std::filesystem::remove(cache()/L"SCAU-Link-live.json",ignored);
                std::filesystem::remove(cache()/L"SCAU-Link-live.sig",ignored);
                std::filesystem::remove(cache()/pending->filename,ignored);
                std::filesystem::remove(cache()/L"SCAU-Link-update.json",ignored);
                std::filesystem::remove(cache()/L"SCAU-Link-update.sig",ignored);
            }
        }catch(...){}
    }catch(...){}
    for(;;) {
        Command command;
        {std::unique_lock lock(mutex_);cv_.wait(lock,[&]{return cancel_||command_!=Command::None;});
            if(cancel_)return;command=command_;command_=Command::None;}
        try {
            if(command==Command::Check)check();
            else if(command==Command::Download)download();
            else if(command==Command::Install)install();
        }catch(unsigned error){next_check_=now()+1800;set(Phase::Failed,error);}
        catch(unsigned long error){next_check_=now()+1800;set(Phase::Failed,unsigned(error));}
        catch(long error){next_check_=now()+1800;set(Phase::Failed,unsigned(error));}
        catch(int error){next_check_=now()+1800;set(Phase::Failed,unsigned(error));}
        catch(...){next_check_=now()+1800;set(Phase::Failed,ERROR_INVALID_DATA);}
    }
}
void Manager::check() {
    const auto body=get(options_.fetch,L"https://api.github.com/repos/Hubujiu/SCAU-Link/releases?per_page=20",metadata_limit,cancel_);
    // Malformed metadata is a failed check, never a claim that this is the latest build.
    const auto list=JsonArray::Parse(wide(body));if(list.Size()>20)throw ERROR_INVALID_DATA;
    const auto candidate=select_release(body,options_.current,options_.allow_preview);
    if(!candidate){next_check_=now()+21600;write(options_.directory/L"checked-at.txt",std::to_string(now()));set(Phase::Current);return;}
    const auto payload=get(options_.fetch,candidate->manifest_url,8192,cancel_);
    const auto signature=get(options_.fetch,candidate->signature_url,64,cancel_);
    auto manifest=verify_manifest(payload,signature,candidate->tag,options_.allow_preview,options_.public_key);
    if(!manifest||manifest->preview!=candidate->preview||!newer(*manifest,options_.current,options_.allow_preview))throw invalid_signature;
    if(manifest_&&parse_version(manifest_->version)>parse_version(manifest->version))throw ERROR_REVISION_MISMATCH;
    manifest_=std::move(manifest);payload_=payload;signature_=signature;
    live_.reset();impact_=Impact::MayDisconnect;
    if(!candidate->live_url.empty()||!candidate->live_signature_url.empty()) {
        if(candidate->live_url.empty()||candidate->live_signature_url.empty())throw invalid_signature;
        const auto live_payload=get(options_.fetch,candidate->live_url,8192,cancel_);
        const auto live_signature=get(options_.fetch,candidate->live_signature_url,64,cancel_);
        live_=verify_live_manifest(live_payload,live_signature,*manifest_,options_.public_key);
        if(!live_)throw invalid_signature;
        write(cache()/L"SCAU-Link-live.json",live_payload);write(cache()/L"SCAU-Link-live.sig",live_signature);
        if(live_compatible(options_.installation,*live_))impact_=Impact::PreserveConnection;
    }else {
        std::error_code ignored;std::filesystem::remove(cache()/L"SCAU-Link-live.json",ignored);
        std::filesystem::remove(cache()/L"SCAU-Link-live.sig",ignored);
    }
    write(cache()/L"SCAU-Link-update.json",payload_);write(cache()/L"SCAU-Link-update.sig",signature_);
    next_check_=now()+21600;write(options_.directory/L"checked-at.txt",std::to_string(now()));
    set(verify_installer(cache()/artifact().filename,artifact())?Phase::Ready:Phase::Available);
}
void Manager::download() {
    if(!manifest_)throw ERROR_INVALID_DATA;
    const auto item=artifact();
    const auto final=cache()/item.filename;auto temporary=final;temporary+=L".part";
    std::ofstream stream(temporary,std::ios::binary|std::ios::trunc);if(!stream)throw ERROR_WRITE_FAULT;
    std::uint64_t received=0;unsigned previous=101;
    const auto error=options_.fetch(item.url,static_cast<std::size_t>(item.size),[&](const void* data,std::size_t size) {
        if(cancel_||size>item.size-received)return false;
        if(!stream.write(static_cast<const char*>(data),static_cast<std::streamsize>(size)))return false;
        received+=size;const auto percentage=unsigned(received*100/item.size);
        if(percentage!=previous){previous=percentage;set(Phase::Downloading,0,percentage);}return true;
    },cancel_);
    stream.flush();const bool written=bool(stream);stream.close();
    if(error||!written||received!=item.size||!verify_installer(temporary,item)) {
        std::error_code ignored;std::filesystem::remove(temporary,ignored);
        throw error?error:invalid_signature;
    }
    if(!MoveFileExW(temporary.c_str(),final.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))throw GetLastError();
    set(Phase::Ready,0,100);
}
void Manager::install() {
    if(!manifest_)throw invalid_signature;
    if(impact_==Impact::PreserveConnection) {
        if(!live_||!live_compatible(options_.installation,*live_)) {
            impact_=Impact::MayDisconnect;set(Phase::Available);return;
        }
        apply_live_bundle(options_.installation,cache()/live_->bundle.filename,*live_,cancel_);
        set(Phase::Applied,0,100);return;
    }
    if(!verify_installer(cache()/manifest_->filename,*manifest_))throw invalid_signature;
    if(!start_install_helper(options_,*manifest_,cache(),cancel_))throw ERROR_INSTALL_FAILURE;
    set(Phase::InstallQueued);
}
} // namespace scau::desktop::updates
