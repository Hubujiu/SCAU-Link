#include "updates.hpp"
#include <bcrypt.h>
#include <fstream>
#include <vector>
#include <algorithm>

namespace scau::desktop::updates {
namespace {
struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    Handle()=default;explicit Handle(HANDLE h):value(h){}
    Handle(const Handle&)=delete;
    Handle(Handle&& other) noexcept:value(other.value){other.value=INVALID_HANDLE_VALUE;}
    ~Handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
};
bool plain(const std::filesystem::path& p,bool directory=false) {
    const auto flags=GetFileAttributesW(p.c_str());
    return flags!=INVALID_FILE_ATTRIBUTES && !(flags&FILE_ATTRIBUTE_REPARSE_POINT) &&
        bool(flags&FILE_ATTRIBUTE_DIRECTORY)==directory;
}
std::string digest(const std::filesystem::path& path,const std::string& expected) {
    Manifest item;item.size=std::filesystem::file_size(path);item.sha256=expected;
    return verify_installer(path,item)?expected:std::string{};
}
std::wstring random_name() {
    std::array<unsigned char,16> value{};
    if(BCryptGenRandom(nullptr,value.data(),DWORD(value.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw ERROR_GEN_FAILURE;
    std::wstring out=L".scau-live-";constexpr wchar_t hex[]=L"0123456789abcdef";
    for(auto byte:value){out+=hex[byte>>4];out+=hex[byte&15];}return out;
}
std::uint64_t integer(std::ifstream& in,unsigned bytes) {
    std::uint64_t value=0;
    for(unsigned i=0;i<bytes;++i){const int ch=in.get();if(ch<0)throw ERROR_INVALID_DATA;value|=std::uint64_t(ch)<<(i*8);}
    return value;
}
void move(const std::filesystem::path& from,const std::filesystem::path& to) {
    // Both paths stay on the installation volume. Never schedule a reboot or copy
    // over a mapped image; rename it and retain the old bytes for its live process.
    if(!MoveFileExW(from.c_str(),to.c_str(),MOVEFILE_WRITE_THROUGH))throw GetLastError();
}
void discard(const std::filesystem::path& work) noexcept {
    try {
        for(const auto* group:{L"old",L"new"}) {
            if(!plain(work/group,true)||(std::filesystem::exists(work/group/L"docs")&&!plain(work/group/L"docs",true)))continue;
            for(const auto* file:live_files) {
                const auto path=work/group/file;
                if(plain(path)){std::error_code error;std::filesystem::remove(path,error);}
            }
        }
        std::error_code ignored;
        for(const auto* group:{L"old/docs",L"new/docs",L"old",L"new"})std::filesystem::remove(work/group,ignored);
        if(!std::filesystem::exists(work/L"old")&&!std::filesystem::exists(work/L"new")) {
            std::filesystem::remove(work/L"committed.txt",ignored);std::filesystem::remove(work,ignored);
        }
    }catch(...){}
}
} // namespace
bool live_compatible(const std::filesystem::path& installation,const LiveManifest& manifest) {
    try {
        if(!plain(installation,true))return false;
        for(std::size_t i=0;i<protected_files.size();++i) {
            const auto file=installation/protected_files[i];
            if(!plain(file)||digest(file,manifest.protected_hashes[i]).empty())return false;
        }
        return true;
    }catch(...){return false;}
}
void apply_live_bundle(const std::filesystem::path& installation,const std::filesystem::path& bundle,
                       const LiveManifest& manifest,const std::atomic_bool& cancelled) {
    if(cancelled)throw ERROR_CANCELLED;
    if(!installation.is_absolute()||!live_compatible(installation,manifest))throw ERROR_REVISION_MISMATCH;
    std::wstring image(32768,0);const auto length=GetModuleFileNameW(nullptr,image.data(),DWORD(image.size()));image.resize(length);
    if(!length||!std::filesystem::equivalent(image,installation/L"SCAU-Link.exe"))throw ERROR_ACCESS_DENIED;
    if(!std::filesystem::exists(installation/L"docs"))std::filesystem::create_directory(installation/L"docs");
    if(!plain(installation/L"docs",true))throw ERROR_PATH_NOT_FOUND;
    // Lock the bundle and every protected file throughout the transaction. The
    // existing authentication process and its job/pipe handles are never touched.
    Handle source{CreateFileW(bundle.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr)};
    if(source.value==INVALID_HANDLE_VALUE||!verify_installer(bundle,manifest.bundle))throw invalid_signature;
    std::vector<Handle> protected_handles;
    for(const auto* name:protected_files) {
        Handle file{CreateFileW((installation/name).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr)};
        if(file.value==INVALID_HANDLE_VALUE)throw GetLastError();protected_handles.push_back(std::move(file));
    }
    if(!live_compatible(installation,manifest))throw ERROR_REVISION_MISMATCH;
    Handle transaction{CreateFileW((installation/L".scau-update.lock").c_str(),GENERIC_READ|GENERIC_WRITE,0,
        nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_HIDDEN,nullptr)};
    if(transaction.value==INVALID_HANDLE_VALUE)throw GetLastError();
    const auto work=installation/random_name();std::filesystem::create_directory(work);
    const auto incoming=work/L"new",backup=work/L"old";
    std::filesystem::create_directories(incoming/L"docs");std::filesystem::create_directories(backup/L"docs");
    std::array<bool,6> saved{},installed{};
    try {
        std::ifstream input(bundle,std::ios::binary);char magic[8]{};input.read(magic,8);
        if(std::string_view(magic,8)!="SCAULIV1"||integer(input,4)!=live_files.size())throw ERROR_INVALID_DATA;
        std::array<char,65536> buffer{};
        std::uint64_t total=12;
        for(const auto* name:live_files) {
            const auto name_size=integer(input,2),size=integer(input,8);
            std::string expected;for(wchar_t ch:std::wstring_view(name))expected+=static_cast<char>(ch);
            if(name_size!=expected.size()||size<1||size>maximum_installer_size||total>manifest.bundle.size||
               name_size+10>manifest.bundle.size-total||size>manifest.bundle.size-total-name_size-10)throw ERROR_INVALID_DATA;
            std::string actual(static_cast<std::size_t>(name_size),0);input.read(actual.data(),actual.size());
            if(actual!=expected)throw ERROR_INVALID_DATA;
            std::ofstream output(incoming/name,std::ios::binary);
            std::uint64_t left=size;
            while(left) {
                if(cancelled)throw ERROR_CANCELLED;
                const auto count=static_cast<std::streamsize>(std::min<std::uint64_t>(left,buffer.size()));
                if(!input.read(buffer.data(),count)||!output.write(buffer.data(),count))throw ERROR_WRITE_FAULT;
                left-=count;
            }
            if(!output.flush())throw ERROR_WRITE_FAULT;
            total+=10+name_size+size;
        }
        if(total!=manifest.bundle.size||input.peek()!=EOF)throw ERROR_INVALID_DATA;
        // Preflight all destination paths before changing any file. In particular,
        // neither the capsule nor its paths can name credentials or the core.
        for(const auto* name:live_files) {
            const auto target=installation/name;
            if(std::filesystem::exists(target)&&!plain(target))throw ERROR_ACCESS_DENIED;
        }
        if(cancelled)throw ERROR_CANCELLED;
        for(std::size_t i=0;i<live_files.size();++i) {
            const auto* name=live_files[i];
            if(std::filesystem::exists(installation/name)){move(installation/name,backup/name);saved[i]=true;}
            move(incoming/name,installation/name);installed[i]=true;
        }
        std::ofstream receipt(work/L"committed.txt",std::ios::binary);
        receipt<<"SCAULIV1\n";receipt.close();
        if(!receipt)throw ERROR_WRITE_FAULT;
        // Backups deliberately remain until the next launch; the previous desktop
        // executable may still be mapped. No parent/worker restart is performed.
    } catch(...) {
        bool restored=true;
        for(std::size_t i=live_files.size();i--;) {
            const auto* name=live_files[i];
            if(installed[i]) {
                std::error_code error;std::filesystem::remove(installation/name,error);
                if(error){restored=false;continue;}
            }
            if(saved[i]&&!MoveFileExW((backup/name).c_str(),(installation/name).c_str(),MOVEFILE_WRITE_THROUGH))restored=false;
        }
        if(!restored)throw ERROR_RECOVERY_FAILURE;
        discard(work);
        throw;
    }
}
void cleanup_live_backups(const std::filesystem::path& installation) {
    // Only a successfully committed, bounded transaction is removed. Never follow
    // reparse points or recursively delete an installation directory.
    try {
        for(const auto& entry:std::filesystem::directory_iterator(installation)) {
            const auto name=entry.path().filename().native();
            if(name.size()!=43||!name.starts_with(L".scau-live-")||
               !std::all_of(name.begin()+11,name.end(),[](wchar_t ch){return (ch>=L'0'&&ch<=L'9')||(ch>=L'a'&&ch<=L'f');})||
               !plain(entry.path(),true)||!plain(entry.path()/L"committed.txt"))continue;
            bool safe=true;
            for(const auto* part:{L"old",L"old/docs",L"new",L"new/docs"})
                if(std::filesystem::exists(entry.path()/part)&&!plain(entry.path()/part,true))safe=false;
            if(!safe)continue;
            discard(entry.path());
        }
    }catch(...){}
}
} // namespace scau::desktop::updates
