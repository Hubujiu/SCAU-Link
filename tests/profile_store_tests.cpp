#include "profile_store.hpp"
#include <windows.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace scau;
void require(bool value,const char* why){if(!value)throw std::runtime_error(why);}
int main(){try{
    wchar_t temporary[MAX_PATH]{};GetTempPathW(MAX_PATH,temporary);const auto file=std::filesystem::path(temporary)/(L"scau-profile-test-"+std::to_wstring(GetCurrentProcessId())+L".scau");
    struct Cleanup {std::filesystem::path path;~Cleanup(){std::error_code e;std::filesystem::remove(path,e);path+=L".tmp";std::filesystem::remove(path,e);}} cleanup{file};
    Profile source;source.local={2,0,0,0,0,1};source.server={2,0,0,0,0,2};source.username="MUST-NOT-PERSIST";source.network[2]=0x13;source.network[3]=0x11;std::fill(source.network.begin()+5,source.network.begin()+21,Byte{77});source.service.resize(32);source.device_id.resize(64,42);
    save_native_profile(file,source);auto result=load_profile(file);
    require(result.username.empty(),"Native profile must not persist an account");require(result.local==source.local&&result.server==source.server&&result.device_id==source.device_id,"Required non-secret protocol fields must round trip");
    require(std::all_of(result.network.begin()+5,result.network.begin()+21,[](Byte b){return b==0;}),"Live network addresses must not be persisted from a capture");
    std::ifstream input(file,std::ios::binary);Bytes bytes((std::istreambuf_iterator<char>(input)),{});require(bytes.size()==141,"Native profile must have a bounded fixed size");
    require(std::search(bytes.begin(),bytes.end(),source.username.begin(),source.username.end())==bytes.end(),"Account may not occur in profile bytes");
    bytes[30]^=1;bool refused=false;try{(void)load_native_profile(bytes);}catch(const std::exception&){refused=true;}require(refused,"Corrupt profiles must be rejected");
    refused=false;try{(void)load_native_profile(std::span(bytes).first(30));}catch(const std::exception&){refused=true;}require(refused,"Truncated profiles must be rejected");
    std::cout<<"PASS: credential-free native profile, live-address reset, bounded parsing and corruption rejection\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
