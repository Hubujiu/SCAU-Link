#include "profile_store.hpp"
#include <windows.h>
#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace scau {
Profile load_native_profile(std::span<const Byte> bytes) {
    constexpr std::size_t size=8+6+6+23+32+64+2;
    if(bytes.size()!=size || !std::equal(native_profile_magic.begin(),native_profile_magic.end(),bytes.begin()) ||
       crc16(bytes.first(size-2))!=((unsigned(bytes[size-2])<<8)|bytes[size-1]))
        throw std::runtime_error("Invalid native authentication profile");
    Profile profile;std::size_t offset=8;
    auto copy=[&](auto& target){std::copy_n(bytes.begin()+offset,target.size(),target.begin());offset+=target.size();};
    copy(profile.local);copy(profile.server);copy(profile.network);
    profile.service.resize(32);copy(profile.service);profile.device_id.resize(64);copy(profile.device_id);
    if(profile.network[0]!=0 || profile.network[1]!=0 || profile.network[2]!=0x13 || profile.network[3]!=0x11 ||
       crc16(std::span(profile.network).first(21))!=((unsigned(profile.network[21])<<8)|profile.network[22]))
        throw std::runtime_error("Invalid native profile network header");
    return profile;
}
void save_native_profile(const std::filesystem::path& path,const Profile& profile) {
    if(profile.service.size()!=32 || profile.device_id.size()!=64)throw std::runtime_error("Invalid service/device profile");
    Bytes bytes(native_profile_magic.begin(),native_profile_magic.end());
    auto append=[&](const auto& value){bytes.insert(bytes.end(),value.begin(),value.end());};
    append(profile.local);append(profile.server);
    auto network=profile.network;std::fill(network.begin()+5,network.begin()+21,Byte{});
    const auto header_crc=crc16(std::span(network).first(21));network[21]=Byte(header_crc>>8);network[22]=Byte(header_crc);
    append(network);append(profile.service);append(profile.device_id);
    const auto crc=crc16(bytes);bytes.push_back(Byte(crc>>8));bytes.push_back(Byte(crc));
    (void)load_native_profile(bytes);
    auto temporary=path;temporary+=L".tmp";
    std::ofstream output(temporary,std::ios::binary|std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));output.close();
    if(!output || !MoveFileExW(temporary.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("Cannot save native authentication profile");
}
}
