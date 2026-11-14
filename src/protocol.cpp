#include "protocol.hpp"
#include "profile_store.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>

extern "C" {
#include "checkV4.h"
// Required by the reference password transform; implemented with Windows CNG.
unsigned char* ComputeHash(unsigned char* source, unsigned int length) {
    static thread_local scau::Digest result;
    result = scau::md5({source, length});
    return result.data();
}
}

namespace scau {
namespace {
constexpr std::array<Byte, 4> vendor{0, 0, 0x13, 0x11};
std::uint16_t be16(std::span<const Byte> data, std::size_t offset) {
    if (offset + 2 > data.size()) throw std::runtime_error("Truncated 16-bit field");
    return (std::uint16_t(data[offset]) << 8) | data[offset + 1];
}
std::uint32_t le32(std::span<const Byte> data, std::size_t offset) {
    if (offset + 4 > data.size()) throw std::runtime_error("Truncated 32-bit field");
    return std::uint32_t(data[offset]) | (std::uint32_t(data[offset+1]) << 8) |
           (std::uint32_t(data[offset+2]) << 16) | (std::uint32_t(data[offset+3]) << 24);
}
void append(Bytes& output, std::span<const Byte> data) { output.insert(output.end(), data.begin(), data.end()); }
void put16(Bytes& output, std::size_t offset, std::size_t value) {
    if (offset+2 > output.size() || value > 65535) throw std::runtime_error("Invalid output field length");
    output[offset] = Byte(value >> 8); output[offset+1] = Byte(value);
}
void property(Bytes& output, Byte type, std::span<const Byte> value) {
    if (value.size() > 247) throw std::runtime_error("Vendor property too large");
    output.push_back(0x1a); output.push_back(Byte(value.size()+8)); append(output, vendor);
    output.push_back(type); output.push_back(Byte(value.size()+2)); append(output, value);
}
}

Digest md5(std::span<const Byte> data) {
    Digest output{};
    const auto status = BCryptHash(BCRYPT_MD5_ALG_HANDLE, nullptr, 0,
        const_cast<PUCHAR>(data.data()), ULONG(data.size()), output.data(), ULONG(output.size()));
    if (status < 0) throw std::runtime_error("Windows CNG MD5 failed");
    return output;
}
Digest md5_response(Byte identifier, std::string_view password, std::span<const Byte> challenge) {
    if (password.size() > 256 || challenge.size() != 16) throw std::runtime_error("Invalid MD5 input length");
    Bytes input{identifier};
    input.insert(input.end(), password.begin(), password.end()); append(input, challenge);
    const auto output = md5(input); SecureZeroMemory(input.data(), input.size()); return output;
}
std::uint16_t crc16(std::span<const Byte> data) {
    std::uint16_t value=0;
    for (const auto byte : data) {
        value ^= std::uint16_t(byte) << 8;
        for (int bit=0; bit<8; ++bit) value = (value & 0x8000) ? std::uint16_t((value << 1)^0x1021) : std::uint16_t(value << 1);
    }
    return value;
}
void encode_network(std::span<Byte> data) {
    for (auto& byte : data) {
        unsigned value=byte, reversed=0;
        for (int bit=0; bit<8; ++bit) { reversed=(reversed<<1)|(value&1); value>>=1; }
        byte = Byte(~reversed);
    }
}
Frame parse_frame(std::span<const Byte> packet) {
    if (packet.size()<18) throw std::runtime_error("Truncated Ethernet/EAPOL frame");
    Frame frame; std::copy_n(packet.begin(),6,frame.destination.begin()); std::copy_n(packet.begin()+6,6,frame.source.begin());
    auto protocol=be16(packet,12); std::size_t offset=14;
    while (protocol==0x8100 || protocol==0x88a8 || protocol==0x9100) { protocol=be16(packet,offset+2); offset+=4; }
    if (protocol!=0x888e || offset+4>packet.size()) throw std::runtime_error("Not an EAPOL frame");
    frame.version=packet[offset]; frame.type=packet[offset+1];
    const auto length=be16(packet,offset+2);
    if (offset+4+length>packet.size()) throw std::runtime_error("EAPOL payload exceeds captured frame");
    frame.eap=packet.subspan(offset+4,length); frame.trailing=packet.subspan(offset+4+length);
    if (frame.type==0) {
        if (frame.eap.size()<4) throw std::runtime_error("Missing EAP header");
        frame.code=frame.eap[0]; frame.identifier=frame.eap[1];
        const auto eap_length=be16(frame.eap,2);
        if (eap_length<4 || eap_length>frame.eap.size()) throw std::runtime_error("Invalid EAP length");
        if (frame.code==1 || frame.code==2) {
            if (eap_length<5) throw std::runtime_error("Missing EAP method");
            frame.method=frame.eap[4];
            if (frame.method==4 && (eap_length<6 || frame.eap[5]>eap_length-6)) throw std::runtime_error("Truncated MD5 challenge");
        }
    }
    return frame;
}
std::vector<Property> parse_client_properties(std::span<const Byte> tail) {
    if (tail.size()<70 || !std::equal(vendor.begin(),vendor.end(),tail.begin()+23)) throw std::runtime_error("Missing Ruijie trailer header");
    if (be16(tail,68)!=tail.size()-70) throw std::runtime_error("Invalid Ruijie property area length");
    std::vector<Property> output;
    for (std::size_t offset=70;offset<tail.size();) {
        if (offset+8>tail.size() || tail[offset]!=0x1a || !std::equal(vendor.begin(),vendor.end(),tail.begin()+offset+2)) throw std::runtime_error("Invalid vendor property header");
        const auto length=tail[offset+1];
        if (length<8 || offset+length>tail.size() || tail[offset+7]<2 || tail[offset+7]+6!=length) throw std::runtime_error("Invalid vendor property boundary");
        output.push_back({tail[offset+6], Bytes(tail.begin()+offset+8,tail.begin()+offset+length)}); offset+=length;
    }
    return output;
}
Profile load_profile(const std::filesystem::path& path) {
    const auto size=std::filesystem::file_size(path);
    if (size>1024*1024) throw std::runtime_error("Use the small eapol-only.pcapng profile, maximum 1 MiB");
    std::ifstream input(path,std::ios::binary); Bytes data(std::size_t(size),0); input.read(reinterpret_cast<char*>(data.data()),data.size());
    if(input && data.size()>=native_profile_magic.size() && std::equal(native_profile_magic.begin(),native_profile_magic.end(),data.begin()))return load_native_profile(data);
    if (!input || size<28 || le32(data,0)!=0x0a0d0d0a || le32(data,8)!=0x1a2b3c4d) throw std::runtime_error("Expected a little-endian PCAPNG profile");
    for (std::size_t offset=0;offset<data.size();) {
        const auto kind=le32(data,offset), length=le32(data,offset+4);
        if (length<12 || length%4 || offset+length>data.size() || le32(data,offset+length-4)!=length) throw std::runtime_error("Invalid PCAPNG block");
        if (kind==6 && length>=32) {
            const auto captured=le32(data,offset+20);
            if (captured>length-32) throw std::runtime_error("Invalid captured packet length");
            auto frame=parse_frame(std::span(data).subspan(offset+28,captured));
            if (frame.code==2 && frame.method==1) {
                Profile profile; profile.local=frame.source; profile.server=frame.destination;
                if (frame.trailing.size()<70) throw std::runtime_error("Missing captured client metadata");
                std::copy_n(frame.trailing.begin(),23,profile.network.begin()); encode_network(profile.network);
                if (!std::equal(vendor.begin(),vendor.end(),profile.network.begin()) || crc16(std::span(profile.network).first(21))!=be16(profile.network,21)) throw std::runtime_error("Captured network header CRC is invalid");
                profile.username.assign(reinterpret_cast<const char*>(frame.eap.data()+5),frame.eap.size()-5);
                for (auto& prop:parse_client_properties(frame.trailing)) {
                    if (prop.type==0x39) profile.service=prop.value;
                    if (prop.type==0x54) profile.device_id=prop.value;
                    SecureZeroMemory(prop.value.data(),prop.value.size());
                }
                SecureZeroMemory(data.data(),data.size());
                if (profile.service.size()!=32 || profile.device_id.size()!=64) throw std::runtime_error("Missing SCAU service/device profile");
                return profile;
            }
        }
        offset+=length;
    }
    throw std::runtime_error("Identity response was not found in the profile");
}
Bytes legacy_trailer(const Profile& profile,std::string_view user,std::string_view password,std::span<const Byte> challenge,bool phase) {
    if (user.empty() || user.size()>256 || password.size()>256 || (phase && challenge.size()!=16)) throw std::runtime_error("Invalid credential/challenge length");
    std::array<Byte,16> seed{}; if (phase) std::copy(challenge.begin(),challenge.end(),seed.begin());
    Bytes output(profile.network.begin(),profile.network.end()); encode_network(output); append(output,vendor);
    std::array<Byte,32> program{}; std::memcpy(program.data(),"8021x.exe",9); append(output,program);
    append(output,std::array<Byte,4>{1,31,1,2});
    output.push_back(0); append(output,vendor); output.push_back(0); output.push_back(0);
    Bytes props;
    property(props,0x18,std::array<Byte,4>{0,0,0,1}); property(props,0x2d,profile.local);
    if (phase) {
        const auto user_string=std::string(user), password_string=std::string(password);
        const auto hash=computePwd(seed.data(),user_string.c_str(),password_string.c_str());
        property(props,0x2f,{reinterpret_cast<const Byte*>(hash),16});
    } else property(props,0x2f,{});
    property(props,0x76,{}); property(props,0x35,std::array<Byte,1>{0});
    const std::array<Byte,16> zero{};
    property(props,0x36,zero); property(props,0x38,zero); property(props,0x4e,zero);
    property(props,0x4d,{computeV4(seed.data(),16),128}); property(props,0x39,profile.service);
    property(props,0x54,profile.device_id); property(props,0x55,{}); property(props,0x62,std::array<Byte,1>{0});
    property(props,0x70,std::array<Byte,1>{sizeof(void*)==8?Byte(64):Byte(32)});
    const std::string version="RG-SU For Windows V1.31"; Bytes version_bytes(version.begin(),version.end()); version_bytes.push_back(0);
    property(props,0x6f,version_bytes); put16(output,68,props.size()); append(output,props); return output;
}
Bytes make_simple(const Mac& local,const Mac& remote,Byte type) {
    Bytes frame; append(frame,remote); append(frame,local); append(frame,std::array<Byte,6>{0x88,0x8e,1,type,0,0}); return frame;
}
bool unicast_mac(const Mac& address) noexcept {
    return !(address[0] & 1) && std::any_of(address.begin(), address.end(), [](Byte ch) { return ch != 0; });
}
std::optional<Bytes> initial_logoff(const Profile& profile, bool recovering) {
    if (recovering || !unicast_mac(profile.server)) return {};
    return make_simple(profile.local, profile.server, 2);
}
Bytes make_response(const Profile& profile,const Mac& server,Byte identifier,std::string_view user,std::string_view password,std::span<const Byte> challenge,bool phase) {
    auto frame=make_simple(profile.local,server,0);
    frame.insert(frame.end(),{2,identifier,0,0,phase?Byte(4):Byte(1)});
    if (phase) { frame.push_back(16); const auto digest=md5_response(identifier,password,challenge); append(frame,digest); }
    frame.insert(frame.end(),user.begin(),user.end()); const auto length=frame.size()-18;
    put16(frame,16,length); put16(frame,20,length); append(frame,legacy_trailer(profile,user,password,challenge,phase)); return frame;
}
}
