#include "maintenance.hpp"
#include <algorithm>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace {
using namespace scau;
constexpr Mac local{2,0,0,0,0,1}, peer{2,0,0,0,0,2};
constexpr std::array<Byte,4> vendor{0,0,0x13,0x11};

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void append_vendor(Bytes& output) { output.insert(output.end(),vendor.begin(),vendor.end()); }
void append32(Bytes& output, std::uint32_t value) {
    output.insert(output.end(),{Byte(value>>24),Byte(value>>16),Byte(value>>8),Byte(value)});
}
void put16(Bytes& output, std::size_t offset, std::size_t value) {
    output[offset]=Byte(value>>8); output[offset+1]=Byte(value);
}
Byte encode(Byte value) {
    unsigned reversed=0;
    for (unsigned bit=0;bit!=8;++bit) { reversed=(reversed<<1)|(value&1u); value=Byte(value>>1); }
    return Byte(~reversed);
}
Bytes prefix(std::size_t message_length, Byte extra_records, bool enabled,
             std::uint32_t key, std::uint32_t interval) {
    Bytes result;
    append_vendor(result);
    result.push_back(Byte(message_length>>8)); result.push_back(Byte(message_length));
    // Decoy vendor bytes in the variable message must never become properties.
    for (std::size_t i=0;i<message_length;++i) result.push_back(vendor[i%vendor.size()]);
    const auto information_offset=result.size();
    result.resize(result.size()+111);
    std::copy(vendor.begin(),vendor.end(),result.begin()+information_offset);
    result[information_offset+4]=0x69;
    result[information_offset+110]=extra_records;
    result.insert(result.end(),std::size_t(extra_records)*32,0x5a);
    for (unsigned i=0;i!=2;++i) { append_vendor(result); result.push_back(1); result.push_back(0); }
    Bytes echo(vendor.begin(),vendor.end());
    echo.push_back(10); echo.push_back(enabled?1:0);
    append32(echo,key); append32(echo,interval); echo.push_back(0);
    std::transform(echo.begin(),echo.end(),echo.begin(),encode);
    result.insert(result.end(),echo.begin(),echo.end());
    return result;
}
void property(Bytes& output, Byte type, std::span<const Byte> value) {
    append_vendor(output); output.push_back(type); output.push_back(Byte(value.size()+2));
    output.insert(output.end(),value.begin(),value.end());
}
void property32(Bytes& output, Byte type, std::uint32_t value) {
    Bytes data; append32(data,value); property(output,type,data);
}
Bytes success(const Bytes& extension) {
    Bytes result;
    result.insert(result.end(),local.begin(),local.end());
    result.insert(result.end(),peer.begin(),peer.end());
    result.insert(result.end(),{0x88,0x8e,1,0,0,0,3,7,0,0});
    result.insert(result.end(),extension.begin(),extension.end());
    put16(result,16,result.size()-18); put16(result,20,result.size()-18);
    return result;
}
template<class Function> void rejects(Function&& action, const char* message) {
    bool rejected=false;
    try { action(); } catch (const std::runtime_error&) { rejected=true; }
    require(rejected,message);
}
Bytes unhex(std::string_view text) {
    Bytes result;
    auto digit=[](char c)->Byte { return Byte(c<='9'?c-'0':c-'a'+10); };
    for (std::size_t i=0;i<text.size();i+=2) result.push_back(Byte((digit(text[i])<<4)|digit(text[i+1])));
    return result;
}
}

int main() {
    using namespace scau;
    try {
        auto extension=prefix(53,2,true,0x01020304,20);
        property32(extension,0x56,2);
        property32(extension,0x59,45);
        property32(extension,0x5b,0xc0000201); // Documentation address, never a real server.
        const std::array<Byte,1> version{2}; property(extension,0x79,version);
        property32(extension,0x80,0);
        auto parameters=parse_success_maintenance(success(extension));
        require(parameters.vendor_parameters_present && parameters.echo_enabled && parameters.echo_key==0x01020304,
                "Dynamic server message and record lengths must locate the echo parameters");
        require(parameters.echo_interval_seconds==20 && parameters.reauth_interval_seconds==120,
                "Echo seconds and reauthentication minutes have distinct units");
        require(parameters.sam_hello_interval_seconds==45 && parameters.sam_server_advertised,
                "SAM interval and server advertisement must parse");
        require(parameters.echo_capability()==MaintenanceCapability::supported && parameters.direct_heartbeat_flags==0,
                "Direct communication flags zero must not disable separately enabled EAPOL echo");
        require(parameters.sam_hello_capability()==MaintenanceCapability::unsupported,
                "A SAM endpoint missing its port, key and time is not operational");

        auto sam_extension=prefix(0,0,false,0,20);
        property32(sam_extension,0x5a,1812);property32(sam_extension,0x5b,0xc0000201);
        const std::array<Byte,8> wrapped_key{},wrapped_iv{0,1,2,3,4,5,6,7},utc{1,2,3,4,5,6,7,8};
        property(sam_extension,0x5c,wrapped_key);property(sam_extension,0x5d,wrapped_iv);property(sam_extension,0x5e,utc);
        property(sam_extension,0x79,version);
        auto sam_parameters=parse_success_maintenance(success(sam_extension));
        const auto key_oracle=unhex("12e8fcd8a2942973"),iv_oracle=unhex("12e9fedba6912f74");
        require(std::equal(key_oracle.begin(),key_oracle.end(),sam_parameters.sam_key.begin()) &&
                std::equal(iv_oracle.begin(),iv_oracle.end(),sam_parameters.sam_iv.begin()),
                "SAM key and IV each use a fresh RC4 wrapping context");
        require(sam_parameters.sam_server_port==1812 && sam_parameters.sam_client_port==80 &&
                sam_parameters.sam_server_utc==0x0102030405060708ull &&
                sam_parameters.sam_server_ipv4==std::array<Byte,4>{192,0,2,1},
                "SAM wire integers are big endian and client port defaults to 80");
        require(sam_parameters.sam_capability()==MaintenanceCapability::supported &&
                sam_parameters.sam_hello_capability()==MaintenanceCapability::disabled,
                "HELLO zero still enables authenticated incoming SAM messages");
        property32(sam_extension,0x59,30);property32(sam_extension,0x6e,8080);property32(sam_extension,0x80,1);
        sam_parameters=parse_success_maintenance(success(sam_extension));
        require(sam_parameters.sam_hello_capability()==MaintenanceCapability::supported &&
                sam_parameters.sam_client_port==8080 && sam_parameters.direct_heartbeat_flags==1,
                "Full SAM and integrity parameters must not remain unsupported");
        auto invalid_sam=sam_parameters;
        invalid_sam.sam_server_port=65536;
        require(invalid_sam.sam_capability()==MaintenanceCapability::unsupported,"Out-of-range SAM port rejected");
        invalid_sam=sam_parameters;invalid_sam.sam_client_port=0;
        require(invalid_sam.sam_capability()==MaintenanceCapability::unsupported,"Zero client port rejected");
        invalid_sam=sam_parameters;invalid_sam.sam_server_ipv4[0]=224;
        require(invalid_sam.sam_capability()==MaintenanceCapability::unsupported,"Multicast SAM peer rejected");
        invalid_sam=sam_parameters;invalid_sam.direct_communication_version=0;
        require(invalid_sam.sam_capability()==MaintenanceCapability::unsupported,"SAM version zero rejected");
        invalid_sam=sam_parameters;invalid_sam.direct_communication_version=255;
        require(invalid_sam.sam_capability()==MaintenanceCapability::supported,"Versions above two retain original clamp-to-two semantics");
        invalid_sam=sam_parameters;invalid_sam.sam_server_utc=UINT64_MAX;
        require(invalid_sam.sam_capability()==MaintenanceCapability::unsupported,"Exhausted SAM counter rejected");

        auto disabled=prefix(7,0,false,0xabcdef01,20);
        property32(disabled,0x56,0);
        parameters=parse_success_maintenance(success(disabled));
        require(!parameters.echo_enabled && parameters.echo_key==0 && parameters.reauth_interval_seconds==0 &&
                parameters.sam_hello_interval_seconds==0 && !parameters.sam_server_advertised,
                "A new disabled Success must replace all prior session maintenance parameters");
        require(parameters.echo_interval_seconds==20 && parameters.echo_capability()==MaintenanceCapability::disabled,
                "A nonzero echo interval alone must not start echo transmission");
        parameters=parse_success_maintenance(success({}));
        require(!parameters.vendor_parameters_present && !parameters.echo_enabled && parameters.echo_key==0 &&
                parameters.echo_interval_seconds==0 && parameters.reauth_interval_seconds==0 &&
                parameters.sam_hello_capability()==MaintenanceCapability::disabled &&
                !parameters.sam_key_present && !parameters.sam_iv_present && !parameters.sam_time_present &&
                std::all_of(parameters.sam_key.begin(),parameters.sam_key.end(),[](Byte b){return b==0;}),
                "Plain EAP Success must yield fresh disabled parameters");

        auto zero_interval=prefix(0,0,true,1,0);
        require(parse_success_maintenance(success(zero_interval)).echo_capability()==MaintenanceCapability::unsupported,
                "Enabled echo without a usable interval must not appear operational");

        const auto complete_prefix=success(prefix(11,1,true,0x01020304,20));
        for (std::size_t length=0;length<complete_prefix.size();++length) {
            if (length==22) continue; // A plain four-byte Success is valid.
            auto truncated=complete_prefix;
            truncated.resize(length);
            if (length>=22) { put16(truncated,16,length-18); put16(truncated,20,length-18); }
            rejects([&]{parse_success_maintenance(truncated);},"Truncated legacy prefix must be rejected at every boundary");
        }
        auto bad=success(disabled); put16(bad,16,65535);
        rejects([&]{parse_success_maintenance(bad);},"Oversized outer EAPOL length must be rejected");
        bad=success(disabled); put16(bad,20,65535);
        rejects([&]{parse_success_maintenance(bad);},"Oversized inner EAP length must be rejected");
        bad=success(disabled); bad[18]=4;
        rejects([&]{parse_success_maintenance(bad);},"Failure cannot be interpreted as Success parameters");
        auto malformed=prefix(0,0,false,0,20);
        append_vendor(malformed); malformed.push_back(0x56); malformed.push_back(1);
        rejects([&]{parse_success_maintenance(success(malformed));},"Property lengths below two must be rejected");
        malformed=prefix(0,0,false,0,20);
        const std::array<Byte,3> short_integer{0,0,1}; property(malformed,0x59,short_integer);
        rejects([&]{parse_success_maintenance(success(malformed));},"Known integer properties require exactly four bytes");
        for(const auto type:std::array<Byte,3>{0x5c,0x5d,0x5e}) {
            for(const std::size_t length:{7u,9u}) {
                malformed=prefix(0,0,false,0,20);property(malformed,type,Bytes(length));
                rejects([&]{parse_success_maintenance(success(malformed));},"SAM session material must have exactly eight bytes");
            }
        }
        malformed=prefix(0,0,false,0,20); property32(malformed,0x56,std::numeric_limits<std::uint32_t>::max()/60+1);
        rejects([&]{parse_success_maintenance(success(malformed));},"Reauthentication conversion must reject overflow");
        auto limit=prefix(0,0,false,0,20); property32(limit,0x56,std::numeric_limits<std::uint32_t>::max()/60);
        require(parse_success_maintenance(success(limit)).reauth_interval_seconds==4294967280u,
                "Largest representable reauthentication interval must remain exact");
        auto padded=success({}); padded.insert(padded.end(),extension.begin(),extension.end());
        require(!parse_success_maintenance(padded).echo_enabled,"Ethernet trailing data must not extend the declared EAP packet");
        auto tagged=success(disabled); tagged.insert(tagged.begin()+12,{0x81,0,0,1});
        require(parse_success_maintenance(tagged).vendor_parameters_present,"VLAN tags must preserve the EAP payload boundary");

        // These fixtures were independently produced by offline Unicorn execution
        // of the original client's pure builder. Every input is synthetic.
        require(make_echo(local,peer,0x01020304,0x11223344)==unhex(
            "020000000002020000000001888e01bf001effff37777f9fb7db93edffff37777f9f77bb33ddffff37777f3fff"),
            "Echo bytes must match the original pure builder oracle");
        require(make_echo(local,peer,0x01020304,0x11223344,0x475)==unhex(
            "020000000002020000000001888e01bf001effff37777f9fb7db93edffff37777f9f77bb333dffff37777f3fff"),
            "Nondefault ring adjustment must match the original builder");
        require(make_echo(local,peer,0xffffffff,0xffffffff,0x473)==unhex(
            "020000000002020000000001888e01bf001effff37777f9f00000080ffff37777f9fffffffffffff37777f3fff"),
            "Echo arithmetic must wrap at 32 bits exactly");
        const auto echo=make_echo(local,peer,0,0);
        require(echo.size()==45 && echo[16]==0 && echo[17]==30 && echo.size()-18==27,
                "Legacy echo advertised length and transmitted length intentionally differ");
        std::cout<<"PASS: maintenance negotiation, disabled modes, bounds, units, and offline echo oracle\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
