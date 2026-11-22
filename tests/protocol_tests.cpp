#include "protocol.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>

void require(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
int main() {
    using namespace scau;
    try {
        const auto empty=md5({});
        require(empty==Digest{0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e},"MD5 RFC test vector");
        const std::string crc_input="123456789";
        require(crc16({reinterpret_cast<const Byte*>(crc_input.data()),crc_input.size()})==0x31c3,"CRC16/XMODEM vector");
        Profile profile; profile.local={2,0,0,0,0,1};profile.server={2,0,0,0,0,2};
        profile.network[2]=0x13;profile.network[3]=0x11;profile.network[4]=1;
        auto checksum=crc16(std::span(profile.network).first(21)); profile.network[21]=Byte(checksum>>8);profile.network[22]=Byte(checksum);
        profile.service.resize(32);profile.device_id.resize(64);
        const auto original=profile.network;encode_network(profile.network);encode_network(profile.network);
        require(original==profile.network,"Network encoding must be involutive");
        const std::array<Byte,16> seed{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        auto identity=make_response(profile,profile.server,1,"test-user","test-password",{},false);
        auto challenge=make_response(profile,profile.server,2,"test-user","test-password",seed,true);
        const auto id=parse_frame(identity),md=parse_frame(challenge);
        require(id.method==1 && id.identifier==1 && md.method==4 && md.identifier==2,"EAP response identifiers");
        const auto digest=md5_response(2,"test-password",seed);
        require(digest==Digest{0x41,0xdf,0x03,0x5e,0x2d,0x37,0xb0,0xcf,0x6f,0x03,0x76,0xe9,0x63,0x77,0x43,0xd3},"Independent standard MD5 response vector");
        require(std::equal(digest.begin(),digest.end(),md.eap.begin()+6),"MD5 response encoding");
        require(!parse_client_properties(id.trailing).empty(),"Legacy identity trailer must parse");
        require(!parse_client_properties(md.trailing).empty(),"Legacy challenge trailer must parse");
        const auto attributes=parse_client_properties(md.trailing);
        const auto pwd=std::find_if(attributes.begin(),attributes.end(),[](const auto& p){return p.type==0x2f;});
        require(pwd!=attributes.end() && pwd->value==Bytes{0x73,0xac,0xef,0x08,0xbe,0xd8,0xa1,0xbd,0xa5,0x3d,0x8f,0xf7,0x9e,0x49,0xe3,0xa9},"Independent private password-transform vector");
        const auto identity_attributes=parse_client_properties(id.trailing);
        const auto validation=std::find_if(identity_attributes.begin(),identity_attributes.end(),[](const auto& p){return p.type==0x4d;});
        const std::string golden_v4="b464896d8135ee1da7dd2926bcbb65ae4eb77df681012a8e52ce8bf566125194ed197bcfda8f729f582a1d330d5f03ba48245a8325f1215ebbe4cf9c1ca25b0b";
        require(validation!=identity_attributes.end() && std::string(validation->value.begin(),validation->value.end())==golden_v4,"Public V4 cross-compiler vector");
        for(std::size_t size=0;size<18;++size) {
            try {parse_frame(std::span(identity).first(size));throw std::logic_error("Accepted a truncated frame");}
            catch(const std::runtime_error&) {}
        }
        auto corrupt=challenge;corrupt[16]=255;corrupt[17]=255;
        bool rejected=false;try{parse_frame(corrupt);}catch(const std::runtime_error&){rejected=true;}
        require(rejected,"Oversized EAPOL length must be rejected");
        auto tagged=challenge;
        tagged.insert(tagged.begin()+12,{0x88,0xa8,0,1,0x81,0,0,2});
        const auto vlan=parse_frame(tagged);
        require(vlan.source==md.source && vlan.destination==md.destination && vlan.method==4 &&
                std::equal(vlan.eap.begin(),vlan.eap.end(),md.eap.begin(),md.eap.end()) &&
                std::equal(vlan.trailing.begin(),vlan.trailing.end(),md.trailing.begin(),md.trailing.end()),
                "Stacked VLAN tags preserve borrowed EAP and trailer boundaries");
        const auto reject_frame=[](std::span<const Byte> packet) {
            try { parse_frame(packet); } catch(const std::runtime_error&) { return true; }
            return false;
        };
        require(reject_frame(std::span(tagged).first(21)),"Reject a truncated inner VLAN tag");
        tagged[31]=0xff;
        require(reject_frame(tagged),"Reject challenge size beyond the declared EAP length");
        auto tail=Bytes(id.trailing.begin(),id.trailing.end());tail[71]=255;
        rejected=false;try{parse_client_properties(tail);}catch(const std::runtime_error&){rejected=true;}
        require(rejected,"Invalid vendor length must be rejected");
        std::cout<<"PASS: MD5, CRC16, encoding, response construction and malformed frame boundaries\n";
        return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
