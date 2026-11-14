#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include "interface_dns.hpp"
#include <algorithm>
#include <array>
#include <span>

namespace scau::desktop {
namespace {
bool cancelled(const std::atomic_bool* value) { return value && value->load(); }
unsigned u16(const unsigned char* p) {return unsigned(p[0])<<8|p[1];}
bool skip_name(std::span<const unsigned char> packet,std::size_t& at) {
    for (unsigned count=0;count<128;++count) {
        if(at>=packet.size())return false;
        const auto size=packet[at++];
        if((size&0xc0)==0xc0){if(at>=packet.size())return false;++at;return true;}
        if(size&0xc0 || size>63 || size>packet.size()-at)return false;
        at+=size;if(!size)return true;
    }
    return false;
}
}
std::vector<std::string> resolve_interface_ipv4(std::string_view host,unsigned index,
    std::chrono::milliseconds timeout,const std::atomic_bool* cancel) {
    IN_ADDR literal{};const std::string name(host);
    if(InetPtonA(AF_INET,name.c_str(),&literal)==1)return {name};
    if(!index || host.empty() || host.size()>253 || timeout.count()<=0)return {};
    WSADATA runtime{};if(WSAStartup(MAKEWORD(2,2),&runtime))return {};
    struct Stop {~Stop(){WSACleanup();}} stop;
    ULONG length=16384;std::vector<unsigned char> buffer(length);
    auto adapters=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    auto status=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST,nullptr,adapters,&length);
    if(status==ERROR_BUFFER_OVERFLOW && length<=1048576){buffer.resize(length);adapters=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());status=GetAdaptersAddresses(AF_INET,0,nullptr,adapters,&length);}
    if(status)return {};
    const IP_ADAPTER_ADDRESSES* adapter=nullptr;
    for(auto a=adapters;a;a=a->Next)if(a->IfIndex==index && a->OperStatus==IfOperStatusUp){adapter=a;break;}
    if(!adapter)return {};
    sockaddr_in local{};bool has_source=false;
    for(auto a=adapter->FirstUnicastAddress;a;a=a->Next)if(a->Address.lpSockaddr && a->Address.lpSockaddr->sa_family==AF_INET){local=*reinterpret_cast<sockaddr_in*>(a->Address.lpSockaddr);local.sin_port=0;has_source=true;break;}
    if(!has_source)return {};
    std::array<unsigned char,512> query{};unsigned short nonce{};
    if(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&nonce),sizeof(nonce),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return {};
    query[0]=static_cast<unsigned char>(nonce>>8);query[1]=static_cast<unsigned char>(nonce);query[2]=1;query[5]=1;
    std::size_t bytes=12,at=0;
    while(at<host.size()) {
        const auto dot=host.find('.',at);const auto end=dot==host.npos?host.size():dot;const auto n=end-at;
        if(!n || n>63 || bytes+n+6>query.size())return {};
        query[bytes++]=static_cast<unsigned char>(n);
        for(auto c:host.substr(at,n)){if(!(c>='a'&&c<='z')&&!(c>='A'&&c<='Z')&&!(c>='0'&&c<='9')&&c!='-')return {};query[bytes++]=c;}
        at=end+1;
    }
    query[bytes++]=0;query[bytes++]=0;query[bytes++]=1;query[bytes++]=0;query[bytes++]=1;
    const auto deadline=GetTickCount64()+static_cast<ULONGLONG>(std::min<std::int64_t>(timeout.count(),4000));
    for(auto dns=adapter->FirstDnsServerAddress;dns && !cancelled(cancel);dns=dns->Next) {
        if(!dns->Address.lpSockaddr || dns->Address.lpSockaddr->sa_family!=AF_INET)continue;
        const SOCKET socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(socket==INVALID_SOCKET)continue;
        struct Close {SOCKET s;~Close(){closesocket(s);}} close{socket};
        const DWORD affinity=htonl(index);
        auto remote=*reinterpret_cast<sockaddr_in*>(dns->Address.lpSockaddr);remote.sin_port=htons(53);
        if(setsockopt(socket,IPPROTO_IP,IP_UNICAST_IF,reinterpret_cast<const char*>(&affinity),sizeof(affinity)) ||
            bind(socket,reinterpret_cast<sockaddr*>(&local),sizeof(local)) ||
            ::connect(socket,reinterpret_cast<sockaddr*>(&remote),sizeof(remote)) ||
            send(socket,reinterpret_cast<const char*>(query.data()),int(bytes),0)!=int(bytes))continue;
        const auto server_deadline=std::min<ULONGLONG>(deadline,GetTickCount64()+1500);
        while(!cancelled(cancel) && GetTickCount64()<server_deadline) {
            fd_set ready{};FD_ZERO(&ready);FD_SET(socket,&ready);timeval wait{0,50000};
            if(select(0,&ready,nullptr,nullptr,&wait)<=0)continue;
            std::array<unsigned char,4096> packet{};const int received=recv(socket,reinterpret_cast<char*>(packet.data()),int(packet.size()),0);
            if(received<12 || u16(packet.data())!=nonce || (u16(packet.data()+2)&0x820f)!=0x8000)continue;
            std::span<const unsigned char> view(packet.data(),received);std::size_t offset=12;
            bool valid=true;
            for(unsigned i=0;i<u16(packet.data()+4);++i)if(!skip_name(view,offset) || offset+4>view.size()){valid=false;break;}else offset+=4;
            std::vector<std::string> answers;
            for(unsigned i=0;valid && i<u16(packet.data()+6) && i<128;++i) {
                if(!skip_name(view,offset)||offset+10>view.size()){valid=false;break;}
                const auto type=u16(packet.data()+offset),kind=u16(packet.data()+offset+2),size=u16(packet.data()+offset+8);offset+=10;
                if(offset+size>view.size()){valid=false;break;}
                if(type==1 && kind==1 && size==4) {
                    char address[INET_ADDRSTRLEN]{};if(InetNtopA(AF_INET,packet.data()+offset,address,sizeof(address)))answers.emplace_back(address);
                }
                offset+=size;
            }
            if(valid && !answers.empty())return answers;
            break;
        }
        if(GetTickCount64()>=deadline)break;
    }
    return {};
}

bool bind_interface_ipv4_socket(std::uintptr_t raw_socket, unsigned index) {
    if (!index) { WSASetLastError(WSAEINVAL); return false; }
    ULONG bytes=16384;std::vector<unsigned char> storage(bytes);
    auto list=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    auto code=GetAdaptersAddresses(AF_INET,0,nullptr,list,&bytes);
    if(code==ERROR_BUFFER_OVERFLOW && bytes<=1048576) {
        storage.resize(bytes);list=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
        code=GetAdaptersAddresses(AF_INET,0,nullptr,list,&bytes);
    }
    if(!code)for(auto a=list;a;a=a->Next)if(a->IfIndex==index && a->OperStatus==IfOperStatusUp)
        for(auto u=a->FirstUnicastAddress;u;u=u->Next)
            if(u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family==AF_INET && u->DadState==IpDadStatePreferred) {
                auto address=*reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
                const auto host=ntohl(address.sin_addr.s_addr);
                if(!host || (host>>24)==127 || (host>>24)>=224 || (host>>16)==0xa9fe)continue;
                address.sin_port=0;const DWORD affinity=htonl(index);
                const auto socket=static_cast<SOCKET>(raw_socket);
                return !setsockopt(socket,IPPROTO_IP,IP_UNICAST_IF,reinterpret_cast<const char*>(&affinity),sizeof(affinity)) &&
                    !bind(socket,reinterpret_cast<const sockaddr*>(&address),sizeof(address));
            }
    WSASetLastError(WSAEADDRNOTAVAIL);return false;
}
} // namespace scau::desktop

