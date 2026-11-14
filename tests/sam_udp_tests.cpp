#include "sam_udp.hpp"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>

namespace {
using namespace scau;
void require(bool condition,const char* message) {if(!condition)throw std::runtime_error(message);}
struct FixtureSocket {
    SOCKET value{INVALID_SOCKET};
    SamEndpoint endpoint{{127,0,0,1},0};
    FixtureSocket() {
        value=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);require(value!=INVALID_SOCKET,"Loopback fixture socket");
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        require(bind(value,reinterpret_cast<const sockaddr*>(&address),sizeof(address))==0,"Loopback fixture bind");
        int length=sizeof(address);require(getsockname(value,reinterpret_cast<sockaddr*>(&address),&length)==0,"Loopback fixture endpoint");
        endpoint.port=ntohs(address.sin_port);
        u_long enabled=1;require(ioctlsocket(value,FIONBIO,&enabled)==0,"Loopback fixture nonblocking");
    }
    ~FixtureSocket(){if(value!=INVALID_SOCKET)closesocket(value);}
    void send(SamEndpoint destination,std::span<const Byte> bytes) {
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(destination.port);
        std::memcpy(&address.sin_addr,destination.address.data(),4);
        require(sendto(value,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0,
            reinterpret_cast<const sockaddr*>(&address),sizeof(address))==static_cast<int>(bytes.size()),"Loopback fixture send");
    }
};
template<class Action>void wait_for(Action action,const char* message) {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    do{if(action())return;std::this_thread::sleep_for(std::chrono::milliseconds(1));}while(std::chrono::steady_clock::now()<deadline);
    throw std::runtime_error(message);
}
}
int main() {
    WSADATA data{};
    if(WSAStartup(MAKEWORD(2,2),&data)!=0)return 1;
    int result=1;
    try {
        FixtureSocket server,wrong_peer;
        sockaddr_in loopback{};loopback.sin_family=AF_INET;loopback.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        ULONG index{};
        require(GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&loopback),&index)==NO_ERROR,"Loopback interface index");
        SamUdpTransport client({{127,0,0,1},0},server.endpoint,index);
        const auto local=client.local();require(local.port!=0,"Bound UDP port must be known");
        require(!client.receive(),"An empty nonblocking socket must return immediately");
        const Bytes bad{1,2,3},good{4,5,6,7};
        wrong_peer.send(local,bad);server.send(local,good);
        std::optional<SamDatagram> inbound;
        wait_for([&]{inbound=client.receive();return bool(inbound);},"Expected loopback UDP input");
        require(inbound->source==server.endpoint && inbound->destination==local && inbound->payload==good,
            "Only the configured peer may supply input");
        SamDatagram outgoing{local,server.endpoint,Bytes{7,8,9}};
        wait_for([&]{return client.send(outgoing);},"Expected nonblocking UDP output");
        Bytes received;sockaddr_in source{};
        wait_for([&]{
            std::array<Byte,64> buffer{};int length=sizeof(source);
            const auto count=recvfrom(server.value,reinterpret_cast<char*>(buffer.data()),static_cast<int>(buffer.size()),0,
                reinterpret_cast<sockaddr*>(&source),&length);
            if(count==SOCKET_ERROR){require(WSAGetLastError()==WSAEWOULDBLOCK,"Loopback fixture receive error");return false;}
            received.assign(buffer.begin(),buffer.begin()+count);return true;
        },"Expected fixture to receive client UDP");
        require(received==outgoing.payload && source.sin_port==htons(local.port) && source.sin_addr.s_addr==htonl(INADDR_LOOPBACK),
            "UDP output must use the reserved local source endpoint");
        bool collision=false;
        try{SamUdpTransport conflicting(local,server.endpoint,index);}catch(const SamSocketError&){collision=true;}
        require(collision,"A second owner must not bind the active client endpoint");
        auto mismatch=outgoing;mismatch.destination=wrong_peer.endpoint;
        bool refused=false;try{client.send(mismatch);}catch(const SamSocketError&){refused=true;}
        require(refused,"The sender must reject an endpoint changed after configuration");
        require(!client.receive(),"No untrusted packet may remain visible to the protocol engine");
        std::cout<<"PASS: loopback-only Windows UDP binding, peer filter, pinned source, exclusive port and nonblocking I/O\n";
        result=0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';}
    WSACleanup();return result;
}
