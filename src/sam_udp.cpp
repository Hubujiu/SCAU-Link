#include "sam_udp.hpp"
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <array>
#include <cstring>

namespace scau {
namespace {
sockaddr_in socket_address(const SamEndpoint& endpoint) {
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(endpoint.port);
    std::memcpy(&address.sin_addr,endpoint.address.data(),endpoint.address.size());
    return address;
}
}
SamUdpTransport::SamUdpTransport(SamEndpoint local,SamEndpoint server,ULONG interface_index)
    :local_(local),server_(server) {
    if(!interface_index || !server.port || !local.address[0] || !server.address[0])
        throw SamSocketError("Invalid SAM UDP endpoints or physical interface");
    WSADATA data{};
    if(WSAStartup(MAKEWORD(2,2),&data)!=0)throw SamSocketError("Cannot initialize SAM Windows sockets");
    winsock_started_=true;
    try {
        socket_=WSASocketW(AF_INET,SOCK_DGRAM,IPPROTO_UDP,nullptr,0,WSA_FLAG_NO_HANDLE_INHERIT);
        if(socket_==INVALID_SOCKET)throw SamSocketError("Cannot create the SAM UDP socket");
        const BOOL exclusive=TRUE;
        if(setsockopt(socket_,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))!=0)
            throw SamSocketError("Cannot reserve the SAM UDP endpoint");
        // Per Microsoft's IPPROTO_IP contract, IP_UNICAST_IF is network order.
        const auto interface_value=htonl(interface_index);
        if(setsockopt(socket_,IPPROTO_IP,IP_UNICAST_IF,reinterpret_cast<const char*>(&interface_value),sizeof(interface_value))!=0)
            throw SamSocketError("Cannot pin SAM to the selected physical interface");
        auto address=socket_address(local_);
        if(bind(socket_,reinterpret_cast<const sockaddr*>(&address),sizeof(address))!=0)
            throw SamSocketError("Cannot bind the advertised SAM client port");
        int length=sizeof(address);
        if(getsockname(socket_,reinterpret_cast<sockaddr*>(&address),&length)!=0)
            throw SamSocketError("Cannot inspect the bound SAM endpoint");
        local_.port=ntohs(address.sin_port);
        SOCKADDR_INET source{},destination{},best_source{};source.Ipv4=address;destination.Ipv4=socket_address(server_);
        MIB_IPFORWARD_ROW2 route{};
        if(GetBestRoute2(nullptr,interface_index,&source,&destination,0,&route,&best_source)!=NO_ERROR || route.InterfaceIndex!=interface_index)
            throw SamSocketError("The selected physical interface has no SAM route");
        u_long nonblocking=1;
        if(ioctlsocket(socket_,FIONBIO,&nonblocking)!=0)throw SamSocketError("Cannot enable nonblocking SAM UDP");
        BOOL report_port_unreachable=FALSE;DWORD bytes{};
        if(WSAIoctl(socket_,SIO_UDP_CONNRESET,&report_port_unreachable,sizeof(report_port_unreachable),nullptr,0,&bytes,nullptr,nullptr)!=0)
            throw SamSocketError("Cannot configure SAM UDP error handling");
    }catch(...) {
        if(socket_!=INVALID_SOCKET){closesocket(socket_);socket_=INVALID_SOCKET;}
        WSACleanup();winsock_started_=false;throw;
    }
}
SamUdpTransport::~SamUdpTransport() {
    if(socket_!=INVALID_SOCKET)closesocket(socket_);
    if(winsock_started_)WSACleanup();
}
bool SamUdpTransport::send(const SamDatagram& datagram) {
    if(datagram.source!=local_ || datagram.destination!=server_ || datagram.payload.empty() || datagram.payload.size()>65507)
        throw SamSocketError("SAM datagram does not match the bound endpoints");
    const auto destination=socket_address(server_);
    const auto count=sendto(socket_,reinterpret_cast<const char*>(datagram.payload.data()),static_cast<int>(datagram.payload.size()),0,
        reinterpret_cast<const sockaddr*>(&destination),sizeof(destination));
    if(count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK)return false;
    if(count!=static_cast<int>(datagram.payload.size()))throw SamSocketError("SAM UDP transmission failed");
    return true;
}
std::optional<SamDatagram> SamUdpTransport::receive() {
    // A bounded drain also ignores unexpected peers without starving EAPOL.
    for(unsigned attempt=0;attempt<64;++attempt) {
        std::array<Byte,65536> buffer{};sockaddr_in source{};int length=sizeof(source);
        const auto count=recvfrom(socket_,reinterpret_cast<char*>(buffer.data()),static_cast<int>(buffer.size()),0,
            reinterpret_cast<sockaddr*>(&source),&length);
        if(count==SOCKET_ERROR) {
            const auto error=WSAGetLastError();
            if(error==WSAEWOULDBLOCK)return {};
            if(error==WSAECONNRESET || error==WSAEMSGSIZE)continue;
            throw SamSocketError("SAM UDP reception failed");
        }
        const auto peer=socket_address(server_);
        if(count==0 || length!=sizeof(source) || source.sin_family!=AF_INET || source.sin_port!=peer.sin_port ||
           source.sin_addr.s_addr!=peer.sin_addr.s_addr)continue;
        return SamDatagram{server_,local_,Bytes(buffer.begin(),buffer.begin()+count)};
    }
    return {};
}
}
