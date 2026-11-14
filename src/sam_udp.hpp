#pragma once

#include <winsock2.h>
#include "sam.hpp"
#include <stdexcept>

namespace scau {
class SamSocketError : public std::runtime_error {
public:
    explicit SamSocketError(const char* message) : std::runtime_error(message) {}
};

// A real bound UDP port prevents the host stack from issuing port-unreachable
// responses. Both source address and outgoing interface are fixed; the system
// default VPN route is never used as an implicit replacement.
class SamUdpTransport {
public:
    SamUdpTransport(SamEndpoint local,SamEndpoint server,ULONG interface_index);
    ~SamUdpTransport();
    SamUdpTransport(const SamUdpTransport&)=delete;
    SamUdpTransport& operator=(const SamUdpTransport&)=delete;
    [[nodiscard]] const SamEndpoint& local() const noexcept {return local_;}
    // false means nonblocking backpressure; other errors throw.
    bool send(const SamDatagram& datagram);
    std::optional<SamDatagram> receive();
private:
    SOCKET socket_{INVALID_SOCKET};
    bool winsock_started_{};
    SamEndpoint local_,server_;
};
}
