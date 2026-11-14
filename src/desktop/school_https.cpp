#include <winsock2.h>
#include <ws2tcpip.h>
#include "school_https.hpp"
#include "interface_dns.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <algorithm>
#include <climits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace scau::desktop::detail {
namespace {
constexpr char host[] = "mavis.scau.edu.cn";
struct Socket {
    SOCKET value = INVALID_SOCKET;
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket() = default;
    explicit Socket(SOCKET s) : value(s) {}
    Socket(const Socket&) = delete;
};
struct Winsock {
    int error{};
    Winsock() { WSADATA data{}; error = WSAStartup(MAKEWORD(2, 2), &data); }
    ~Winsock() { if (!error) WSACleanup(); }
};
struct Addresses {
    PADDRINFOEXW value{};
    ~Addresses() { if (value) FreeAddrInfoExW(value); }
};
struct Wipe {
    std::string& value;
    ~Wipe() { if (!value.empty()) SecureZeroMemory(value.data(), value.size()); }
};
bool stopped(const std::atomic_bool* cancel) { return cancel && cancel->load(std::memory_order_relaxed); }
bool wait_socket(SOCKET socket, bool writing, std::uint64_t deadline, TlsDiagnostics& info,
                 const std::atomic_bool* cancel) {
    while (!stopped(cancel)) {
        const auto now = GetTickCount64();
        if (now >= deadline) break;
        const auto milliseconds = std::min<std::uint64_t>(200, deadline - now);
        timeval timeout{long(milliseconds / 1000), long(milliseconds % 1000 * 1000)};
        fd_set ready{}, errors{}; FD_ZERO(&ready); FD_ZERO(&errors);
        FD_SET(socket, &ready); FD_SET(socket, &errors);
        const auto n = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr, &errors, &timeout);
        if (n == SOCKET_ERROR) { info.socket_error = WSAGetLastError(); return false; }
        if (n > 0) {
            if (FD_ISSET(socket, &errors)) {
                int error{}, size = sizeof(error);
                getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size);
                info.socket_error = error ? error : WSAECONNABORTED; return false;
            }
            if (FD_ISSET(socket, &ready)) return true;
        }
    }
    info.socket_error = stopped(cancel) ? ERROR_CANCELLED : WSAETIMEDOUT;
    return false;
}
SSL_CTX* context() {
    static const std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> value = [] {
        // No global config, legacy provider DLL, or Windows trust-policy changes.
        if (OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1)
            throw std::runtime_error("Cannot initialize package TLS");
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
        if (!ctx) throw std::runtime_error("Cannot create package TLS context");
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_security_level(ctx.get(), 0); // User-authorized MD5/1024-bit school certificate.
        if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(ctx.get(), TLS1_2_VERSION) != 1 ||
            SSL_CTX_set_cipher_list(ctx.get(),
                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256") != 1 ||
            SSL_CTX_set1_groups_list(ctx.get(), "P-256:P-384") != 1)
            throw std::runtime_error("Cannot configure package TLS");
        SSL_CTX_set_options(ctx.get(), SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
        return ctx;
    }();
    return value.get();
}
bool retry(SSL* ssl, int result, SOCKET socket, std::uint64_t deadline,
           TlsDiagnostics& info, const std::atomic_bool* cancel) {
    const int error = SSL_get_error(ssl, result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
        return wait_socket(socket, error == SSL_ERROR_WANT_WRITE, deadline, info, cancel);
    info.tls_error = ERR_peek_last_error();
    if (!info.tls_error) info.tls_error = static_cast<unsigned long>(error);
    return false;
}
} // namespace

const char* school_tls_version() noexcept { return OPENSSL_VERSION_TEXT; }

std::optional<std::wstring> decode_school_response(std::string_view bytes, std::string_view content_type) {
    if (bytes.empty() || bytes.size() > maximum_http_body) return {};
    UINT codepage = CP_UTF8;
    if (auto charset = content_type.find("charset="); charset != std::string_view::npos) {
        auto name = content_type.substr(charset + 8);
        if (!name.empty() && (name.front() == '"' || name.front() == '\'')) name.remove_prefix(1);
        name = name.substr(0, name.find_first_of(";\"' \t"));
        if (name == "gbk" || name == "gb2312") codepage = 936;
        else if (name == "gb18030") codepage = 54936;
        else if (name != "utf-8" && name != "utf8" && name != "us-ascii") return {};
    }
    if (codepage == CP_UTF8 && bytes.starts_with("\xef\xbb\xbf")) bytes.remove_prefix(3);
    if (bytes.empty()) return {};
    const auto count = MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, bytes.data(), int(bytes.size()), nullptr, 0);
    if (!count) return {};
    std::wstring result(count, L'\0');
    if (MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, bytes.data(), int(bytes.size()), result.data(), count) != count) return {};
    return result;
}

HttpsResult school_tls_exchange(std::uintptr_t raw_socket, std::string_view method, std::string_view path,
                                std::string_view body, std::uint64_t deadline,
                                TlsDiagnostics* diagnostics, const std::atomic_bool* cancel,
                                std::string_view session_cookie) {
    TlsDiagnostics local;
    auto& info = diagnostics ? *diagnostics : local;
    HttpsResult result;
    if ((method != "GET" && method != "POST") || !path.starts_with("/selfservice/") ||
        path.size() > 2048 || path.find_first_of("\r\n") != std::string_view::npos ||
        path.find('\0') != std::string_view::npos || body.size() > 8192 ||
        (!session_cookie.empty() && !valid_school_session(session_cookie))) {
        result.state = TransportState::ProtocolError; return result;
    }
    const auto socket = static_cast<SOCKET>(raw_socket);
    if (socket > INT_MAX) { info.socket_error = WSAEINVAL; return result; }
    u_long nonblocking = 1;
    if (ioctlsocket(socket, FIONBIO, &nonblocking)) { info.socket_error = WSAGetLastError(); return result; }
    ERR_clear_error();
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context()), SSL_free);
    if (!ssl || SSL_set_tlsext_host_name(ssl.get(), host) != 1 ||
        SSL_set_fd(ssl.get(), static_cast<int>(socket)) != 1) {
        info.tls_error = ERR_peek_last_error(); result.state = TransportState::TlsError; return result;
    }
    for (;;) {
        if (stopped(cancel) || GetTickCount64() >= deadline) {
            info.socket_error = stopped(cancel) ? ERROR_CANCELLED : WSAETIMEDOUT; return result;
        }
        ERR_clear_error();
        const int connected = SSL_connect(ssl.get());
        if (connected == 1) break;
        if (!retry(ssl.get(), connected, socket, deadline, info, cancel)) {
            result.state = info.socket_error ? TransportState::NetworkError : TransportState::TlsError;
            return result;
        }
    }
    info.connected = true;
    std::string request;
    request.reserve(path.size() + body.size() + session_cookie.size() + 512);
    request = std::string(method) + " " + std::string(path) +
        " HTTP/1.1\r\nHost: mavis.scau.edu.cn:8443\r\nUser-Agent: SCAU-Link/0.11.1\r\n"
        "Accept: application/json, text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n";
    Wipe request_wipe{request};
    if (!session_cookie.empty()) { request += "Cookie: "; request += session_cookie; request += "\r\n"; }
    if (method == "POST") request += "Content-Type: application/x-www-form-urlencoded\r\n";
    request += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    request.append(body);
    std::size_t written = 0;
    while (written < request.size()) {
        if (stopped(cancel) || GetTickCount64() >= deadline) {
            info.socket_error = stopped(cancel) ? ERROR_CANCELLED : WSAETIMEDOUT; return result;
        }
        std::size_t count{};
        ERR_clear_error();
        const auto sent = SSL_write_ex(ssl.get(), request.data() + written, request.size() - written, &count);
        if (sent == 1) { written += count; continue; }
        if (!retry(ssl.get(), sent, socket, deadline, info, cancel)) {
            result.state = info.socket_error ? TransportState::NetworkError : TransportState::TlsError; return result;
        }
    }
    std::string wire;
    Wipe wire_wipe{wire};
    for (;;) {
        result.response = parse_http_response(wire);
        if (result.response.invalid) { result.state = TransportState::ProtocolError; return result; }
        if (result.response.complete) {
            result.state = TransportState::Complete;
            SSL_shutdown(ssl.get()); // Best effort on the nonblocking, one-use connection.
            return result;
        }
        if (stopped(cancel) || GetTickCount64() >= deadline) {
            info.socket_error = stopped(cancel) ? ERROR_CANCELLED : WSAETIMEDOUT; return result;
        }
        char buffer[8192]; std::size_t count{};
        ERR_clear_error();
        const auto received = SSL_read_ex(ssl.get(), buffer, sizeof(buffer), &count);
        if (received == 1) {
            if (wire.size() + count > maximum_http_header + maximum_http_body + 65536) {
                result.state = TransportState::ProtocolError; return result;
            }
            wire.append(buffer, count); continue;
        }
        const int error = SSL_get_error(ssl.get(), received);
        if (error == SSL_ERROR_ZERO_RETURN) {
            result.response = parse_http_response(wire, true);
            result.state = result.response.complete ? TransportState::Complete : TransportState::ProtocolError;
            return result;
        }
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            if (wait_socket(socket, error == SSL_ERROR_WANT_WRITE, deadline, info, cancel)) continue;
            return result;
        }
        info.tls_error = ERR_peek_last_error();
        if (!info.tls_error) info.tls_error = static_cast<unsigned long>(error);
        result.state = TransportState::TlsError; return result;
    }
}

HttpsResult school_https_request(std::string_view method, std::string_view path, std::string_view body,
                                 TlsDiagnostics* diagnostics, const std::atomic_bool* cancel,
                                 std::string_view session_cookie) {
    return school_https_request_on_interface(0,method,path,body,diagnostics,cancel,session_cookie);
}
HttpsResult school_https_request_on_interface(unsigned index, std::string_view method, std::string_view path,
                                 std::string_view body, TlsDiagnostics* diagnostics,
                                 const std::atomic_bool* cancel, std::string_view session_cookie) {
    TlsDiagnostics local;
    auto& info = diagnostics ? *diagnostics : local;
    info = {};
    HttpsResult failed;
    Winsock runtime;
    if (runtime.error) { info.socket_error = runtime.error; return failed; }
    const auto deadline = GetTickCount64() + 8000;
    Addresses addresses;
    std::vector<sockaddr_in> bound_addresses;
    std::vector<ADDRINFOEXW> bound_records;
    ADDRINFOEXW* first=nullptr;
    if(index) {
        const auto resolved=resolve_interface_ipv4("mavis.scau.edu.cn",index,std::chrono::milliseconds(2500),cancel);
        bound_addresses.resize(resolved.size());bound_records.resize(resolved.size());
        for(std::size_t i=0;i<resolved.size();++i) {
            auto& address=bound_addresses[i];address.sin_family=AF_INET;address.sin_port=htons(8443);
            if(InetPtonA(AF_INET,resolved[i].c_str(),&address.sin_addr)!=1){info.socket_error=WSAHOST_NOT_FOUND;return failed;}
            auto& record=bound_records[i];record.ai_family=AF_INET;record.ai_socktype=SOCK_STREAM;record.ai_protocol=IPPROTO_TCP;
            record.ai_addr=reinterpret_cast<sockaddr*>(&address);record.ai_addrlen=sizeof(address);
            if(i+1<resolved.size())record.ai_next=&bound_records[i+1];
        }
        if(bound_records.empty()){info.socket_error=stopped(cancel)?ERROR_CANCELLED:WSAHOST_NOT_FOUND;return failed;}
        first=bound_records.data();
    } else {
    ADDRINFOEXW hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    timeval timeout{2, 0};
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event) { info.socket_error = GetLastError(); return failed; }
    OVERLAPPED overlapped{}; overlapped.hEvent = event;
    HANDLE request{};
    auto status = GetAddrInfoExW(L"mavis.scau.edu.cn", L"8443", NS_DNS, nullptr, &hints, &addresses.value,
                                 &timeout, &overlapped, nullptr, &request);
    if (status == WSA_IO_PENDING) {
        while (WaitForSingleObject(event, 50) == WAIT_TIMEOUT) {
            if (stopped(cancel) || GetTickCount64() >= deadline) {
                GetAddrInfoExCancel(&request);
                // Drain cancellation before the stack-owned OVERLAPPED/result
                // can be released. The resolver also has its own 2-second limit.
                WaitForSingleObject(event, INFINITE);
                break;
            }
        }
        status = GetAddrInfoExOverlappedResult(&overlapped);
    }
    CloseHandle(event);
    if (stopped(cancel)) { info.socket_error = ERROR_CANCELLED; return failed; }
    if (status) { info.socket_error = status; return failed; }
    first=addresses.value;
    }
    for (auto address = first; address && !stopped(cancel); address = address->ai_next) {
        if (GetTickCount64() >= deadline) break;
        Socket candidate(::socket(address->ai_family, address->ai_socktype, address->ai_protocol));
        if (candidate.value == INVALID_SOCKET) continue;
        if(index && !bind_interface_ipv4_socket(candidate.value,index)){info.socket_error=WSAGetLastError();continue;}
        u_long nonblocking = 1;
        if (ioctlsocket(candidate.value, FIONBIO, &nonblocking)) continue;
        const auto connected = connect(candidate.value, address->ai_addr, static_cast<int>(address->ai_addrlen));
        if (connected == SOCKET_ERROR) {
            const auto error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS) { info.socket_error = error; continue; }
            if (!wait_socket(candidate.value, true, deadline, info, cancel)) continue;
            int connect_error{}, length = sizeof(connect_error);
            if (getsockopt(candidate.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&connect_error), &length) ||
                connect_error) { info.socket_error = connect_error ? connect_error : WSAGetLastError(); continue; }
        }
        info.socket_error = 0;
        // Match the original client's 30-second receive allowance. The
        // connection/DNS budget stays short; cancellation is polled throughout.
        return school_tls_exchange(candidate.value, method, path, body, GetTickCount64() + 30000, &info, cancel,
                                   session_cookie);
    }
    if (!info.socket_error) info.socket_error = stopped(cancel) ? ERROR_CANCELLED : WSAETIMEDOUT;
    return failed;
}
} // namespace scau::desktop::detail
