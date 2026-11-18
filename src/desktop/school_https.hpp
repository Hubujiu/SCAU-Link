#pragma once
#include "http_response.hpp"
#include <atomic>
#include <cstdint>
#include <string_view>
#include <optional>

namespace scau::desktop::detail {
enum class TransportState { Complete, NetworkError, TlsError, ProtocolError, CertificateError };
struct TlsDiagnostics {
    unsigned long socket_error{}, tls_error{};
    bool connected = false;
};
struct HttpsResult {
    TransportState state = TransportState::NetworkError;
    HttpResponse response;
};
// The legacy TLS policy is confined to this fixed school origin and pinned certificate.
HttpsResult school_https_request(std::string_view method, std::string_view path, std::string_view body,
                                 TlsDiagnostics* diagnostics = nullptr, const std::atomic_bool* cancel = nullptr,
                                 std::string_view session_cookie = {});
HttpsResult school_https_request_on_interface(unsigned index, std::string_view method, std::string_view path,
                                 std::string_view body, TlsDiagnostics* diagnostics = nullptr,
                                 const std::atomic_bool* cancel = nullptr, std::string_view session_cookie = {});
// Connected-socket seam for loopback fixtures; only production requires the school pin.
// The caller owns the socket. No DNS, proxy, credential storage or UI access.
HttpsResult school_tls_exchange(std::uintptr_t socket, std::string_view method, std::string_view path,
                                std::string_view body, std::uint64_t deadline,
                                TlsDiagnostics* diagnostics = nullptr, const std::atomic_bool* cancel = nullptr,
                                std::string_view session_cookie = {}, bool require_school_certificate = false);
const char* school_tls_version() noexcept;
std::optional<std::wstring> decode_school_response(std::string_view bytes, std::string_view content_type);
} // namespace scau::desktop::detail
