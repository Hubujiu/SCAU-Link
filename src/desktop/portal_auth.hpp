#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace scau::desktop { struct Credential; }

namespace scau::desktop::portal {
// Reconstructed PortalAuth.dll authAPI protocol, distinct from 802.1X and
// the school's account/self-service query. All strings are UTF-8.
enum class State {
    Ready, Success, Offline, Rejected, Unsupported, UntrustedTarget,
    InvalidInput, InvalidResponse, NetworkError, CertificateError,
    Timeout, Cancelled, InterfaceUnavailable
};
enum class Protocol { AuthApi, InterFace };
struct Options {
    std::uint32_t interface_index{}; // A supplied interface is mandatory, never silently ignored.
    std::chrono::milliseconds timeout{10000}; // Whole operation, not each read.
    const std::atomic_bool* cancel{};
    // Exact origins supplied by the application's school policy. Discovery
    // never adds an origin to this allowlist, and does not carry credentials.
    std::vector<std::string> trusted_origins;
    Protocol protocol = Protocol::AuthApi;
};
struct Target {
    std::string origin;
    std::string query_string; // The intercepted portal URL's query, without '?'.
    std::string user_ip;
    Protocol protocol = Protocol::AuthApi;
    bool password_encrypt = false;
    std::string public_exponent, public_modulus;
};
struct Request {
    std::string url, method, body;
    std::string expected_source_ip; // Verified before sending a credential-bearing body.
    bool form = false;
    Request() = default;
    Request(std::string url, std::string method, std::string body);
    ~Request();
    Request(const Request&) = delete;
    Request& operator=(const Request&) = delete;
    Request(Request&&) noexcept;
    Request& operator=(Request&&) noexcept;
};
struct Response {
    State state = State::NetworkError;
    unsigned status{};
    unsigned long error{};
    std::string body, location;
};
using Transport = std::function<Response(const Request&, const Options&)>;
struct Service {
    std::string name;
    bool is_default{};
};
struct Result {
    State state = State::InvalidResponse;
    unsigned http_status{};
    unsigned long transport_error{};
    std::string message; // Untrusted server text, never log; login redacts its credentials.
    std::string user_index;
    // Raw server value. The DLL does not establish its unit or a keepalive API.
    std::optional<std::uint32_t> keepalive_interval;
    std::vector<Service> services;
    bool password_encrypt = false, captcha_required = false;
    std::string public_exponent, public_modulus;
};
struct Discovery {
    State state = State::Unsupported;
    std::optional<Target> target;
    // Recognized page shape only; no query, IP, credentials or automatic trust.
    // The UI may show this origin, save explicit approval for its WiFi adapter,
    // and repeat discovery with that exact origin in trusted_origins.
    std::string candidate_origin;
};

// Pure URL/HTML and JSON operations. No scripts are evaluated. The target is
// returned only if its exact origin is trusted; redirects cannot confer trust.
Discovery parse_discovery(const Response& response, std::string_view user_ip,
                          const Options& options);
std::optional<Target> target_from_url(std::string_view url, std::string_view user_ip,
                                    const Options& options);
Result parse_page_info(std::string_view json);
Result parse_login(std::string_view json);
Result parse_online(std::string_view json);
Result parse_logout(std::string_view json);
std::optional<Request> page_info_request(const Target&, const Options&);
std::optional<Request> login_request(const Target&, const Credential&, std::string_view service,
                                     const Options&);
std::optional<Request> online_request(const Target&, std::string_view user_index, const Options&);
std::optional<Request> logout_request(const Target&, std::string_view user_index, const Options&);

// Native WinHTTP: direct connection, no automatic redirects, cookies or HTTP
// authentication, normal TLS certificate policy, bounded body, deadline and
// cancellation. Interface binding failure stops before sending any request.
Response send_winhttp(const Request&, const Options&);
Discovery discover(std::string_view probe_url, std::string_view user_ip,
                   const Options&, Transport = {});
Result page_info(const Target&, const Options&, Transport = {});
Result login(const Target&, const Credential&, std::string_view service,
             const Options&, Transport = {});
Result online(const Target&, std::string_view user_index, const Options&, Transport = {});
Result logout(const Target&, std::string_view user_index, const Options&, Transport = {});
Result keepalive(const Target&, std::string_view user_index, const Options&, Transport = {});
State internet_available(std::string_view user_ip, const Options&, Transport = {});
std::vector<std::string> school_portal_origins();
} // namespace scau::desktop::portal
