#pragma once
#include <cstddef>
#include <string>
#include <string_view>

namespace scau::desktop::detail {
inline constexpr std::size_t maximum_http_body = 524288;
inline constexpr std::size_t maximum_http_header = 32768;
struct HttpResponse {
    bool complete = false, invalid = false;
    unsigned status{};
    std::string body, content_type, session_cookie, location;
};
// Only a bounded Tomcat session token; never accepts arbitrary HTTP headers.
bool valid_school_session(std::string_view cookie);
// A single HTTP/1.x response. The caller never reuses the connection or follows
// redirects. Incomplete framing stays incomplete until EOF, then fails closed.
HttpResponse parse_http_response(std::string_view wire, bool eof = false);
} // namespace scau::desktop::detail
