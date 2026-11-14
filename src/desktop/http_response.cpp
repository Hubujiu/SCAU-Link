#include "http_response.hpp"
#include <charconv>
#include <optional>

namespace scau::desktop::detail {
namespace {
std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return text;
}
std::string lower(std::string_view text) {
    std::string out(text);
    for (auto& ch : out) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    return out;
}
bool number(std::string_view text, std::size_t& out, int base = 10) {
    if (text.empty() || text.size() > 12) return false;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), out, base);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}
bool token(std::string_view text) {
    if (text.empty()) return false;
    for (unsigned char ch : text)
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              std::string_view("!#$%&'*+-.^_`|~").find(char(ch)) != std::string_view::npos)) return false;
    return true;
}
} // namespace

bool valid_school_session(std::string_view cookie) {
    if (!cookie.starts_with("JSESSIONID=") || cookie.size() <= 11 || cookie.size() > 256) return false;
    for (unsigned char ch : cookie.substr(11))
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '.' || ch == '-' || ch == '_')) return false;
    return true;
}

HttpResponse parse_http_response(std::string_view wire, bool eof) {
    HttpResponse result;
    auto bad = [&] { result.invalid = true; result.complete = false; result.body.clear(); return result; };
    auto pending = [&] { if (eof) return bad(); return result; };
    std::size_t start = 0;
    for (unsigned interim = 0; interim < 5; ++interim) {
        const auto end = wire.find("\r\n\r\n", start);
        if (end == std::string_view::npos) {
            if (wire.size() > maximum_http_header) return bad();
            return pending();
        }
        if (end + 4 > maximum_http_header) return bad();
        const auto first_end = wire.find("\r\n", start);
        const auto line = wire.substr(start, first_end - start);
        if (line.size() < 12 || !(line.starts_with("HTTP/1.1 ") || line.starts_with("HTTP/1.0 ")) ||
            (line.size() > 12 && line[12] != ' ')) return bad();
        unsigned status = 0;
        for (unsigned i = 9; i < 12; ++i) {
            if (line[i] < '0' || line[i] > '9') return bad();
            status = status * 10 + unsigned(line[i] - '0');
        }
        if (status < 100 || status > 599 || status == 101) return bad();
        std::optional<std::size_t> length;
        bool chunked = false, encoding_seen = false;
        std::string content_type, session_cookie, location;
        bool session_seen = false;
        for (auto p = first_end + 2; p < end;) {
            const auto next = wire.find("\r\n", p);
            if (next == std::string_view::npos || next > end) return bad();
            const auto field = wire.substr(p, next - p);
            const auto colon = field.find(':');
            if (colon == std::string_view::npos || !token(field.substr(0, colon))) return bad();
            const auto name = lower(field.substr(0, colon));
            const auto value = trim(field.substr(colon + 1));
            for (unsigned char ch : value) if ((ch < 32 && ch != '\t') || ch == 127) return bad();
            if (name == "content-length") {
                std::size_t count{};
                if (length || !number(value, count) || count > maximum_http_body) return bad();
                length = count;
            } else if (name == "transfer-encoding") {
                if (encoding_seen || lower(value) != "chunked") return bad();
                encoding_seen = chunked = true;
            } else if (name == "content-type") {
                if (value.size() > 256) return bad();
                content_type = lower(value);
            } else if (name == "location") {
                if (!location.empty() || value.size() > 2048) return bad();
                location = value;
            } else if (name == "set-cookie" && value.starts_with("JSESSIONID=")) {
                const auto cookie = value.substr(0, value.find(';'));
                if (session_seen) session_cookie.clear();
                else if (valid_school_session(cookie)) session_cookie = cookie;
                session_seen = true;
            } else if (name == "content-encoding" && lower(value) != "identity") return bad();
            p = next + 2;
        }
        if (length && chunked) return bad();
        if (status < 200) { start = end + 4; continue; }
        result.status = status;
        result.content_type = std::move(content_type);
        result.session_cookie = std::move(session_cookie);
        result.location = std::move(location);
        // Rejections and redirects need no body, and are never followed.
        if (status != 200) { result.complete = true; return result; }
        const auto body = wire.substr(end + 4);
        if (chunked) {
            std::string decoded;
            std::size_t p = 0;
            for (;;) {
                const auto next = body.find("\r\n", p);
                if (next == std::string_view::npos) return body.size() - p > 1024 ? bad() : pending();
                const auto chunk_line = body.substr(p, next - p);
                if (chunk_line.size() > 1024) return bad();
                std::size_t chunk{};
                if (!number(chunk_line.substr(0, chunk_line.find(';')), chunk, 16) ||
                    chunk > maximum_http_body - decoded.size()) return bad();
                p = next + 2;
                if (!chunk) {
                    if (body.substr(p).starts_with("\r\n")) {
                        result.body = std::move(decoded); result.complete = true; return result;
                    }
                    const auto trailers = body.find("\r\n\r\n", p);
                    if (trailers == std::string_view::npos) return body.size() - p > 4096 ? bad() : pending();
                    if (trailers - p > 4096) return bad();
                    for (auto t = p; t < trailers;) {
                        const auto e = body.find("\r\n", t), colon = body.find(':', t);
                        if (colon >= e || !token(body.substr(t, colon - t))) return bad();
                        t = e + 2;
                    }
                    result.body = std::move(decoded); result.complete = true; return result;
                }
                if (body.size() - p < chunk + 2) return pending();
                if (body.substr(p + chunk, 2) != "\r\n") return bad();
                decoded.append(body.substr(p, chunk)); p += chunk + 2;
            }
        }
        if (length) {
            if (body.size() < *length) return pending();
            result.body.assign(body.substr(0, *length)); result.complete = true; return result;
        }
        if (body.size() > maximum_http_body) return bad();
        if (!eof) return result;
        result.body.assign(body); result.complete = true; return result;
    }
    return bad();
}
} // namespace scau::desktop::detail
