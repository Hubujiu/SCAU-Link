#include "desktop/http_response.hpp"
#include <iostream>
#include <stdexcept>
using namespace scau::desktop::detail;
void require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
int main() {
    try {
        const std::string normal = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: application/json; charset=GBK\r\n\r\n{\"ok\":true}";
        for (std::size_t n = 0; n < normal.size(); ++n)
            require(!parse_http_response(std::string_view(normal).substr(0, n)).complete, "Fragmented response cannot complete early");
        auto full = parse_http_response(normal);
        require(full.complete && full.status == 200 && full.body == "{\"ok\":true}" &&
                    full.content_type == "application/json; charset=gbk", "Length and charset");
        auto chunks = parse_http_response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=x\r\n{\"ok\"\r\n6\r\n:true}\r\n0\r\nX-End: yes\r\n\r\n");
        require(chunks.complete && chunks.body == "{\"ok\":true}", "Chunk extensions, fragments and trailers");
        require(parse_http_response("HTTP/1.1 100 Continue\r\n\r\n" + normal).body == full.body, "Interim response");
        require(!parse_http_response("HTTP/1.0 200 OK\r\n\r\ntext").complete &&
                    parse_http_response("HTTP/1.0 200 OK\r\n\r\ntext", true).body == "text", "Close-delimited framing");
        for (const auto& bad : {
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nxx",
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nG\r\nx\r\n",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nx",
                "HTTP/1.1 200 OK\r\nContent-Length: 524289\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nx",
                "HTTP/1.1 200 OK\r\n Folded: value\r\n\r\n",
                "HTTP/1.1 101 Switching\r\n\r\n"})
            require(parse_http_response(bad, true).invalid, "Truncation, ambiguity or unsupported framing must fail");
        auto redirect = parse_http_response("HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/\r\n\r\n");
        require(redirect.complete && redirect.status == 302 && redirect.body.empty() &&
                    redirect.location == "https://elsewhere.invalid/", "Redirect only reported, never followed");
        require(parse_http_response("HTTP/1.1 302 Found\r\nLocation: /one\r\nLocation: /two\r\n\r\n").invalid &&
                    parse_http_response("HTTP/1.1 302 Found\r\nLocation: " + std::string(2049, 'x') + "\r\n\r\n").invalid,
                "Redirect metadata is bounded and unambiguous");
        require(parse_http_response(std::string(maximum_http_header + 1, 'x')).invalid, "Bounded headers");
        auto session = parse_http_response("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: JSESSIONID=fixture.node-1; Path=/selfservice; HttpOnly\r\n\r\n");
        require(session.session_cookie == "JSESSIONID=fixture.node-1", "Only the bounded session token is retained");
        require(!valid_school_session("JSESSIONID=") && !valid_school_session("JSESSIONID=x\r\nInjected: y") &&
                    !valid_school_session("other=fixture") && !valid_school_session("JSESSIONID=x; other=y"),
                "Cookie cannot inject arbitrary headers or additional cookies");
        auto duplicate = parse_http_response("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: JSESSIONID=a\r\nSet-Cookie: JSESSIONID=b\r\n\r\n");
        require(duplicate.session_cookie.empty(), "Ambiguous session cookies are not reused");
        std::cout << "PASS: incremental HTTP framing, chunking, trailers, bounds, ambiguous lengths, encoding, redirects\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
