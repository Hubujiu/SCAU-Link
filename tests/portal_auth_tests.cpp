#include <winsock2.h>
#include "desktop/portal_auth.hpp"
#include "desktop/platform.hpp"
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <source_location>
#include <thread>

using namespace scau::desktop;
using namespace scau::desktop::portal;
namespace {
int checks{};
void check(bool passed, const std::source_location where = std::source_location::current()) {
    ++checks; if (!passed) { std::cerr << "portal check " << checks << " failed at line " << where.line() << '\n'; std::abort(); }
}
Response reply(unsigned status, std::string body = {}, std::string location = {}) {
    Response value; value.state = State::Ready; value.status = status;
    value.body = std::move(body); value.location = std::move(location); return value;
}
struct Server {
    SOCKET socket = INVALID_SOCKET;
    unsigned short port{};
    std::thread worker;
    std::string received;
    Server(std::string response, std::chrono::milliseconds delay = {}) {
        socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        check(socket != INVALID_SOCKET);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        check(bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        int bytes = sizeof(address);
        check(getsockname(socket, reinterpret_cast<sockaddr*>(&address), &bytes) == 0);
        port = ntohs(address.sin_port); check(listen(socket, 2) == 0);
        worker = std::thread([this, response = std::move(response), delay] {
            fd_set readable; FD_ZERO(&readable); FD_SET(socket, &readable); timeval wait{3, 0};
            if (select(0, &readable, nullptr, nullptr, &wait) != 1) return;
            SOCKET client = accept(socket, nullptr, nullptr); if (client == INVALID_SOCKET) return;
            DWORD timeout = 1000; setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
            char buffer[2048];
            while (received.find("\r\n\r\n") == received.npos) {
                int count = recv(client, buffer, sizeof(buffer), 0); if (count <= 0) break;
                received.append(buffer, count);
            }
            const auto length = received.find("Content-Length: ");
            if (length != received.npos) {
                auto body_size = std::stoul(received.substr(length + 16));
                const auto headers_end = received.find("\r\n\r\n");
                while (received.size() < headers_end + 4 + body_size) {
                    int count = recv(client, buffer, sizeof(buffer), 0); if (count <= 0) break;
                    received.append(buffer, count);
                }
            }
            std::this_thread::sleep_for(delay);
            send(client, response.data(), static_cast<int>(response.size()), 0);
            shutdown(client, SD_BOTH); closesocket(client);
        });
    }
    ~Server() { if (worker.joinable()) worker.join(); if (socket != INVALID_SOCKET) closesocket(socket); }
    std::string origin() const { return "http://127.0.0.1:" + std::to_string(port); }
};
std::uint32_t interface_index(bool loopback) {
    ULONG bytes = 16384; std::vector<unsigned char> storage(bytes);
    auto list = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    auto error = GetAdaptersAddresses(AF_INET, 0, nullptr, list, &bytes);
    if (error == ERROR_BUFFER_OVERFLOW) { storage.resize(bytes); list = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()); error = GetAdaptersAddresses(AF_INET, 0, nullptr, list, &bytes); }
    if (error != NO_ERROR) return 0;
    for (auto adapter = list; adapter; adapter = adapter->Next)
        if ((adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) == loopback &&
            adapter->OperStatus == IfOperStatusUp && adapter->FirstUnicastAddress) return adapter->IfIndex;
    return 0;
}
std::string wire(unsigned code, std::string body, std::string headers = {}) {
    return "HTTP/1.1 " + std::to_string(code) + " Test\r\nContent-Length: " + std::to_string(body.size()) +
        "\r\nConnection: close\r\n" + headers + "\r\n" + body;
}
}
int main() {
    Options options; options.interface_index = 1; options.trusted_origins = {"http://portal.example:8080"};
    auto target = target_from_url("http://PORTAL.example:8080/eportal/index.jsp?wlanuserip=10.0.0.2&x=%2f", "10.0.0.2", options);
    check(target && target->origin == "http://portal.example:8080" && target->query_string == "wlanuserip=10.0.0.2&x=%2f");
    check(!target_from_url("http://portal.example.evil:8080/eportal/index.jsp?q=1", "10.0.0.2", options));
    check(!target_from_url("http://portal.example:8080@evil/eportal/index.jsp?q=1", "10.0.0.2", options));
    check(!target_from_url("http://portal.example:8080/eportal/index.jsp?q=1#fragment", "10.0.0.2", options));
    check(!target_from_url("file:///eportal/index.jsp?q=1", "10.0.0.2", options));
    check(!target_from_url("http://portal.example:8080/eportal/index.jsp?q=1", "0.0.0.0", options));
    check(!target_from_url("http://portal.example:8080/eportal/index.jsp?q=1", "10.0.0.256", options));
    check(!target_from_url("http://portal.example:8080/eportal/InterFace.do", "10.0.0.2", options));
    check(parse_discovery(reply(302, {}, "http://portal.example:8080/eportal/index.jsp?q=1"), "10.0.0.2", options).state == State::Ready);
    const auto untrusted_discovery = parse_discovery(reply(302, {}, "http://evil.example/eportal/index.jsp?q=1"), "10.0.0.2", options);
    check(untrusted_discovery.state == State::UntrustedTarget && !untrusted_discovery.target &&
          untrusted_discovery.candidate_origin == "http://evil.example");
    check(parse_discovery(reply(302, {}, "http://evil.example/other/path?q=1"), "10.0.0.2", options).candidate_origin.empty());
    check(parse_discovery(reply(200, "<script>location.href = 'http://portal.example:8080/eportal/index.jsp?q=1';</script>"), "10.0.0.2", options).target.has_value());
    check(parse_discovery(reply(200, "location.href='http://portal.example:8080/eportal/index.jsp?q=1';location.href='http://evil.example/eportal/?q=2'"), "10.0.0.2", options).state == State::Unsupported);
    check(parse_discovery(reply(200, "location.href = buildUrl();"), "10.0.0.2", options).state == State::Unsupported);
    check(parse_discovery(reply(200, "Already online"), "10.0.0.2", options).state == State::Unsupported);
    auto page = parse_page_info(R"({"portalUrl":"http://unused.example/","service":[{"serviceName":"校园网","serviceDefault":"true"},{"serviceName":"Other","serviceDefault":false}]})");
    check(page.state == State::Ready && page.services.size() == 2 && page.services[0].is_default);
    check(parse_page_info(R"({"service":[]})").state == State::Ready);
    check(parse_page_info(R"({"service":{},"passwordEncrypt":"false","publicKeyExponent":"10001","publicKeyModulus":"public-fixture","validCodeUrl":""})").state==State::Ready);
    check(parse_page_info(R"({"service":{"unknown":"shape"}})").state==State::InvalidResponse);
    check(parse_page_info(R"({"service":{},"passwordEncrypt":"true","validCodeUrl":"image.jsp"})").captcha_required);
    check(parse_page_info(R"({"service":[{"serviceName":"x"},{"serviceName":"x"}]})").state == State::InvalidResponse);
    check(parse_page_info(R"({"service":"wrong"})").state == State::InvalidResponse);
    check(parse_page_info(R"({"unrelated":true})").state == State::InvalidResponse);
    auto success = parse_login(R"({"result":"success","message":"OK","userIndex":"synthetic-index","keepaliveInterval":60})");
    check(success.state == State::Success && success.user_index == "synthetic-index" && success.keepalive_interval == 60u);
    check(parse_login(R"({"result":"success","userIndex":"x"})").state == State::Success);
    check(parse_login(R"({"result":"success","userIndex":"x","keepaliveInterval":"60"})").keepalive_interval==60u);
    check(parse_login(R"({"result":"success","userIndex":""})").state == State::InvalidResponse);
    check(parse_login(R"({"result":"unrecognized","message":"unknown outcome"})").state == State::InvalidResponse);
    check(parse_login(R"({"result":"success","userIndex":"x","keepaliveInterval":-1})").state == State::InvalidResponse);
    check(parse_login(R"({"result":"success","userIndex":"x","keepaliveInterval":1.5})").state == State::InvalidResponse);
    check(parse_login(R"({"result":"success","userIndex":"x","keepaliveInterval":4294967296})").state == State::InvalidResponse);
    auto rejected = parse_login(R"({"result":"fail","message":"时段限制\n请稍后重试"})");
    check(rejected.state == State::Rejected && rejected.message == "时段限制 请稍后重试");
    check(parse_login(R"({"result":"fail","result":"success","userIndex":"x"})").state == State::InvalidResponse);
    check(parse_login(R"({"result":"success","userIndex":"x"}garbage)").state == State::InvalidResponse);
    check(parse_login(R"({"result":"fail","message":"\ud800"})").state == State::InvalidResponse);
    check(parse_login(R"({"result":"fail","message":"\ud83d\ude03"})").message == "😃");
    check(parse_online(R"({"result":"success","devices":["ignored"]})").state == State::Success);
    check(parse_online(R"({"result":"fail"})").state == State::Offline);
    check(parse_online(R"({"result":"mystery"})").state == State::InvalidResponse);
    check(parse_online(R"({})").state == State::InvalidResponse);
    check(parse_logout(R"({"result":"success"})").state == State::Success);
    check(parse_logout(R"({"result":"fail","message":"session expired"})").state == State::Rejected);
    Credential credential; credential.username = L"synthetic-user"; credential.password = L"synth\"pass\\word";
    auto request = login_request(*target, credential, "校园网", options);
    check(request && request->method == "POST" && request->url == "http://portal.example:8080/eportal/inferface/authAPI/login");
    check(request->url.find("synthetic") == request->url.npos && request->url.find("pass") == request->url.npos);
    check(request->body.find(R"("password":"synth\"pass\\word")") != request->body.npos);
    check(request->body.find(R"("queryString":"wlanuserip=10.0.0.2&x=%2f")") != request->body.npos);
    check(request->body.find(R"("userAgent":"PC")") != request->body.npos);
    check(online_request(*target, "", options)->body == R"({"userip":"10.0.0.2","userIndex":""})");
    check(!logout_request(*target, "", options));
    check(logout_request(*target, "index", options)->body == R"({"userip":"10.0.0.2","userIndex":"index"})");
    {
        auto browser=*target;browser.protocol=Protocol::InterFace;
        Credential form;form.username=L"u@x";form.password=L"p&%";
        const auto page_request=page_info_request(browser,options);
        check(page_request && page_request->form &&
            page_request->url.ends_with("/eportal/InterFace.do?method=pageInfo") &&
            page_request->body=="queryString=wlanuserip%3D10.0.0.2%26x%3D%252f");
        auto submitted=login_request(browser,form,"",options);
        check(submitted && submitted->form && submitted->body.find("userId=u%2540x&password=p%2526%2525&")!=submitted->body.npos);
        browser.password_encrypt=true;browser.public_exponent="10001";
        browser.public_modulus=std::string(126,'f')+"c7";browser.query_string="mac=02-11-22-33-44-55";
        form.password=L"pw";
        submitted=login_request(browser,form,"",options);
        check(submitted && submitted->body.find("password=6fa57e9b3949abb1327675c2654ae113650c348852b6c515163737dacaafa1b1ecac076caf57b9a6bd5089e0cf63dbd9d3a4de1e79b4e2c84fe098bcd1ee0d04&")!=submitted->body.npos);
        browser.public_exponent="10001gar";
        check(!login_request(browser,form,"",options));
        browser.public_exponent="0";check(!login_request(browser,form,"",options));
        browser.public_exponent="10001";browser.public_modulus.back()='8';
        check(!login_request(browser,form,"",options));
        check(internet_available("10.0.0.2",options,[](const Request& request,const Options&){
            check(request.url=="https://cp.cloudflare.com/generate_204" && request.method=="GET" && request.body.empty() &&
                request.expected_source_ip=="10.0.0.2");return reply(204,"");
        })==State::Success);
        check(internet_available("10.0.0.2",options,[](const Request&,const Options&){return reply(200,"Portal");})!=State::Success);
        unsigned legacy_calls=0;
        check(internet_available("10.0.0.2",options,[&](const Request& request,const Options&){
            ++legacy_calls;
            if(request.url.starts_with("https://")) {
                Response value;value.state=State::NetworkError;value.error=ERROR_WINHTTP_INVALID_OPTION;return value;
            }
            check(request.url=="http://www.msftconnecttest.com/connecttest.txt" && request.expected_source_ip=="10.0.0.2");
            return reply(200,"Microsoft Connect Test");
        })==State::Success && legacy_calls==3);
    }
    int calls{};
    auto fake = [&](const Request& req, const Options&) {
        ++calls; check(req.url.ends_with("/login"));
        return reply(200, R"({"result":"fail","message":"synthetic-user synth\"pass\\word denied"})");
    };
    auto login_result = login(*target, credential, "", options, fake);
    check(login_result.state == State::Rejected && login_result.message == "[hidden] [hidden] denied" && calls == 1);
    Target untrusted = *target; untrusted.origin = "http://other.example";
    check(login(untrusted, credential, "", options, fake).state == State::UntrustedTarget && calls == 1);
    std::atomic_bool cancel{true}; options.cancel = &cancel;
    check(login(*target, credential, "", options, fake).state == State::Cancelled && calls == 1);
    options.cancel = nullptr;
    check(login(*target, credential, "", options, [](const Request&, const Options&) { return reply(302, {}, "http://evil.example"); }).state == State::UntrustedTarget);
    check(login(*target, credential, "", options, [](const Request&, const Options&) { return reply(403); }).state == State::Rejected);
    check(discover("http://123.123.123.123/", "10.0.0.2", options, [](const Request& req, const Options&) {
        check(req.method == "GET" && req.body.empty());
        return reply(302, {}, "http://portal.example:8080/eportal/index.jsp?x=1");
    }).target.has_value());
    check(discover("http://user:password@host/", "10.0.0.2", options, fake).state == State::InvalidInput);
    check(parse_login(std::string(65537, ' ')).state == State::InvalidResponse);

    // Native transport tests contact only an ephemeral loopback listener.
    WSADATA data{}; check(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    options.interface_index = interface_index(true); check(options.interface_index != 0);
    {
        Server server(wire(200, R"({"result":"success"})"));
        options.trusted_origins = {server.origin()};
        Target local{server.origin(), "synthetic=1", "127.0.0.1"};
        auto value = online(local, "synthetic-index", options);
        if (value.state != State::Success)
            std::cerr << "loopback state=" << static_cast<int>(value.state) << " error=" << value.transport_error << '\n';
        check(value.state == State::Success && value.http_status == 200);
        server.worker.join();
        check(server.received.starts_with("POST /eportal/inferface/authAPI/getOnlineUserInfo HTTP/1.1\r\n"));
        check(server.received.find(R"({"userip":"127.0.0.1","userIndex":"synthetic-index"})") != server.received.npos);
    }
    {
        Server server(wire(302, {}, "Location: http://127.0.0.1:1/eportal/index.jsp?synthetic=1\r\n"));
        options.trusted_origins = {server.origin()};
        auto value = discover(server.origin() + "/", "127.0.0.1", options);
        check(value.state == State::UntrustedTarget);
    }
    {
        Server server(wire(200, "{}"), std::chrono::milliseconds(250));
        options.trusted_origins = {server.origin()}; options.timeout = std::chrono::milliseconds(70);
        auto started = std::chrono::steady_clock::now();
        auto value = discover(server.origin() + "/", "127.0.0.1", options);
        check(value.state == State::Timeout && std::chrono::steady_clock::now() - started < std::chrono::milliseconds(220));
    }
    {
        Server server(wire(200, "{}"), std::chrono::milliseconds(250));
        options.trusted_origins = {server.origin()}; options.timeout = std::chrono::seconds(2);
        cancel = false; options.cancel = &cancel;
        std::thread abort([&] { std::this_thread::sleep_for(std::chrono::milliseconds(40)); cancel = true; });
        auto value = discover(server.origin() + "/", "127.0.0.1", options);
        abort.join(); check(value.state == State::Cancelled); options.cancel = nullptr;
    }
    {
        // Affinity is corroborated against the actual local socket address
        // before WinHttpWriteData. A route mismatch sends no credential body.
        const auto other_interface = interface_index(false);
        if (other_interface) {
            Server server(wire(200, "{}"));
            options.trusted_origins = {server.origin()}; options.interface_index = other_interface;
            Target local{server.origin(), "synthetic=1", "127.0.0.1"};
            auto value = login(local, credential, "", options);
            check(value.state == State::InterfaceUnavailable || value.state == State::NetworkError);
            server.worker.join();
            check(server.received.find("synthetic-user") == server.received.npos &&
                  server.received.find("synth") == server.received.npos);
        }
    }
    {
        Server server(wire(200, "{}"));
        options.trusted_origins = {server.origin()}; options.interface_index = interface_index(true);
        Target stale_ip{server.origin(), "synthetic=1", "192.0.2.1"};
        auto value = login(stale_ip, credential, "", options);
        check(value.state == State::InterfaceUnavailable);
        server.worker.join();
        check(server.received.find("synthetic-user") == server.received.npos &&
              server.received.find("synth") == server.received.npos);
    }
    {
        options.interface_index = 0;
        Request local("http://127.0.0.1:1/", "GET", {});
        check(send_winhttp(local, options).state == State::InterfaceUnavailable);
        options.interface_index = 0xfffffff0;
        check(send_winhttp(local, options).state == State::InterfaceUnavailable);
    }
    WSACleanup();
    std::cout << "portal_auth_tests: " << checks << " checks passed (synthetic and loopback only)\n";
}
