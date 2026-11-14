#include "desktop/wireless_session.hpp"
#include "desktop/platform.hpp"
#include "auth_result.hpp"
#include <filesystem>
#include <iostream>
#include <source_location>

using namespace scau;
using namespace scau::desktop;
namespace {
int checks{};
void check(bool passed, const std::source_location where = std::source_location::current()) {
    ++checks; if (!passed) { std::cerr << "wireless session check " << checks << " failed at " << where.line() << '\n'; std::abort(); }
}
portal::Response response(std::string body, unsigned status = 200) {
    portal::Response value; value.state = portal::State::Ready; value.status = status; value.body = std::move(body); return value;
}
struct Fixture {
    std::filesystem::path directory = std::filesystem::temp_directory_path() /
        (L"scau-wireless-session-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(checks));
    Credential credential;
    WirelessNetwork wifi;
    std::atomic_bool cancel{};
    WirelessSessionOptions options;
    WirelessCallbacks callbacks;
    int logins{}, logouts{}, online_events{}, recoveries{}, probes{}, polls{}, pauses{}, environment_checks{};
    std::string failure, login_body, logout_body;
    std::string page = R"({"service":[{"serviceName":"Campus","serviceDefault":true}]})";
    std::string login_reply = R"({"result":"success","userIndex":"owned-index","keepaliveInterval":1})";
    std::function<void(std::string_view)> before_request;
    std::function<portal::Response(const portal::Request&)> override_response;
    Fixture(bool approved = true) {
        wifi.mac = {0x02, 0x40, 0x50, 0x60, 0x70, 0x80}; wifi.index = 19;
        wifi.ipv4 = "10.1.0.2"; wifi.found = wifi.link_up = wifi.ready = true;
        credential.username = L"synthetic-user"; credential.password = L"synthetic-password";
        options.directory = directory; options.cancel = &cancel;
        options.network_provider = [&](const Mac&) { return wifi; };
        options.environment_ready = [&] { ++environment_checks; };
        options.pause = [&](std::chrono::milliseconds duration) {
            ++pauses; check(duration <= std::chrono::seconds(1));
            if (pauses > 150) cancel = true;
        };
        options.transport = [&](const portal::Request& request, const portal::Options& request_options) {
            check(request_options.interface_index == wifi.index);
            if (before_request) before_request(request.url);
            if (override_response) return override_response(request);
            return normal_response(request);
        };
        callbacks.online = [&] { ++online_events; cancel = true; };
        callbacks.recovering = [&] { ++recoveries; };
        callbacks.event = [&](std::string_view name) {
            check(name.starts_with("wireless_") && name.find("synthetic") == name.npos && name.find("http") == name.npos);
        };
        if (approved) save_wireless_origin(directory, wifi, "http://portal.example:8080");
    }
    portal::Response normal_response(const portal::Request& request) {
        if (request.method == "GET") {
            ++probes; check(request.body.empty());
            auto value = response({}, 302);
            value.location = "http://portal.example:8080/eportal/index.jsp?wlanuserip=" + wifi.ipv4 + "&synthetic=1";
            return value;
        }
        if (request.url.ends_with("/pageInfo")) return response(page);
        if (request.url.ends_with("/login")) {
            ++logins; login_body = request.body; check(online_events == 0 || logins > 1);
            check(request.url.find("synthetic") == request.url.npos);
            return response(login_reply);
        }
        if (request.url.ends_with("/logout")) { ++logouts; logout_body = request.body; return response(R"({"result":"success"})"); }
        if (request.url.ends_with("/getOnlineUserInfo")) {
            if (request.body.find("owned-index") != request.body.npos) { ++polls; return response(R"({"result":"success"})"); }
            return response(R"({"result":"fail"})");
        }
        check(false); return {};
    }
    int run() { return run_wireless_session(credential, options, callbacks, &failure); }
    ~Fixture() {
        // The directory is constructed exclusively below the system temp root.
        std::error_code ignored;
        if (directory.parent_path() == std::filesystem::temp_directory_path() &&
            directory.filename().wstring().starts_with(L"scau-wireless-session-")) std::filesystem::remove_all(directory, ignored);
    }
};
}
int main() {
    {
        Fixture test;test.options.allow_existing_network=true;int available=0;
        test.override_response=[&](const portal::Request& request) {
            check(request.method=="GET" && request.expected_source_ip==test.wifi.ipv4);
            return request.url.starts_with("https://")?response("",204):response("Already online");
        };
        test.callbacks.network_available=[&]{++available;test.cancel=true;};
        check(test.run()==0 && available==1 && test.online_events==0 && test.logins==0 && test.logouts==0);
    }
    {
        Fixture test;test.options.allow_existing_network=true;
        test.override_response=[&](const portal::Request& request) {
            auto result=response("Captive page");
            if(request.url.starts_with("https://"))result.state=portal::State::CertificateError;
            return result;
        };
        check(test.run()==auth_protocol_unsupported && test.online_events==0 && test.logins==0 && test.logouts==0);
    }
    {
        Fixture test;
        check(test.run() == 0);
        check(test.logins == 1 && test.online_events == 1 && test.logouts == 1 && test.environment_checks == 1);
        check(test.login_body.find(R"("service":"Campus")") != test.login_body.npos);
        check(test.logout_body.find("owned-index") != test.logout_body.npos);
        check(test.failure.empty());
    }
    {
        Fixture test(false);
        check(test.run() == auth_protocol_unsupported && test.failure == wireless_origin_unconfirmed);
        check(test.probes == 0 && test.logins == 0 && test.logouts == 0);
    }
    {
        Fixture test;
        test.override_response = [&](const portal::Request&) {
            auto value = response({}, 302); value.location = "http://other.example/eportal/index.jsp?q=1"; return value;
        };
        check(test.run() == auth_protocol_unsupported && test.failure == wireless_origin_changed);
        check(test.logins == 0 && test.online_events == 0);
    }
    {
        Fixture test;
        test.login_reply = R"({"result":"fail","message":"synthetic-user synthetic-password 时段限制"})";
        check(test.run() == auth_rejected && test.failure == "[hidden] [hidden] 时段限制");
        check(test.logins == 1 && test.logouts == 0 && test.online_events == 0);
        check(allows_account_retry(auth_rejected));
    }
    {
        Fixture test;
        test.login_reply = R"({"result":"unrecognized","message":"unknown outcome"})";
        check(test.run() == auth_protocol_unsupported && test.failure == wireless_login_uncertain && test.logins == 1);
        check(test.logouts == 0 && test.online_events == 0 && !allows_account_retry(auth_protocol_unsupported));
    }
    {
        Fixture test;
        test.override_response = [&](const portal::Request& request) {
            if (!request.url.ends_with("/login")) return test.normal_response(request);
            ++test.logins; portal::Response value; value.state = portal::State::Timeout; return value;
        };
        check(test.run() == auth_protocol_unsupported && test.failure == wireless_login_uncertain);
        check(test.logins == 1 && test.logouts == 0 && test.online_events == 0 && test.pauses == 0);
    }
    {
        Fixture test;
        test.override_response = [&](const portal::Request& request) {
            if (!request.url.ends_with("/getOnlineUserInfo")) return test.normal_response(request);
            return response(R"({"result":"success","userIndex":"unattributed-session"})");
        };
        check(test.run() == 0 && test.logins == 1 && test.online_events == 1 && test.logouts == 1);
        check(test.logout_body.find("unattributed-session") == test.logout_body.npos);
    }
    {
        Fixture test;
        test.before_request = [&](std::string_view url) { if (url.ends_with("/pageInfo")) test.cancel = true; };
        check(test.run() == 0 && test.logins == 0 && test.online_events == 0 && test.logouts == 0);
    }
    {
        Fixture test;
        test.page = R"({"service":[{"serviceName":"A"},{"serviceName":"B"}]})";
        check(test.run() == auth_protocol_unsupported && test.failure == wireless_service_ambiguous && test.logins == 0);
    }
    {
        Fixture test;
        test.page = R"({"service":[]})";
        check(test.run() == 0 && test.login_body.find(R"("service":"")") != test.login_body.npos);
    }
    {
        Fixture test;
        test.callbacks.online = [&] { ++test.online_events; test.wifi.ipv4 = "10.1.0.3"; test.cancel = true; };
        check(test.run() == 0 && test.logins == 1 && test.logouts == 0);
    }
    {
        Fixture test;
        bool changed = false;
        test.before_request = [&](std::string_view url) {
            if (url.ends_with("/pageInfo") && !changed) { test.wifi.ipv4 = "10.1.0.3"; changed = true; }
        };
        check(test.run() == 0 && test.probes == 2 && test.logins == 1 && test.recoveries == 1);
        check(test.login_body.find(R"("userip":"10.1.0.3")") != test.login_body.npos);
    }
    {
        Fixture test;
        test.callbacks.online = [&] { if (++test.online_events == 2) test.cancel = true; };
        test.options.pause = [&](std::chrono::milliseconds) {
            ++test.pauses;
            if (test.pauses == 1) test.wifi.link_up = test.wifi.ready = false;
            if (test.pauses == 2) { test.wifi.link_up = test.wifi.ready = true; test.wifi.ipv4 = "10.1.0.3"; }
            if (test.pauses > 5) test.cancel = true;
        };
        check(test.run() == 0 && test.online_events == 2 && test.logins == 2 && test.logouts == 1 && test.recoveries == 1);
        check(test.logout_body.find(R"("userip":"10.1.0.3")") != test.logout_body.npos);
    }
    {
        Fixture test;
        test.callbacks.online = [&] { ++test.online_events; };
        test.override_response = [&](const portal::Request& request) {
            if (request.url.ends_with("/getOnlineUserInfo") && request.body.find("owned-index") != request.body.npos) {
                ++test.polls; return response(R"({"result":"fail"})");
            }
            return test.normal_response(request);
        };
        check(test.run() == auth_server_terminated && test.failure == wireless_session_lost);
        check(test.pauses == 30 && test.polls == 1 && test.logins == 1 && test.logouts == 1 && !allows_account_retry(auth_server_terminated));
    }
    {
        Fixture test;
        test.callbacks.online = [&] { if (++test.online_events == 2) test.cancel = true; };
        test.override_response = [&](const portal::Request& request) {
            if (request.url.ends_with("/getOnlineUserInfo") && request.body.find("owned-index") != request.body.npos) {
                if (++test.polls == 1) { portal::Response value; value.state = portal::State::NetworkError; return value; }
                return response(R"({"result":"success"})");
            }
            return test.normal_response(request);
        };
        check(test.run() == 0 && test.logins == 1 && test.logouts == 1 && test.recoveries == 1 && test.pauses == 60);
    }
    {
        Fixture test;
        test.wifi.found = false;
        check(test.run() == auth_environment_error && test.logins == 0 && test.environment_checks == 0);
    }
    {
        Fixture test;
        test.cancel = true;
        check(test.run() == 0 && test.probes == 0 && test.logins == 0 && test.logouts == 0);
    }
    std::cout << "wireless_session_tests: " << checks << " checks passed (injected network/transport only)\n";
}
