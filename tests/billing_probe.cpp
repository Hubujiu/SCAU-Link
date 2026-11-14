// Explicit, read-only research of the first saved account's billing pages.
// Never changes EAP state, submits a service operation, or prints private data.
#include "desktop/accounts.hpp"
#include "desktop/package_query.hpp"
#include "desktop/school_https.hpp"
#include "protocol.hpp"
#include <winrt/Windows.Data.Json.h>
#include <roapi.h>
#include <fstream>
#include <iostream>
#include <regex>
#include <set>
#include <stdexcept>

using namespace scau::desktop;
using namespace scau::desktop::detail;
namespace {
template<class T> struct Wipe {
    T& text;
    ~Wipe() { if (!text.empty()) SecureZeroMemory(text.data(), text.size() * sizeof(typename T::value_type)); }
};
void save(const std::filesystem::path& root, const std::string& name, const HttpsResult& reply) {
    std::ofstream(root / (name + ".bin"), std::ios::binary).write(reply.response.body.data(), reply.response.body.size());
    std::ofstream(root / (name + "-type.txt")) << reply.response.content_type;
    std::cout << "{\"page\":\"" << name << "\",\"httpStatus\":" << reply.response.status
              << ",\"bodyBytes\":" << reply.response.body.size() << "}\n";
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2 || std::wstring_view(argv[1]) != L"--live-own-account-readonly") return 2;
    if (FAILED(RoInitialize(RO_INIT_MULTITHREADED))) return 3;
    try {
        AccountStore store(data_directory()); const auto catalog = store.load(); Credential credential;
        if (!catalog.first_account() || !store.read(*catalog.first_account(), credential)) return 4;
        std::array<unsigned char, 6> mac{};
        const auto profile = locate_profile(data_directory(), executable_path());
        if (!profile.empty()) mac = scau::load_profile(profile).local;
        auto query = account_query_path(credential, mac); Wipe query_wipe{query};
        auto summary = school_https_request("GET", query, {});
        Wipe summary_wipe{summary.response.body}, summary_cookie_wipe{summary.response.session_cookie};
        auto decoded = decode_school_response(summary.response.body, summary.response.content_type);
        if (!decoded) throw std::runtime_error("Summary unavailable");
        Wipe decoded_wipe{*decoded};
        auto route = package_detail_login_path(*decoded); Wipe route_wipe{route};
        if (route.empty()) throw std::runtime_error("Route unavailable");
        auto login = school_https_request("GET", route, {});
        Wipe login_wipe{login.response.body}, login_cookie_wipe{login.response.session_cookie};
        auto cookie = login.response.session_cookie; Wipe cookie_wipe{cookie};
        if (login.state != TransportState::Complete || login.response.status != 200 || !valid_school_session(cookie))
            throw std::runtime_error("Session unavailable");
        auto refresh = school_https_request("POST",
            "/selfservice/module/userself/web/userself_ajax.jsf?methodName=indexBean.refreshSelfIndexData", {}, nullptr, nullptr, cookie);
        Wipe refresh_wipe{refresh.response.body}, refresh_cookie_wipe{refresh.response.session_cookie};
        auto status = decode_school_response(refresh.response.body, refresh.response.content_type);
        if (!status || refresh.state != TransportState::Complete || refresh.response.status != 200)
            throw std::runtime_error("Identity unavailable");
        Wipe status_wipe{*status};
        if (std::wstring(winrt::Windows::Data::Json::JsonObject::Parse(*status).GetNamedString(L"userId")) != credential.username)
            throw std::runtime_error("Wrong account");
        credential.clear();
        const auto destination = std::filesystem::current_path() / "captures/billing-api-20261114";
        std::filesystem::create_directories(destination);
        save(destination, "refresh", refresh);
        std::set<std::string> scripts;
        // These three GET pages are linked by the school's own index/detail JS.
        for (const auto& [name, path] : {
                std::pair{"package", "/selfservice/module/userself/web/portal_packagemoney.jsf"},
                {"business", "/selfservice/module/userself/web/business_detail.jsf"},
                {"consume", "/selfservice/module/userself/web/consume.jsf"}}) {
            auto reply = school_https_request("GET", path, {}, nullptr, nullptr, cookie);
            Wipe body_wipe{reply.response.body}, reply_cookie_wipe{reply.response.session_cookie};
            save(destination, name, reply);
            const std::regex pattern("src=[\"'](/selfservice/module/(?:userself|webcontent)/js/[A-Za-z0-9_-]+\\.js)[\"']");
            for (std::sregex_iterator at(reply.response.body.begin(), reply.response.body.end(), pattern), end; at != end; ++at)
                scripts.insert((*at)[1].str());
        }
        if (scripts.size() > 16) throw std::runtime_error("Too many scripts");
        for (const auto& script : scripts) {
            auto reply = school_https_request("GET", script, {}, nullptr, nullptr, cookie);
            Wipe body_wipe{reply.response.body}, reply_cookie_wipe{reply.response.session_cookie};
            save(destination, script.substr(script.rfind('/') + 1), reply);
        }
        std::cout << "{\"ownTargetVerified\":true,\"mutationRequests\":0}\n";
        RoUninitialize(); return 0;
    } catch (...) {
        RoUninitialize(); std::cout << "{\"billingResearchFailed\":true}\n"; return 1;
    }
}
