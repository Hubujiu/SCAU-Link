#include "desktop/service_query.hpp"
#include <winrt/base.h>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace scau::desktop;
using namespace scau::desktop::detail;
void require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
namespace {
struct Request { std::string method, path, body, cookie; };
enum class Mutation { Success, TimeoutCommitted, TimeoutUnchanged, Rejected, MarkerOnly };
struct Fixture {
    int state = 2;
    bool pause_permission = true, resume_permission = true, wrong_user = false, wrong_target = false,
         duplicate_target = false, disabled_confirm = false, duplicate_permission = false, redirect = false;
    std::wstring count = L"2";
    Mutation mutation = Mutation::Success;
    unsigned commits = 0;
    std::uint64_t now = 1000;
    std::vector<Request> requests;
    std::function<void(const Request&)> on_read;
    CampusSession session;
    Fixture() : session([this](auto method, auto path, auto body, auto cookie, auto) {
        return send(method, path, body, cookie);
    }, [this] { return now; }) {}
    static HttpsResult response(std::wstring_view text, std::string cookie = {}) {
        HttpsResult result; result.state = TransportState::Complete;
        result.response.complete = true; result.response.status = 200;
        result.response.body = winrt::to_string(text);
        result.response.content_type = "text/html; charset=utf-8";
        result.response.session_cookie = std::move(cookie);
        return result;
    }
    HttpsResult send(std::string_view method, std::string_view path, std::string_view body, std::string_view cookie) {
        requests.push_back({std::string(method), std::string(path), std::string(body), std::string(cookie)});
        const auto request = requests.back();
        if (path.find("newConfirm") == path.npos && on_read) on_read(request);
        if (path.starts_with("/selfservice/module/scgroup/web/login_judge2.jsf?s=")) {
            require(method == "GET" && body.empty() && cookie.empty(), "Account query uses its own empty-cookie GET");
            return response(LR"({"getNewLoginInfo":{"ballInfo":[
                {"id":"onlinedevice","type":"deviceNum","displayName":"在线设备","value":"2"},
                {"id":"packageandfee","url":"selfserviceurl/module/scgroup/web/login_judge2.jsf?userid=fixture&password=fixture-only&callBack=su_business_detail&channel=su&index=1&userIp=192.0.2.1"}
            ]}})", "JSESSIONID=information-fixture");
        }
        if (path.starts_with("/selfservice/module/scgroup/web/login_judge2.jsf?userid=")) {
            require(method == "GET" && body.empty() && cookie.empty(), "Information cookie cannot cross into the business web session");
            return response(L"<script>window.location='fixed-page';</script>", "JSESSIONID=web-fixture");
        }
        require(cookie == "JSESSIONID=web-fixture", "Read and mutation must use only their own isolated web session");
        if (redirect) {
            auto out = response({}); out.response.status = 302; out.response.location = "/login.jsf"; return out;
        }
        if (path == "/selfservice/module/webcontent/web/index_self.jsf") {
            require(method == "GET" && body.empty(), "Home is read-only");
            // The shared school head and a container have malformed quotes.
            // Neither may conceal a valid body input or supply a false target.
            std::wstring home = LR"(<head><input id="bad" value='literal '"' quote'></head><body>
                <!-- <input id="canSuspend" value="false"> -->
                <script>var fake='<input id="canSuspend" value="false">';</script>
                <div class="step1" -moz-user-select: none" onselectstart="return false">
                <input type="hidden" id="canSuspend" value=")";
            home += pause_permission ? L"true" : L"false";
            home += L"\"><input id='canResume' value='";
            home += resume_permission ? L"true" : L"false";
            home += L"'>";
            if (duplicate_permission) home += L"<input id='canSuspend' value='true'>";
            return response(home + L"</div></body>");
        }
        if (path.ends_with("methodName=indexBean.refreshSelfIndexData")) {
            require(method == "POST" && body.empty(), "Status refresh is the original empty, read-only POST");
            std::wstring json = L"{\"userId\":\"";
            json += wrong_user ? L"another-user" : L"fixture";
            json += L"\",\"userState\":" + std::to_wstring(state);
            if (!count.empty()) json += L",\"onlineNum\":\"" + count + L"\"";
            return response(json + L"}");
        }
        if (path == "/selfservice/module/userself/web/self_suspend.jsf" ||
            path == "/selfservice/module/userself/web/self_resume.jsf") {
            require(method == "GET" && body.empty(), "Opening a confirmation form cannot mutate service");
            const auto target = wrong_target ? L"another-user" : L"fixture";
            std::wstring form = L"<body><input id='targetUserId' type='hidden' value='" + std::wstring(target) + L"'>";
            if (duplicate_target) form += L"<input id='targetUserId' type='hidden' value='fixture'>";
            form += L"<input id='confirm' type='button' value='confirm'";
            if (disabled_confirm) form += L" disabled";
            return response(form + L"></body>");
        }
        require(path == "/selfservice/module/userself/web/userself_ajax.jsf?methodName=userSelfOperationBean.newConfirmSuspend" ||
                path == "/selfservice/module/userself/web/userself_ajax.jsf?methodName=userSelfOperationBean.newConfirmResume",
                "No unknown or device-kick endpoint can be requested");
        require(method == "POST" && body == "targetUserId=fixture", "Mutation contains exactly the reverified own target");
        ++commits;
        const bool pause = path.ends_with("newConfirmSuspend");
        if (mutation == Mutation::Rejected) return response(LR"({"data":"notAllowed"})");
        if (mutation != Mutation::TimeoutUnchanged && mutation != Mutation::MarkerOnly) {
            state = pause ? 1 : 2; count = pause ? L"0" : L"2";
        }
        if (mutation == Mutation::TimeoutCommitted || mutation == Mutation::TimeoutUnchanged) return {};
        return response(pause ? LR"({"data":"toSelfPause"})" : LR"({"data":"toSelfResume"})");
    }
    CampusView prepare() {
        Credential credential; credential.username = L"fixture"; credential.password = L"fixture-only";
        return session.prepare(credential, {});
    }
};
}
int main() {
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        {
            Fixture f;
            const auto view = f.prepare();
            require(view.error == CampusError::None && view.state == CampusState::Normal && view.can_pause &&
                    !view.can_resume && view.online_devices == 2 && f.session.prepared() && f.commits == 0,
                    "Read-only preparation verifies identity, normal state, form and count without any mutation");
            const auto paused = f.session.apply(CampusAction::Pause);
            require(paused.outcome == CampusOutcome::Success && paused.request_sent && f.commits == 1 &&
                    paused.view.state == CampusState::Paused && paused.view.online_devices == 0 && paused.view.can_resume,
                    "One confirmed pause is reconciled against the read-only server state");
            const auto repeated = f.session.apply(CampusAction::Pause);
            require(repeated.outcome == CampusOutcome::Expired && !repeated.request_sent && f.commits == 1,
                    "A state transition cannot repeat the same operation");
            f.session.refresh();
            const auto resumed = f.session.apply(CampusAction::Resume);
            require(resumed.outcome == CampusOutcome::Success && f.commits == 2 && resumed.view.state == CampusState::Normal,
                    "Resume uses its distinct endpoint and reconciles normal state");
        }
        for (int fault = 0; fault < 6; ++fault) {
            Fixture f;
            if (fault == 0) f.wrong_user = true;
            if (fault == 1) f.wrong_target = true;
            if (fault == 2) f.duplicate_target = true;
            if (fault == 3) f.disabled_confirm = true;
            if (fault == 4) f.duplicate_permission = true;
            if (fault == 5) f.redirect = true;
            const auto view = f.prepare();
            require(view.error != CampusError::None && !f.session.prepared() &&
                    f.session.apply(CampusAction::Pause).outcome == CampusOutcome::Expired && f.commits == 0,
                    "Wrong identity, ambiguous/disabled controls and login redirects fail closed before any mutation");
        }
        {
            Fixture f; f.pause_permission = false;
            const auto view = f.prepare();
            require(view.state == CampusState::Normal && !view.can_pause && !f.session.prepared() && f.commits == 0,
                    "Service permission is required even when an account is normal");
        }
        for (auto value : {L"", L"-1", L"unknown"}) {
            Fixture f; f.count = value;
            const auto view = f.prepare();
            require(view.error == CampusError::None && view.can_pause && !view.online_devices,
                    "Missing/malformed counts do not become zero or fabricate a device list");
        }
        {
            Fixture f; f.state = 1; f.count = L"0";
            const auto view = f.prepare();
            require(view.can_resume && !view.can_pause && view.online_devices == 0, "Paused server state is mapped independently of normal state");
        }
        {
            Fixture f; f.state = 7;
            require(f.prepare().state == CampusState::Unknown && !f.session.prepared() && f.commits == 0,
                    "Unrecognized service states cannot authorize a mutation");
        }
        for (auto mode : {Mutation::TimeoutCommitted, Mutation::TimeoutUnchanged, Mutation::Rejected, Mutation::MarkerOnly}) {
            Fixture f; f.prepare(); f.mutation = mode;
            const auto result = f.session.apply(CampusAction::Pause);
            const auto expected = mode == Mutation::TimeoutUnchanged ? CampusOutcome::Unknown
                                : mode == Mutation::Rejected ? CampusOutcome::Rejected : CampusOutcome::Success;
            require(result.outcome == expected && f.commits == 1 && result.request_sent,
                    "Timeouts reconcile read-only and never automatically retry a mutation");
            if (mode == Mutation::TimeoutUnchanged || mode == Mutation::MarkerOnly)
                require(!f.session.prepared() && f.session.apply(CampusAction::Pause).outcome == CampusOutcome::Expired && f.commits == 1,
                        "Unknown or unreconciled results need a new explicit preparation");
        }
        {
            Fixture f; f.prepare(); f.now += 120001;
            require(f.session.apply(CampusAction::Pause).outcome == CampusOutcome::Expired && f.commits == 0,
                    "Expired preparation cannot submit");
        }
        {
            Fixture f; f.prepare();
            f.on_read = [&](const auto& request) { if (request.path.ends_with("index_self.jsf")) f.now += 120001; };
            require(f.session.apply(CampusAction::Pause).outcome == CampusOutcome::Expired && f.commits == 0,
                    "Approval expiry is checked again after slow read-only revalidation");
        }
        {
            Fixture f; f.prepare(); bool current = true;
            f.on_read = [&](const auto&) { current = false; };
            require(f.session.apply(CampusAction::Pause, nullptr, [&] { return current; }).outcome == CampusOutcome::Expired && f.commits == 0,
                    "Credential changes during revalidation revoke commit authorization");
        }
        {
            Fixture f; f.prepare(); f.wrong_user = true;
            require(f.session.apply(CampusAction::Pause).outcome == CampusOutcome::Expired && f.commits == 0,
                    "Identity is reverified immediately before the operation");
        }
        {
            Fixture f; f.prepare(); std::atomic_bool cancelled = true;
            require(!f.session.apply(CampusAction::Pause, &cancelled).request_sent && f.commits == 0,
                    "Cancellation before commit causes no mutation");
        }
        std::cout << "PASS: offline own-session identity/permission/form checks, device counts, single POST, read-only reconciliation, expiry and cancellation\n";
        winrt::uninit_apartment(); return 0;
    } catch (const winrt::hresult_error& e) {
        std::cerr << "WinRT fixture error: " << std::hex << static_cast<unsigned>(e.code()) << '\n'; return 1;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; winrt::uninit_apartment(); return 1; }
}
