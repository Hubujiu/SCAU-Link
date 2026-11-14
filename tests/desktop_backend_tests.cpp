#include "auth_result.hpp"
#include "desktop/backend.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <objbase.h>
#include <stdexcept>

using namespace scau::desktop;
void require(bool value, const char *why) {
    if (!value)
        throw std::runtime_error(why);
}
struct Fixture {
    HWND window{};
    std::unique_ptr<Backend> backend;
    std::vector<Event> events;
    static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l) {
        auto *self = reinterpret_cast<Fixture *>(GetWindowLongPtrW(h, GWLP_USERDATA));
        if (m == WM_NCCREATE) {
            self = static_cast<Fixture *>(reinterpret_cast<CREATESTRUCTW *>(l)->lpCreateParams);
            SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (m == backend_message) {
            std::unique_ptr<Event> value(reinterpret_cast<Event *>(l));
            if (self)
                self->events.push_back(std::move(*value));
            return 0;
        }
        return DefWindowProcW(h, m, w, l);
    }
    explicit Fixture(BackendOptions options) {
        window = CreateWindowExW(0, L"ScauLink.BackendFixture", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr,
                                 GetModuleHandleW(nullptr), this);
        require(window != nullptr, "Cannot create message-only test fixture");
        options.demo = true;
        options.demo_delay_ms = 5;
        options.retry_delay_ms = 5;
        options.switch_delay_ms = 5;
        backend = std::make_unique<Backend>(window, options);
        backend->initialize();
        wait([&] { return !events.empty() && events.back().kind == EventKind::Initialized; });
    }
    void pump() {
        MSG m{};
        while (PeekMessageW(&m, window, 0, 0, PM_REMOVE))
            DispatchMessageW(&m);
    }
    template <class F> void wait(F condition, unsigned timeout = 1500) {
        const auto end = GetTickCount64() + timeout;
        while (GetTickCount64() < end) {
            pump();
            if (condition())
                return;
            Sleep(2);
        }
        throw std::runtime_error("Timed out waiting for offline backend fixture");
    }
    std::vector<std::string> attempts() const {
        std::vector<std::string> ids;
        for (const auto &e : events)
            if (e.kind == EventKind::State && e.login_attempt)
                ids.push_back(e.account_id);
        return ids;
    }
    bool state(Status s) const {
        return std::any_of(events.begin(), events.end(),
                           [&](const auto &e) { return e.kind == EventKind::State && e.status == s; });
    }
    ~Fixture() {
        backend.reset();
        pump();
        DestroyWindow(window);
    }
};
int wmain() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    try {
        WNDCLASSW wc{};
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpfnWndProc = Fixture::proc;
        wc.lpszClassName = L"ScauLink.BackendFixture";
        RegisterClassW(&wc);
        {
            BackendOptions options;options.demo_packages=true;options.demo_package_delay_ms=80;
            Fixture f(options);const auto id=f.events.front().accounts.entries.front().id;
            f.backend->request_packages(id);
            f.wait([&]{return std::any_of(f.events.begin(),f.events.end(),[](const auto& e){
                return e.kind==EventKind::Package && e.package.state==PackageState::Loading;});});
            f.backend->connect();f.wait([&]{return f.state(Status::Online);});
            for(unsigned i=0;i<20;++i)f.backend->request_packages(id);
            const auto completed=[&]{return std::count_if(f.events.begin(),f.events.end(),[](const auto& e){
                return e.kind==EventKind::Package && e.package.state!=PackageState::Loading;});};
            f.wait([&]{return completed()>=2;});
            require(completed()==2 && std::count_if(f.events.begin(),f.events.end(),[](const auto& e){
                return e.kind==EventKind::Package && e.package.state==PackageState::Loading;})==1,
                "A late pre-login result must trigger one fresh query without duplicating an in-flight request");
        }
        {
            BackendOptions options;options.demo_failed_modes={ConnectionMode::Wired};
            Fixture f(options);
            Settings settings;settings.mode=ConnectionMode::Wireless8021x;
            settings.startup_modes={ConnectionMode::Wired,ConnectionMode::WirelessWeb,ConnectionMode::Wireless8021x};
            f.backend->save_preferences(settings);
            f.wait([&]{return f.events.back().kind==EventKind::SettingsSaved;});
            f.events.clear();f.backend->connect(true);
            f.wait([&]{return f.state(Status::Online);});
            std::vector<ConnectionMode> chosen;
            for(const auto& e:f.events)if(e.kind==EventKind::ModeSelected)chosen.push_back(e.connection_mode);
            require(chosen==std::vector<ConnectionMode>{ConnectionMode::Wired,ConnectionMode::WirelessWeb},
                "Startup must follow configured order and stop after a successful mode");
            f.backend->disconnect();f.wait([&]{return !f.backend->running() && f.state(Status::Offline);});
            f.events.clear();f.backend->connect(false);
            f.wait([&]{return f.state(Status::Online);});
            chosen.clear();
            for(const auto& e:f.events)if(e.kind==EventKind::ModeSelected)chosen.push_back(e.connection_mode);
            require(chosen==std::vector<ConnectionMode>{ConnectionMode::Wireless8021x},
                "Startup fallback cannot overwrite the user's last manual selection");
        }
        {
            BackendOptions options;options.demo_terminal=scau::auth_protocol_unsupported;
            Fixture f(options);Settings settings;
            settings.startup_modes={ConnectionMode::WirelessWeb,ConnectionMode::Wired};
            f.backend->save_preferences(settings);
            f.wait([&]{return f.events.back().kind==EventKind::SettingsSaved;});
            f.events.clear();f.backend->connect(true);
            f.wait([&]{return f.state(Status::Error) && !f.backend->running();});
            require(std::count_if(f.events.begin(),f.events.end(),[](const auto& e){return e.kind==EventKind::ModeSelected;})==1,
                "An unknown login result must not submit credentials through another mode");
        }
        {
            BackendOptions options; options.demo_wireless_8021x = true; options.demo_first_run = true;
            Fixture f(options);
            require(f.events.front().settings.mode == ConnectionMode::Wireless8021x &&
                    !f.events.front().credentials && f.events.front().adapter == L"WLAN",
                    "SCAUNET_1x first use must require no imported profile or extra EAP fields");
            auto credential = std::make_shared<Credential>();
            credential->username = L"wireless-fixture"; credential->password = L"synthetic-only";
            f.backend->save_account({},credential,true);
            f.wait([&]{return f.state(Status::Online);});
            require(f.attempts().size() == 1, "Saving the first wireless 802.1X account must start its selected mode");
            f.backend->save_preferences({});
            f.wait([&]{return f.events.back().kind == EventKind::SettingsSaved;});
            require(!f.events.back().success && f.backend->running(),"An online WLAN session cannot switch to wired mode");
            f.backend->disconnect();f.wait([&]{return !f.backend->running() && f.state(Status::Offline);});
            Settings settings;settings.mode=ConnectionMode::Wireless8021x;
            f.backend->save_preferences(settings);
            f.wait([&]{return f.events.back().kind == EventKind::SettingsSaved;});
            require(f.events.back().success && f.events.back().settings.mode == ConnectionMode::Wireless8021x,
                    "WLAN mode must persist after manual disconnection");
        }
        {
            BackendOptions options; options.demo_wireless = options.demo_portal = true;
            Fixture f(options);
            require(f.events.front().settings.mode == ConnectionMode::WirelessWeb && f.events.front().adapter == L"WLAN",
                    "Wireless mode must initialize its own adapter label");
            f.backend->connect();
            const auto portal = [&]() -> const Event* {
                const auto found = std::find_if(f.events.begin(),f.events.end(),[](const auto& e){return e.kind == EventKind::PortalDetected;});
                return found == f.events.end() ? nullptr : &*found;
            };
            f.wait([&] {return portal() != nullptr;});
            const auto ticket = portal()->portal_ticket;
            require(!ticket.empty() && portal()->portal_origin == "https://portal.example.test" && !f.state(Status::Online),
                    "A discovered origin needs approval before the demo can become online");
            Settings wired;
            f.backend->save_preferences(wired);
            f.wait([&] {return f.events.back().kind == EventKind::SettingsSaved;});
            require(!f.events.back().success && f.backend->running(), "Cannot switch modes during portal approval");
            f.backend->approve_portal("wrong-ticket");
            f.backend->save_preferences(wired); // IO queue barrier.
            f.wait([&] {return std::count_if(f.events.begin(),f.events.end(),[](const auto& e){return e.kind == EventKind::SettingsSaved;}) == 2;});
            require(!f.state(Status::Online),"A stale approval cannot release authentication");
            f.backend->approve_portal(ticket);
            f.wait([&] {return f.state(Status::Online);});
            require(f.attempts().size() == 1, "Approval resumes the same account without a new login round");
            f.backend->disconnect();
            f.wait([&] {return !f.backend->running() && f.state(Status::Offline);});
            f.backend->save_preferences(wired);
            f.wait([&] {return f.events.back().kind == EventKind::SettingsSaved && f.events.back().success;});
            require(f.events.back().settings.mode == ConnectionMode::Wired,"Offline mode switching must be available");
        }
        {
            BackendOptions options; options.demo_wireless = options.demo_portal = true;
            Fixture f(options); f.backend->connect();
            f.wait([&] {return f.events.back().kind == EventKind::PortalDetected;});
            const auto ticket = f.events.back().portal_ticket;
            f.backend->disconnect();
            f.wait([&] {return !f.backend->running() && f.state(Status::Offline);});
            f.backend->approve_portal(ticket);
            f.backend->save_preferences({});
            f.wait([&] {return f.events.back().kind == EventKind::SettingsSaved;});
            require(!f.state(Status::Online),"Disconnect revokes an outstanding wireless approval");
        }
        for (int outcome = 0; outcome < 3; ++outcome) {
            BackendOptions options; options.demo_password_unknown = outcome == 1; options.demo_password_rejected = outcome == 2;
            Fixture f(options); const auto account = f.events.front().accounts.entries.front();
            auto input = std::make_shared<PasswordEdit>(); input->old_password = L"demo-only";
            input->new_password = input->confirmation = L"new-demo-only";
            const auto result = [&](unsigned request) -> const Event* {
                const auto found = std::find_if(f.events.begin(),f.events.end(),[&](const auto& e){
                    return e.kind == EventKind::PasswordChanged && e.password_request == request;
                });
                return found == f.events.end() ? nullptr : &*found;
            };
            f.backend->change_password(account.id,account.secret_id,input,1);
            f.wait([&] {return result(1) != nullptr;});
            const auto* changed = result(1);
            require(changed->password_change.request_sent && changed->success == (outcome == 0) &&
                    changed->password_local_saved == (outcome == 0),"Only explicit success commits the saved credential");
            const auto updated = *changed->accounts.find(account.id);
            require((updated.secret_id != account.secret_id) == (outcome == 0) &&
                    input->old_password.empty() && input->new_password.empty() && input->confirmation.empty() &&
                    f.attempts().empty() && !f.backend->running(),
                    "Password change clears input, preserves account on failure, and cannot start network authentication");
            require(changed->password_change.outcome == (outcome == 0 ? PasswordChangeOutcome::Success :
                outcome == 1 ? PasswordChangeOutcome::Unknown : PasswordChangeOutcome::Rejected),"Exact remote outcome reaches UI");
            auto replay = std::make_shared<PasswordEdit>(); replay->old_password = outcome ? L"demo-only" : L"new-demo-only";
            replay->new_password = replay->confirmation = L"another-demo";
            f.backend->change_password(account.id,updated.secret_id,replay,1);
            f.wait([&] {return std::count_if(f.events.begin(),f.events.end(),[](const auto& e){return e.kind == EventKind::PasswordChanged;}) == 2;});
            require(!f.events.back().password_change.request_sent &&
                    f.events.back().password_change.error == PasswordChangeError::AlreadySubmitted,
                    "Repeated request ID cannot cause a second password mutation");
            if (outcome == 0) {
                auto stale = std::make_shared<PasswordEdit>(); stale->old_password = L"new-demo-only";
                stale->new_password = stale->confirmation = L"third-demo";
                f.backend->change_password(account.id,account.secret_id,stale,2);
                f.wait([&] {return result(2) != nullptr;});
                require(!result(2)->password_change.request_sent && result(2)->password_change.error == PasswordChangeError::Stale,
                        "A stale account snapshot cannot submit changed credentials");
                auto verify = std::make_shared<PasswordEdit>(); verify->old_password = L"new-demo-only";
                verify->new_password = verify->confirmation = L"third-demo";
                f.backend->change_password(account.id,updated.secret_id,verify,3);
                f.wait([&] {return result(3) != nullptr;});
                require(result(3)->success,"A successful change must actually replace the saved password for future use");
            }
        }
        {
            BackendOptions options; options.demo_first_run = true;
            Fixture f(options);
            require(!f.events.front().profile && !f.events.front().credentials &&
                    f.events.front().accounts.entries.empty(), "First run starts without imported configuration or saved accounts");
            auto secret = std::make_shared<Credential>();
            secret->username = L"first-run-demo"; secret->password = L"synthetic-only";
            f.backend->save_account({},secret,true);
            f.wait([&] { return f.state(Status::Online); });
            const auto saved = std::find_if(f.events.begin(),f.events.end(),[](const auto& e) {
                return e.kind == EventKind::AccountsChanged && e.success;
            });
            require(saved != f.events.end() && saved->accounts.entries.size() == 1 && f.attempts().size() == 1 &&
                    f.attempts().front() == saved->accounts.entries.front().id,
                    "Saving account and password with Login must directly start authentication, with no import step");
            f.backend->disconnect();
            f.wait([&] { return !f.backend->running(); });
        }
        {
            Fixture f({});
            const auto account = f.events.front().accounts.entries.front();
            auto result = [&](unsigned request) -> const Event* {
                const auto found = std::find_if(f.events.begin(), f.events.end(), [&](const auto& e) {
                    return e.kind == EventKind::Campus && e.campus_request == request;
                });
                return found == f.events.end() ? nullptr : &*found;
            };
            f.backend->prepare_campus(account.id, 1);
            f.wait([&] { return result(1) != nullptr; });
            const auto ticket = result(1)->campus_ticket;
            require(!ticket.empty() && result(1)->campus.state == CampusState::Normal &&
                    result(1)->campus.online_devices == 2 && result(1)->package_secret == account.secret_id &&
                    f.attempts().empty() && !f.backend->running(),
                    "Campus read-only preparation carries exact account/version and cannot start authentication");
            f.backend->change_campus(account.id, ticket, CampusAction::Pause, 2);
            f.wait([&] { return result(2) != nullptr; });
            const auto resume_ticket = result(2)->campus_ticket;
            require(result(2)->campus_outcome == CampusOutcome::Success &&
                    result(2)->campus.state == CampusState::Paused && result(2)->campus.online_devices == 0 &&
                    !resume_ticket.empty() && resume_ticket != ticket, "One-use approval changes only the selected demo account");
            f.backend->change_campus(account.id, ticket, CampusAction::Pause, 3);
            f.wait([&] { return result(3) != nullptr; });
            require(result(3)->campus_outcome == CampusOutcome::Expired && result(3)->campus_ticket.empty(),
                    "Replayed approval cannot submit another mutation");
            f.backend->prepare_campus(account.id, 4);
            f.wait([&] { return result(4) != nullptr; });
            require(result(4)->campus.state == CampusState::Paused, "Replay cannot change the paused state");
            const auto refreshed = result(4)->campus_ticket;
            f.backend->change_campus(account.id, refreshed, CampusAction::Resume, 5);
            f.wait([&] { return result(5) != nullptr; });
            require(result(5)->campus_outcome == CampusOutcome::Success &&
                    result(5)->campus.state == CampusState::Normal, "Resume needs a fresh selected-account approval");
            const auto old = result(5)->campus_ticket;
            auto changed = std::make_shared<Credential>();
            changed->username = account.username; changed->password = L"changed-demo-only";
            f.backend->save_account(account.id, changed);
            f.backend->change_campus(account.id, old, CampusAction::Pause, 6);
            f.wait([&] { return result(6) != nullptr; });
            require(result(6)->campus_outcome == CampusOutcome::Expired && !result(6)->campus_request_sent &&
                    f.attempts().empty(), "Changing credentials immediately revokes pending approval");
            f.backend->prepare_campus(account.id, 7);
            f.wait([&] { return result(7) != nullptr; });
            const auto valid = result(7)->campus_ticket;
            const auto another = f.events.front().accounts.entries[1].id;
            f.backend->change_campus(another, valid, CampusAction::Pause, 8);
            f.wait([&] { return result(8) != nullptr; });
            require(result(8)->campus_outcome == CampusOutcome::Expired && !result(8)->campus_request_sent,
                    "A ticket for one account cannot target another account");
        }
        {
            BackendOptions options;
            options.demo_packages = true;
            Fixture f(options);
            const auto account = f.events.front().accounts.entries.front();
            f.backend->request_packages(account.id);
            f.wait([&] { return f.events.back().kind == EventKind::Package &&
                               f.events.back().package.state == PackageState::Ready; });
            require(f.events.back().account_id == account.id && f.events.back().package_secret == account.secret_id &&
                        f.events.back().package.balance == 13650 && f.events.back().package.monthly_fee == 3000,
                    "Package result must carry its exact account/credential version");
            const auto before = f.events.size();
            f.backend->request_packages(account.id);
            const auto deadline = GetTickCount64() + 60;
            while (GetTickCount64() < deadline) { f.pump(); Sleep(2); }
            require(f.events.size() == before, "Repeated visible-page requests must coalesce within cache TTL");
            auto changed = std::make_shared<Credential>();
            changed->username = account.username; changed->password = L"changed-demo-only";
            f.backend->save_account(account.id, changed);
            f.wait([&] { return f.events.back().kind == EventKind::AccountsChanged; });
            const auto updated = *f.events.back().accounts.find(account.id);
            require(updated.secret_id != account.secret_id, "Credential update must get a new query cache version");
            f.backend->request_packages(account.id);
            f.wait([&] { return f.events.back().kind == EventKind::Package &&
                               f.events.back().package.state == PackageState::Ready; });
            require(f.events.back().package_secret == updated.secret_id, "Credential change must invalidate package TTL");
        }
        {
            BackendOptions options;
            options.demo_failover = true;
            Fixture f(options);
            const auto catalog = f.events.front().accounts;
            f.backend->connect();
            f.wait([&] { return f.state(Status::Online); });
            require(f.attempts() == std::vector<std::string>{catalog.entries[0].id, catalog.entries[0].id,
                                                             catalog.entries[1].id},
                    "Current account must retry once before the next account succeeds");
            auto online = std::find_if(f.events.begin(), f.events.end(), [](const auto &e) {
                return e.kind == EventKind::State && e.status == Status::Online;
            });
            require(online->username == catalog.entries[1].username,
                    "Active identity must match the succeeding fallback account");
            f.backend->pin_account(catalog.entries[2].id);
            f.wait([&] { return f.events.back().kind == EventKind::AccountsChanged; });
            require(f.events.back().accounts.first_account()->id == catalog.entries[2].id &&
                        f.attempts().size() == 3,
                    "Pin must change list order without replacing the active session");
            f.backend->disconnect();
            f.wait([&] { return f.state(Status::Offline) && !f.backend->running(); });
        }
        {
            BackendOptions options;
            options.demo_failure = true;
            Fixture f(options);
            const auto catalog = f.events.front().accounts;
            f.backend->connect();
            f.wait([&] { return f.state(Status::Error); });
            const auto ids = f.attempts();
            require(ids.size() == 6, "All-failed round must have exactly two tries per saved account");
            for (const auto &row : catalog.entries)
                require(std::count(ids.begin(), ids.end(), row.id) == 2,
                        "No account may exceed one retry in a failed round");
            require(f.events.back().message == L"unknown" && !f.backend->running(),
                    "Exhaustion must stop with one final failure state");
            require(f.events.back().username == catalog.entries.back().username &&
                        f.events.back().account_id == catalog.entries.back().id,
                    "Failure reason must belong to the final attempted account");
        }
        {
            BackendOptions options;
            options.demo_failure = true;
            options.demo_failure_reason = "已达到同时在线用户数量上限";
            Fixture f(options);
            f.backend->connect();
            f.wait([&] { return f.state(Status::Error); });
            require(f.events.back().message == L"已达到同时在线用户数量上限" && f.attempts().size() == 6,
                    "Final rejection must show the server reason after the normal account retry sequence");
            f.backend->disconnect();
            f.wait([&] { return f.events.back().status == Status::Offline; });
            require(f.events.back().message.empty(), "Manual stop must clear the previous failure message");
        }
        {
            BackendOptions options;
            options.demo_terminal = scau::auth_environment_error;
            options.demo_failure = true;
            options.demo_failure_reason = "Windows 无线认证权限不足";
            Fixture f(options);
            f.backend->connect();
            f.wait([&] { return f.state(Status::Error); });
            require(f.attempts().size() == 1, "Environment failure must stop without retrying all accounts");
            require(f.events.back().message == L"Windows 无线认证权限不足", "Wireless infrastructure reason must reach the UI without becoming an account rejection");
        }
        {
            BackendOptions options;
            options.demo_failure = true;
            Fixture f(options);
            f.backend->connect();
            f.wait([&] { return !f.attempts().empty(); });
            f.backend->disconnect();
            f.wait([&] { return f.state(Status::Offline) && !f.backend->running(); });
            const auto count = f.attempts().size();
            const auto end = GetTickCount64() + 100;
            while (GetTickCount64() < end) {
                f.pump();
                Sleep(2);
            }
            require(f.attempts().size() == count && !f.state(Status::Error),
                    "Manual disconnect must cancel retries and all subsequent accounts");
        }
        {
            BackendOptions options;
            Fixture f(options);
            auto value = std::make_shared<Credential>();
            value->username = L"saved-demo-account";
            value->password = L"test-only";
            const auto original_first = f.events.front().accounts.first_account()->id;
            f.backend->save_account({}, value, true);
            f.wait([&] { return f.state(Status::Online); });
            const auto saved = std::find_if(f.events.begin(), f.events.end(), [](const auto &e) {
                return e.kind == EventKind::AccountsChanged;
            });
            require(saved != f.events.end() && saved->success && saved->accounts.entries.size() == 4 &&
                        saved->accounts.first_account()->id == original_first &&
                        f.attempts() == std::vector<std::string>{original_first},
                    "A new account must append; every new login round begins with the first visible row");
        }
        {
            BackendOptions options;
            Fixture f(options);
            auto value = std::make_shared<Credential>();
            value->username = L"extra-demo-account";
            value->password = L"test-only";
            f.backend->save_account({}, value, true);
            f.backend->disconnect();
            f.wait([&] {
                return std::any_of(f.events.begin(), f.events.end(),
                                   [](const auto &e) { return e.kind == EventKind::AccountsChanged; });
            });
            require(f.attempts().empty() && !f.backend->running(),
                    "Disconnect must revoke queued save-and-login work");
        }
        {
            BackendOptions options;
            options.demo_failover = true;
            Fixture f(options);
            const auto c = f.events.front().accounts;
            f.backend->reorder_accounts({c.entries[2].id, c.entries[0].id, c.entries[1].id});
            f.wait([&] { return f.events.back().kind == EventKind::AccountsChanged; });
            require(f.events.back().accounts.entries.front().id == c.entries[2].id &&
                        f.events.back().accounts.entries[1].id == c.entries[0].id,
                    "Drag reorder must become the only authentication order");
            f.events.clear();
            f.backend->connect();
            f.wait([&] { return f.state(Status::Online); });
            require(f.attempts() ==
                        std::vector<std::string>{c.entries[2].id, c.entries[2].id, c.entries[0].id},
                    "Authentication must retry the first row once, then use the second row");
        }
        {
            BackendOptions options;
            Fixture f(options);
            const auto original = f.events.front().accounts;
            f.backend->remove_account(original.entries.front().id);
            f.wait([&] { return f.events.back().kind == EventKind::AccountsChanged; });
            const auto &removed = f.events.back();
            require(removed.success && removed.refresh_form && removed.accounts.entries.size() == 2 &&
                        removed.accounts.first_account()->id == original.entries[1].id,
                    "Removing the first saved account must promote the next visible row");
            f.events.clear();
            f.backend->connect();
            f.wait([&] { return f.state(Status::Online); });
            require(f.attempts() == std::vector<std::string>{original.entries[1].id},
                    "Login after removal must begin with the promoted first row");
        }
        std::cout << "PASS: offline asynchronous multi-account failover, exhaustion, cancellation, pinning "
                     "and ordering\n";
        CoUninitialize();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        CoUninitialize();
        return 1;
    }
}
