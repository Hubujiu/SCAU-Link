#include "backend.hpp"
#include "package_retry.hpp"
#include "connection_setup.hpp"
#include "portal_auth.hpp"
#include "wireless_session.hpp"
#include "auth_result.hpp"
#include "profile_store.hpp"
#include "protocol.hpp"
#include "supervisor.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <stdexcept>
#include <roapi.h>
#include <limits>

namespace scau::desktop {
namespace {
std::wstring stamp() {
    SYSTEMTIME s{};
    GetSystemTime(&s);
    wchar_t text[64]{};
    swprintf_s(text, L"%04u%02u%02u-%02u%02u%02u-%03u-%u", s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute,
               s.wSecond, s.wMilliseconds, GetCurrentProcessId());
    return text;
}
} // namespace
Backend::Backend(HWND window, BackendOptions options)
    : window_(window), options_(options), executable_(executable_path()) {
    io_thread_ = std::thread([this] { work(); });
    try { package_thread_ = std::thread([this] { package_work(); }); }
    catch (...) {
        { std::lock_guard lock(queue_mutex_); quitting_ = true; }
        queue_cv_.notify_one(); io_thread_.join(); throw;
    }
}
Backend::~Backend() {
    interrupted_ = true;
    ++generation_;
    package_quit_ = true;
    package_cv_.notify_one();
    {
        std::lock_guard lock(queue_mutex_);
        quitting_ = true;
        queue_.clear();
    }
    queue_cv_.notify_one();
    if (io_thread_.joinable())
        io_thread_.join();
    if (package_thread_.joinable())
        package_thread_.join();
    if (auth_thread_.joinable())
        auth_thread_.join();
}
void Backend::request_packages(std::string id) {
    queue([this, id = std::move(id)] {
        if (package_quit_) return;
        std::array<unsigned char, 6> mac{};
        unsigned interface_index = 0;
        if (!options_.demo && !profile_.empty()) {
            try { mac = load_profile(profile_).local; } catch (const std::exception&) {}
        }
        if (!options_.demo && (running_ ? session_mode_.load() : mode_) != ConnectionMode::Wired) {
            const auto network = current_wireless_network();
            if (network.found) {mac = network.mac; interface_index = network.index;}
        }
        for (const auto& entry : catalog_.entries) {
            if (!id.empty() && entry.id != id) continue;
            const auto key = entry.id + ":" + entry.secret_id;
            {
                std::lock_guard lock(package_mutex_);
                const auto now = GetTickCount64();
                if(package_inflight_.contains(key))continue;
                if (auto due = package_due_.find(key); due != package_due_.end() && now < due->second) continue;
                package_due_[key] = now + 10000; // In-flight deduplication; failures use a short retry below.
                package_inflight_.insert(key);
                Event e; e.kind = EventKind::Package; e.account_id = entry.id; e.package_secret = entry.secret_id;
                e.package.state = PackageState::Loading;
                post(std::move(e));
                PackageTask task;task.account=entry;task.mac=mac;task.connection_epoch=package_connection_epoch_.load();
                task.interface_index=interface_index;
                package_queue_.push_back(std::move(task));
            }
            package_cv_.notify_one();
        }
    });
}
void Backend::prepare_campus(std::string id, unsigned request) {
    request_campus(std::move(id), request, false, {}, CampusAction::Pause);
}
void Backend::change_campus(std::string id, std::string ticket, CampusAction action, unsigned request) {
    request_campus(std::move(id), request, true, std::move(ticket), action);
}
void Backend::request_campus(std::string id, unsigned request, bool apply, std::string ticket, CampusAction action) {
    const auto epoch = campus_epoch_.load();
    queue([this, id = std::move(id), request, apply, ticket = std::move(ticket), action, epoch] {
        const auto* entry = catalog_.find(id);
        if (!entry || package_quit_) return;
        PackageTask task; task.account = *entry; task.request = request; task.epoch = epoch;
        task.kind = apply ? QueryKind::CampusApply : QueryKind::CampusPrepare;
        task.ticket = ticket; task.action = action;
        if (!options_.demo && !profile_.empty()) {
            try { task.mac = load_profile(profile_).local; } catch (...) {}
        }
        {
            std::lock_guard lock(package_mutex_);
            // Explicit operations precede background billing work, but retain
            // their own order so another view cannot overtake a confirmed POST.
            const auto background = std::find_if(package_queue_.begin(), package_queue_.end(),
                [](const auto& queued) { return queued.kind == QueryKind::Package; });
            package_queue_.insert(background, std::move(task));
        }
        package_cv_.notify_one();
    });
}
void Backend::campus_work(const PackageTask& task) {
    Event e; e.kind = EventKind::Campus; e.account_id = task.account.id;
    e.package_secret = task.account.secret_id; e.campus_request = task.request;
    e.campus_change = task.kind == QueryKind::CampusApply; e.campus_action = task.action;
    const auto current = [&] { return !package_quit_ && campus_epoch_.load() == task.epoch; };
    const auto same = campus_account_ == task.account.id && campus_secret_ == task.account.secret_id &&
                      campus_snapshot_epoch_ == task.epoch;
    try {
        if (!current() || (e.campus_change && (!same || task.ticket.empty() || task.ticket != campus_ticket_))) {
            e.campus_outcome = CampusOutcome::Expired; e.campus.error = CampusError::Stale;
        } else if (options_.demo) {
            if (!e.campus_change) {
                campus_account_ = task.account.id; campus_secret_ = task.account.secret_id;
                campus_snapshot_epoch_ = task.epoch;
            }
            auto& state = campus_demo_states_[task.account.id];
            if (state == CampusState::Unknown) state = CampusState::Normal;
            if (e.campus_change) {
                const bool permitted = task.action == CampusAction::Pause ? state == CampusState::Normal : state == CampusState::Paused;
                if (permitted) { state = task.action == CampusAction::Pause ? CampusState::Paused : CampusState::Normal; e.campus_outcome = CampusOutcome::Success; }
                else e.campus_outcome = CampusOutcome::Expired;
            }
            e.campus.state = state; e.campus.can_pause = state == CampusState::Normal;
            e.campus.can_resume = state == CampusState::Paused; e.campus.online_devices = state == CampusState::Paused ? 0u : 2u;
        } else if (e.campus_change) {
            campus_ticket_.clear(); // One-use approval, including unknown outcomes.
            if (!campus_session_) throw std::runtime_error("Missing campus session");
            const auto result = campus_session_->apply(task.action, &package_quit_, current);
            e.campus = result.view; e.campus_outcome = result.outcome; e.campus_request_sent = result.request_sent;
        } else {
            if (same && campus_session_) e.campus = campus_session_->refresh(&package_quit_);
            if (!same || !campus_session_ || e.campus.error == CampusError::Auth) {
                campus_session_ = std::make_unique<CampusSession>();
                campus_account_ = task.account.id; campus_secret_ = task.account.secret_id;
                campus_snapshot_epoch_ = task.epoch;
                Credential credential;
                if (!accounts_ || !accounts_->read(task.account, credential)) throw std::runtime_error("Missing campus credential");
                e.campus = campus_session_->prepare(credential, task.mac, &package_quit_);
            }
        }
    } catch (...) { e.campus.error = CampusError::Data; }
    campus_ticket_.clear();
    if (current() && campus_account_ == task.account.id && campus_secret_ == task.account.secret_id &&
        campus_snapshot_epoch_ == task.epoch && e.campus.error == CampusError::None &&
        (options_.demo || (campus_session_ && campus_session_->prepared())) &&
        (e.campus.can_pause || e.campus.can_resume) && e.campus_outcome != CampusOutcome::Unknown &&
        e.campus_outcome != CampusOutcome::Expired) campus_ticket_ = new_account_id();
    e.campus_ticket = campus_ticket_;
    if (e.campus_change) log(e.campus_outcome == CampusOutcome::Success
                                ? (task.action == CampusAction::Pause ? "campus_paused" : "campus_resumed")
                                : e.campus_outcome == CampusOutcome::Unknown ? "campus_change_unknown" : "campus_change_not_applied");
    if (!package_quit_) post(std::move(e));
}
void Backend::package_work() {
    const auto apartment = RoInitialize(RO_INIT_MULTITHREADED);
    PackageCooldown cooldown;
    unsigned cooldown_epoch = package_connection_epoch_.load();
    std::map<std::string,std::pair<unsigned,unsigned>> billing_retries;
    for (;;) {
        PackageTask task;
        {
            std::unique_lock lock(package_mutex_);
            package_cv_.wait(lock, [&] { return package_quit_ || !package_queue_.empty(); });
            if (package_quit_) break;
            task = std::move(package_queue_.front()); package_queue_.pop_front();
        }
        if (task.kind != QueryKind::Package) {
            campus_work(task);
            continue;
        }
        Event e; e.kind = EventKind::Package; e.account_id = task.account.id; e.package_secret = task.account.secret_id;
        e.package.state = PackageState::Unsupported;
        const auto epoch = package_connection_epoch_.load();
        if (epoch != cooldown_epoch) {cooldown.reset();cooldown_epoch=epoch;}
        try {
            if (options_.demo) {
                const auto ready=GetTickCount64()+options_.demo_package_delay_ms;
                while(!package_quit_ && GetTickCount64()<ready)Sleep(5);
                if (options_.demo_packages) {
                    // Explicit, synthetic demo fixture; no network/credential access.
                    e.package = parse_package_response(LR"({"getNewLoginInfo":{"ballInfo":[
                        {"id":"myFee","displayName":"账户余额","value":"136.50元"},
                        {"displayName":"每月扣费","value":"30.00元"},
                        {"displayName":"到期日期","value":"2026-12-10"},
                        {"displayName":"下次扣费时间","value":"2026-12-01 00:00:00"},
                        {"id":"onlinedevice","type":"deviceNum","displayName":"在线设备","value":"2"}
                    ]}})");
                    if (task.account.username == L"20260089") {
                        e.package = parse_package_detail(LR"(<body><table id="totalTable">
                            <tr><td>余额</td><td>136.50元</td></tr><tr><td>当前套餐</td><td>演示周期套餐</td></tr>
                            <tr><td>计费策略</td><td>周期31天24.50元</td></tr>
                            <tr><td>周期时间范围</td><td>2026-11-01 至 2026-12-01</td></tr>
                            <tr><td>用户状态</td><td>正常</td></tr></table></body>)");
                        e.package.online_devices = 1;
                    }
                }
            } else if (FAILED(apartment)) {
                e.package.state = PackageState::Unsupported;
            } else if (const auto cached = cooldown.failure(GetTickCount64())) {
                e.package.state = *cached;
            } else {
                Credential secret;
                if (accounts_ && accounts_->read(task.account, secret)) {
                    PackageDiagnostics diagnostic;
                    e.package = query_package(secret, task.mac, &diagnostic, nullptr, &package_quit_, {}, task.interface_index);
                    cooldown.record(e.package.state, GetTickCount64());
                    log("package_query_stage", int(diagnostic.stage));
                    log("package_query_interface", diagnostic.interface_index);
                    log("package_query_http", diagnostic.http_status);
                    log("package_query_transport_error", diagnostic.transport_error);
                    log("package_query_tls_error", diagnostic.tls_library_error);
                    log("package_query_detail_http", diagnostic.detail_http_status);
                    log("package_query_billing_http", diagnostic.billing_http_status);
                    log("package_query_response_bytes", diagnostic.response_bytes);
                    log("package_query_transport_state", int(diagnostic.transport_state));
                    log("package_query_http_complete", diagnostic.http_complete);
                    log("package_query_summary", int(diagnostic.summary_result));
                    if (diagnostic.legacy_error_code) log("package_query_legacy_error", *diagnostic.legacy_error_code);
                    log("package_query_summary_items", diagnostic.summary_items);
                    log("package_query_detail_route", diagnostic.detail_route_available);
                    log("package_query_detail_login_http", diagnostic.detail_login_status);
                    log("package_query_detail_session", diagnostic.detail_session_available);
                    log("package_query_balance_available", e.package.balance.has_value());
                    log("package_query_fee_available", package_fee(e.package).has_value());
                } else log("package_query_credential_unavailable");
            }
        } catch (...) { e.package.state = PackageState::Unsupported; }
        {
            std::lock_guard lock(package_mutex_);
            const auto state = e.package.state;
            const auto key=task.account.id+":"+task.account.secret_id;
            const auto connection_epoch=package_connection_epoch_.load();
            if(!package_quit_ && task.connection_epoch!=connection_epoch) {
                // A pre-login query can finish after the connection/recovery
                // event. Do not let that late partial/error cache suppress the
                // new connection's query for five minutes.
                auto retry=task;retry.connection_epoch=connection_epoch;
                if(running_ && session_mode_.load()!=ConnectionMode::Wired) {
                    try {const auto network=current_wireless_network();if(network.found){retry.mac=network.mac;retry.interface_index=network.index;}}
                    catch(...) {}
                }
                package_queue_.push_back(std::move(retry));
                cooldown.reset();
                package_due_[key]=GetTickCount64()+10000;
                log("package_query_restarted_after_connection");
            } else {
            package_inflight_.erase(key);
            auto& attempts=billing_retries[key];
            if(attempts.first!=task.connection_epoch)attempts={task.connection_epoch,0};
            const bool incomplete=(state==PackageState::Ready || state==PackageState::Partial) &&
                (!package_fee(e.package) || (!e.package.next_charge && !e.package.cycle_end));
            attempts.second=incomplete?attempts.second+1:0;
            package_due_[key] = GetTickCount64() +
                (state == PackageState::Ready || state == PackageState::Partial ?
                    (incomplete && attempts.second<=3?30000:300000) :
                 state == PackageState::AuthError ? 60000 : state == PackageState::NetworkError ? 5000 : 15000);
            }
        }
        log("package_query_state",int(e.package.state));
        if (!package_quit_) post(std::move(e));
    }
    if (SUCCEEDED(apartment)) RoUninitialize();
}
void Backend::post(Event value) noexcept {
    try {
        auto *event = new Event(std::move(value));
        if (!PostMessageW(window_, backend_message, 0, reinterpret_cast<LPARAM>(event)))
            delete event;
    } catch (...) {
    }
}
void Backend::queue(std::function<void()> task) {
    {
        std::lock_guard lock(queue_mutex_);
        if (quitting_)
            return;
        queue_.push_back(std::move(task));
    }
    queue_cv_.notify_one();
}
void Backend::work() {
    for (;;) {
        std::function<void()> task;
        {
            std::unique_lock lock(queue_mutex_);
            queue_cv_.wait(lock, [&] { return quitting_ || !queue_.empty(); });
            if (quitting_)
                break;
            task = std::move(queue_.front());
            queue_.pop_front();
        }
        try {
            task();
        } catch (const std::exception &) {
            Event e;
            e.status = Status::Error;
            e.message = L"操作失败，请查看记录";
            post(std::move(e));
        }
    }
}
void Backend::log(std::string_view event, long long value) {
    if (options_.demo || logs_.empty())
        return;
    std::lock_guard lock(log_mutex_);
    SYSTEMTIME s{};
    GetSystemTime(&s);
    char time[40]{};
    sprintf_s(time, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute,
              s.wSecond, s.wMilliseconds);
    std::ofstream file(logs_ / L"desktop.jsonl", std::ios::app);
    file << "{\"time\":\"" << time << "\",\"event\":\"" << event << '"';
    if (value >= 0)
        file << ",\"value\":" << value;
    file << "}\n";
}
void Backend::account_summary(Event &e) const {
    e.accounts = catalog_;
    e.credentials = !catalog_.entries.empty();
    if (auto *first = catalog_.first_account())
        e.username = first->username;
}
void Backend::initialize() {
    queue([this] {
        Event e;
        e.kind = EventKind::Initialized;
        if (options_.demo) {
            for (unsigned n = 1; !options_.demo_first_run && n <= 3; ++n) {
                const std::string id(32, char('0' + n));
                auto secret = std::make_shared<Credential>();
                secret->username = n == 1 ? L"20260088" : n == 2 ? L"20260089" : L"20260090";
                secret->password = L"demo-only";
                catalog_.entries.push_back({id, std::string(32, char('a' + n - 1)), secret->username});
                demo_values_[id] = std::move(secret);
            }
            e.settings.mini = options_.mini;
            e.settings.mode = options_.demo_wireless_8021x ? ConnectionMode::Wireless8021x :
                              options_.demo_wireless ? ConnectionMode::WirelessWeb : ConnectionMode::Wired;
            mode_ = e.settings.mode;
            preferences_ = e.settings;
            e.profile = !options_.demo_first_run;
            e.adapter = e.settings.mode == ConnectionMode::Wired ? L"以太网" : L"WLAN";
            const bool online = options_.demo_online && !catalog_.entries.empty();
            e.status = online ? Status::Online : Status::Offline;
            e.account_id = online ? catalog_.entries.front().id : std::string{};
            e.network_only = online && options_.demo_network_only;
            account_summary(e);
            post(std::move(e));
            return;
        }
        try {
            directory_ = options_.directory.empty()?data_directory():options_.directory;
            profile_ = directory_ / L"connection.scau";
            logs_ = directory_ / L"logs";
            std::filesystem::create_directories(logs_);
            e.settings = load_settings(directory_);
            mode_ = e.settings.mode;
            preferences_ = e.settings;
            accounts_ = std::make_unique<AccountStore>(directory_);
            catalog_ = accounts_->load();
            try {
                if (mode_ == ConnectionMode::Wired) {
                    const auto connection = prepare_connection(directory_);
                    e.profile = connection.found; e.adapter = connection.adapter;
                    if (connection.created) log("connection_ready");
                } else {
                    const auto wireless = current_wireless_network();
                    e.profile = wireless.found; e.adapter = wireless.found ? wireless.name : L"WLAN";
                    if (mode_ == ConnectionMode::Wireless8021x) e.adapter = L"SCAUNET_1x · " + e.adapter;
                }
            } catch (const std::exception &) {
                log("connection_setup_failed");
            }
            e.status = Status::Offline;
        } catch (const std::exception &) {
            e.status = Status::Error;
            e.message = L"无法读取应用配置或账号";
            e.success = false;
        }
        account_summary(e);
        post(std::move(e));
    });
}
void Backend::connect(bool startup) {
    const auto token = generation_.load();
    queue([this, token, startup] { start_auth(token, startup ? startup_connection_modes(preferences_) : std::vector<ConnectionMode>{}); });
}
void Backend::disconnect() {
    ++generation_;
    interrupted_ = true;
    { std::lock_guard lock(portal_mutex_); pending_portal_.reset(); }
    Event e;
    e.status = running_ ? Status::Stopping : Status::Offline;
    post(std::move(e));
}
void Backend::approve_portal(std::string ticket) {
    queue([this,ticket=std::move(ticket)] {
        std::optional<PendingPortal> pending;
        { std::lock_guard lock(portal_mutex_); pending = pending_portal_; }
        if (!pending || pending->ticket != ticket || pending->generation != generation_.load() || interrupted_) return;
        try {
            if (options_.demo) {
                std::lock_guard lock(portal_mutex_);
                if (pending_portal_ && pending_portal_->ticket == ticket && pending_portal_->generation == generation_.load())
                    pending_portal_->approved = true;
                return;
            }
            const auto current = current_wireless_network(pending->network.mac);
            if (!current.ready || current.mac != pending->network.mac || current.index != pending->network.index ||
                current.ipv4 != pending->network.ipv4) throw std::runtime_error("Wireless network changed");
            save_wireless_origin(directory_,current,pending->origin);
            { std::lock_guard lock(portal_mutex_);
              if (pending_portal_ && pending_portal_->ticket == ticket && pending_portal_->generation == generation_.load())
                  pending_portal_->approved = true; }
            log("wireless_portal_approved");
        } catch (...) {
            Event e; e.kind = EventKind::PortalDetected; e.success = false; e.portal_ticket = ticket;
            e.message = L"认证页面保存失败，请重试"; post(std::move(e));
        }
    });
}
void Backend::change_password(std::string id, std::string expected_secret, std::shared_ptr<PasswordEdit> input,
                              unsigned request) {
    queue([this,id=std::move(id),expected_secret=std::move(expected_secret),input=std::move(input),request] {
        Event e; e.kind = EventKind::PasswordChanged; e.account_id = id; e.password_request = request;
        struct Wipe { PasswordEdit* input; ~Wipe(){ if(input) input->clear(); } } wipe{input.get()};
        try {
            const auto* found = catalog_.find(id);
            if (!input || !request || request <= password_request_) e.password_change.error = PasswordChangeError::AlreadySubmitted;
            else if (!found || found->secret_id != expected_secret) e.password_change.error = PasswordChangeError::Stale;
            else {
                password_request_ = request;
                const auto entry = *found;
                Credential credential;
                if (options_.demo) {
                    const auto saved = demo_values_.find(id);
                    if (saved == demo_values_.end()) throw std::runtime_error("Demo credential unavailable");
                    credential.username = saved->second->username; credential.password = saved->second->password;
                } else if (!accounts_ || !accounts_->read(entry,credential)) throw std::runtime_error("Saved credential unavailable");
                PasswordChangeSender sender;
                if (options_.demo) sender = [this](std::string_view,std::string_view,std::string_view,const std::atomic_bool*) {
                    detail::HttpsResult reply; reply.state = detail::TransportState::Complete;
                    reply.response.complete = true; reply.response.status = 200; reply.response.content_type = "text/plain;charset=utf-8";
                    reply.response.body = options_.demo_password_unknown ? "unrecognized-demo-response"
                                            : options_.demo_password_rejected ? "&success=2" : "&success=0";
                    return reply;
                };
                PasswordChangeSession session(std::move(sender));
                e.password_change = session.submit(credential,input->old_password,input->new_password,input->confirmation,
                    &package_quit_,[this,&entry] { const auto* current = catalog_.find(entry.id);
                        return !package_quit_ && current && current->secret_id == entry.secret_id; });
                if (e.password_change.outcome == PasswordChangeOutcome::Success) {
                    Credential updated_credential;
                    updated_credential.username = credential.username; updated_credential.password = input->new_password;
                    if (options_.demo) {
                        auto updated = std::make_shared<Credential>(); updated->username = updated_credential.username;
                        updated->password = updated_credential.password; demo_values_[id] = std::move(updated);
                        auto row = std::find_if(catalog_.entries.begin(),catalog_.entries.end(),[&](const auto& item){return item.id == id;});
                        row->secret_id = new_account_id();
                    } else accounts_->save(catalog_,id,updated_credential);
                    ++campus_epoch_;
                    e.password_local_saved = true;
                    log("password_changed");
                } else log(e.password_change.outcome == PasswordChangeOutcome::Unknown ? "password_change_unknown" : "password_change_rejected");
            }
            e.message = password_change_result_text(e.password_change);
        } catch (...) {
            e.message = e.password_change.outcome == PasswordChangeOutcome::Success
                            ? L"密码已修改，本机保存失败，请更新账号" : L"修改失败，请重试";
        }
        e.success = e.password_change.outcome == PasswordChangeOutcome::Success && e.password_local_saved;
        account_summary(e);
        post(std::move(e));
    });
}
bool Backend::prepare_wireless(unsigned token, const AccountInfo& account, std::wstring& problem) {
    const auto cancelled = [&] { return interrupted_.load() || token != generation_.load(); };
    const auto pause = [&](unsigned milliseconds) {
        const auto end = GetTickCount64() + milliseconds;
        while (!cancelled() && GetTickCount64() < end) Sleep(25);
        return !cancelled();
    };
    std::wstring previous;
    while (!cancelled()) {
        if (original_client_running()) { problem = L"请先退出锐捷客户端"; return false; }
        const auto network = current_wireless_network();
        if (!network.ready) {
            const std::wstring reason = !network.found ? L"等待无线网卡" : !network.link_up ? L"请先连接 SCAUNET" : L"等待无线网络地址";
            if (reason != previous) {
                Event e; e.status = Status::Waiting; e.username = account.username; e.account_id = account.id;
                e.message = reason; post(std::move(e)); previous = reason;
            }
            if (!pause(1000)) return false;
            continue;
        }
        portal::Options options; options.interface_index = network.index; options.cancel = &interrupted_;
        const auto known = load_wireless_origin(directory_,network);
        if (!known.empty()) options.trusted_origins.push_back(known);
        const auto discovery = portal::discover("http://www.scau.edu.cn/",network.ipv4,options);
        if (cancelled()) return false;
        if (discovery.target) {
            Event e; e.kind = EventKind::ConnectionReady; e.profile = true; e.adapter = network.name;
            post(std::move(e));
            return true;
        }
        if (!discovery.candidate_origin.empty() && valid_wireless_origin(discovery.candidate_origin)) {
            PendingPortal pending{network,discovery.candidate_origin,new_account_id(),token};
            { std::lock_guard lock(portal_mutex_); pending_portal_ = pending; }
            Event e; e.kind = EventKind::PortalDetected; e.status = Status::Waiting;
            e.account_id = account.id; e.username = account.username;
            e.portal_origin = pending.origin; e.portal_ticket = pending.ticket;
            e.message = L"确认学校认证页面"; post(std::move(e));
            while (!cancelled()) {
                bool approved = false, current = false;
                { std::lock_guard lock(portal_mutex_);
                  current = pending_portal_ && pending_portal_->ticket == pending.ticket;
                  approved = current && pending_portal_->approved; }
                if (!current || approved) break;
                const auto now = current_wireless_network(network.mac);
                if (!now.ready || now.mac != network.mac || now.index != network.index || now.ipv4 != network.ipv4) break;
                if (!pause(1000)) return false;
            }
            { std::lock_guard lock(portal_mutex_);
              if (pending_portal_ && pending_portal_->ticket == pending.ticket) pending_portal_.reset(); }
            previous.clear();
            continue; // Discover again; approval can never authorize a changed redirect.
        }
        problem = discovery.state == portal::State::NetworkError || discovery.state == portal::State::Timeout
                      ? L"无法访问无线认证页面" : L"未识别无线 Web 认证页面";
        return false;
    }
    return false;
}
void Backend::start_auth(unsigned token, std::vector<ConnectionMode> startup_modes) {
    if (token != generation_.load() || running_)
        return;
    if (auth_thread_.joinable())
        auth_thread_.join();
    const auto mode = startup_modes.empty() ? mode_ : startup_modes.front();
    const auto try_next = [this, token, &startup_modes] {
        if (startup_modes.size() <= 1 || token != generation_.load()) return false;
        auto remaining = startup_modes;
        remaining.erase(remaining.begin());
        log("startup_next_mode", int(remaining.front()));
        queue([this, token, remaining = std::move(remaining)] { start_auth(token, remaining); });
        return true;
    };
    if (catalog_.entries.empty()) {
        Event e;
        e.status = Status::Error;
        e.message = L"请先保存账号";
        post(std::move(e));
        return;
    }
    if (!options_.demo) {
        std::wstring problem;
        if (original_client_running()) {
            log("original_client_conflict");
            problem = L"请先退出锐捷客户端";
        } else if (!std::filesystem::is_regular_file(executable_.parent_path() / L"scau-auth.exe"))
            problem = L"认证核心未找到";
        else if (mode == ConnectionMode::Wired && !capture_driver_available())
            problem = L"请先安装 Npcap";
        if (!problem.empty()) {
            if (!original_client_running() && try_next()) return;
            Event e;
            e.status = Status::Error;
            e.message = problem;
            post(std::move(e));
            return;
        }
    }
    struct ReadyAccount {
        AccountInfo info;
        std::unique_ptr<EncryptedSessionSecret> secret;
        std::string wlan_profile;
    };
    auto catalog = catalog_;
    session_mode_=mode;
    Event selected; selected.kind = EventKind::ModeSelected; selected.connection_mode = mode;
    post(std::move(selected));
    AccountRotation rotation(catalog);
    std::vector<ReadyAccount> ready;
    for (const auto &entry : catalog.entries) {
        if (token != generation_.load())
            return;
        ReadyAccount account;
        account.info = entry;
        if (mode == ConnectionMode::Wireless8021x) account.wlan_profile = new_account_id();
        if (!options_.demo) {
            Credential saved;
            if (!accounts_->read(entry, saved))
                throw std::runtime_error("Saved account is unavailable");
            SessionCredentials encoded;
            encoded.username = to_gbk(saved.username);
            encoded.password = to_gbk(saved.password);
            account.secret = std::make_unique<EncryptedSessionSecret>(encoded.username, encoded.password);
        }
        ready.push_back(std::move(account));
    }
    if (token != generation_.load())
        return;
    interrupted_ = false;
    if (token != generation_.load()) {
        interrupted_ = true;
        return;
    }
    running_ = true;
    try {
        auth_thread_ = std::thread([this, token, mode, startup_modes = std::move(startup_modes), catalog = std::move(catalog), rotation = std::move(rotation),
                                    ready = std::move(ready)]() mutable {
            std::atomic_bool authenticated = false, startup_expired = false;
            std::jthread startup_timer;
            if (startup_modes.size() > 1) startup_timer = std::jthread([&](std::stop_token stop) {
                const auto deadline = GetTickCount64() + options_.startup_timeout_ms;
                while (!stop.stop_requested() && !authenticated && token == generation_.load() && !interrupted_) {
                    if (GetTickCount64() >= deadline) {
                        startup_expired = true; interrupted_ = true; break;
                    }
                    Sleep(25);
                }
            });
            const auto cancelled = [&] { return interrupted_.load() || token != generation_.load(); };
            const auto pause = [&](unsigned milliseconds) {
                const auto deadline = GetTickCount64() + milliseconds;
                while (!cancelled()) {
                    const auto now = GetTickCount64();
                    if (now >= deadline)
                        break;
                    Sleep(DWORD(std::min<ULONGLONG>(25, deadline - now)));
                }
                return !cancelled();
            };
            int result = supervisor_error;
            std::string failure_reason;
            std::wstring environment_problem;
            std::wstring attempted_username;
            std::string attempted_account;
            bool exhausted = false;
            unsigned ordinal = 0;
            const auto first_id = std::string(rotation.current());
            try {
                while (!cancelled() && !rotation.finished()) {
                    failure_reason.clear();
                    const auto id = std::string(rotation.current());
                    auto found = std::find_if(ready.begin(), ready.end(),
                                              [&](const auto &a) { return a.info.id == id; });
                    if (found == ready.end())
                        throw std::runtime_error("Account rotation snapshot is invalid");
                    attempted_username = found->info.username;
                    attempted_account = id;
                    ++ordinal;
                    log("account_attempt", ordinal);
                    Event start;
                    start.status = Status::Connecting;
                    start.username = found->info.username;
                    start.account_id = id;
                    start.login_attempt = rotation.attempt();
                    if (ordinal > 1)
                        start.message = rotation.attempt() == 2 ? L"正在重试账号" : L"正在切换账号";
                    if (!cancelled())
                        post(std::move(start));
                    if (options_.demo) {
                        if (!pause(options_.demo_delay_ms))
                            break;
                        if (options_.demo_portal && mode == ConnectionMode::WirelessWeb) {
                            const auto ticket = new_account_id();
                            { std::lock_guard lock(portal_mutex_);
                              pending_portal_ = PendingPortal{{},"https://portal.example.test",ticket,token,false}; }
                            Event detected; detected.kind = EventKind::PortalDetected; detected.status = Status::Waiting;
                            detected.account_id = id; detected.username = found->info.username;
                            detected.portal_origin = "https://portal.example.test"; detected.portal_ticket = ticket;
                            post(std::move(detected));
                            while (!cancelled()) {
                                bool approved = false;
                                { std::lock_guard lock(portal_mutex_);
                                  approved = pending_portal_ && pending_portal_->ticket == ticket && pending_portal_->approved; }
                                if (approved) break;
                                if (!pause(25)) break;
                            }
                            { std::lock_guard lock(portal_mutex_); pending_portal_.reset(); }
                            if (cancelled()) break;
                        }
                        const bool rejected =
                            options_.demo_failure || (options_.demo_failover && id == first_id);
                        result = std::find(options_.demo_failed_modes.begin(),options_.demo_failed_modes.end(),mode) != options_.demo_failed_modes.end()
                                 ? auth_environment_error : options_.demo_terminal ? options_.demo_terminal
                                 : rejected             ? auth_rejected
                                                        : 0;
                        if (rejected) failure_reason = options_.demo_failure_reason;
                        if (result == 0) {
                            authenticated = true;
                            ++package_connection_epoch_;
                            {std::lock_guard lock(package_mutex_);package_due_.erase(id+":"+found->info.secret_id);}
                            Event online;
                            online.status = Status::Online;
                            online.username = found->info.username;
                            online.account_id = id;
                            if (options_.demo_network_only) {online.network_only=true;online.account_id.clear();online.username.clear();}
                            if (!cancelled())
                                post(std::move(online));
                            while (!cancelled())
                                Sleep(100);
                            break;
                        }
                    } else {
                        bool waiting = false;
                        if (mode == ConnectionMode::WirelessWeb) {
                            const auto network=current_wireless_network();
                            if(!network.found){result=auth_environment_error;environment_problem=L"未找到无线网卡";break;}
                            Event e;e.kind=EventKind::ConnectionReady;e.profile=true;e.adapter=L"SCAUNET · "+network.name;post(std::move(e));
                            waiting = true;
                        } else if (mode == ConnectionMode::Wireless8021x) {
                            while (!cancelled()) {
                                if (original_client_running()) { result = auth_environment_error; environment_problem = L"请先退出锐捷客户端"; break; }
                                const auto network = current_wireless_network();
                                if (network.found) {
                                    Event e; e.kind = EventKind::ConnectionReady; e.profile = true;
                                    e.adapter = L"SCAUNET_1x · " + network.name; post(std::move(e)); break;
                                }
                                if (!waiting) {
                                    Event e; e.status = Status::Waiting; e.username = found->info.username;
                                    e.account_id = id; e.message = L"等待无线网卡"; post(std::move(e));
                                }
                                waiting = true; if (!pause(1000)) break;
                            }
                        } else {
                        std::wstring waiting_message;
                        while (!cancelled()) {
                            if (original_client_running()) {
                                result = auth_environment_error;
                                environment_problem = L"请先退出锐捷客户端";
                                log("original_client_conflict");
                                break;
                            }
                            const auto connection = prepare_connection(directory_);
                            if (connection.found && connection.link_up) {
                                Event e; e.kind = EventKind::ConnectionReady;
                                e.profile = true; e.adapter = connection.adapter;
                                post(std::move(e));
                                break;
                            }
                            const auto reason = connection.found ? L"等待网线接入" : L"等待有线网卡";
                            if (waiting_message != reason) {
                                Event e;
                                e.status = Status::Waiting;
                                e.username = found->info.username;
                                e.account_id = id;
                                e.message = reason;
                                post(std::move(e));
                                log("waiting_for_network");
                                waiting_message = reason;
                            }
                            waiting = true;
                            if (!pause(1000))
                                break;
                        }
                        }
                        if (cancelled())
                            break;
                        if (!environment_problem.empty()) break;
                        if (original_client_running()) {
                            result = auth_environment_error;
                            environment_problem = L"请先退出锐捷客户端";
                            log("original_client_conflict");
                            break;
                        }
                        if (waiting) {
                            Event e;
                            e.status = Status::Connecting;
                            e.username = found->info.username;
                            e.account_id = id;
                            post(std::move(e));
                        }
                        SupervisorConfig config;
                        config.executable = executable_.parent_path() / L"scau-auth.exe";
                        const auto worker_log =
                            logs_ / (L"session-" + stamp() + L"-" + std::to_wstring(ordinal) + L".jsonl");
                        config.arguments = {L"--connect", L"--duration", L"86400", L"--log", worker_log.wstring()};
                        if(!options_.directory.empty()) {
                            config.arguments.push_back(L"--state-directory");config.arguments.push_back(directory_.wstring());
                        }
                        if (mode == ConnectionMode::WirelessWeb) config.arguments.push_back(L"--wireless-web");
                        else if (mode == ConnectionMode::Wireless8021x) {
                            config.arguments.push_back(L"--wireless-8021x");
                            config.arguments.push_back(L"--wlan-profile-id");
                            config.arguments.emplace_back(found->wlan_profile.begin(),found->wlan_profile.end());
                        }
                        else { config.arguments.push_back(L"--profile"); config.arguments.push_back(profile_.wstring()); }
                        result = supervise_worker(config, *found->secret, interrupted_,
                                                  [&](std::string_view name, long long value) {
                                                      log(name, value);
                                                      Event e;
                                                      e.username = found->info.username;
                                                      e.account_id = id;
                                                      if (name == "worker_authenticated") {
                                                          authenticated = true;
                                                          ++package_connection_epoch_;
                                                          rotation.authenticated();
                                                          { std::lock_guard lock(package_mutex_);
                                                            package_due_.erase(id+":"+found->info.secret_id); }
                                                          e.status = Status::Online;
                                                      } else if (name == "worker_network_available") {
                                                          authenticated=true;
                                                          ++package_connection_epoch_;
                                                          {std::lock_guard lock(package_mutex_);package_due_.erase(id+":"+found->info.secret_id);}
                                                          e.status=Status::Online;e.network_only=true;
                                                          e.username.clear();e.account_id.clear();
                                                      } else if (name == "worker_unauthenticated" ||
                                                                 name == "worker_crashed" ||
                                                                 name == "worker_restart_scheduled")
                                                          e.status = Status::Recovering;
                                                      else
                                                          return;
                                                      if (mode != ConnectionMode::Wired && e.status == Status::Recovering)
                                                          e.message = L"正在恢复无线连接";
                                                      if (!cancelled())
                                                          post(std::move(e));
                                                  }, &failure_reason);
                    }
                    if (cancelled())
                        break;
                    if (!rotation.failed(result)) {
                        exhausted = allows_account_retry(result);
                        break;
                    }
                    const bool retry = rotation.current() == id;
                    log(retry ? "account_retry" : "account_next", ordinal);
                    Event next;
                    next.status = Status::Connecting;
                    next.message = retry ? L"正在重试账号" : L"正在切换账号";
                    next.account_id = std::string(rotation.current());
                    if (auto *entry = catalog.find(next.account_id))
                        next.username = entry->username;
                    post(std::move(next));
                    if (!pause(retry ? options_.retry_delay_ms : options_.switch_delay_ms))
                        break;
                }
            } catch (const std::exception &) {
                result = auth_environment_error;
                log("desktop_authentication_error");
            }
            const bool manual = cancelled();
            if (startup_timer.joinable()) { startup_timer.request_stop(); startup_timer.join(); }
            running_ = false;
            if (!authenticated && startup_modes.size() > 1 && token == generation_.load() &&
                (!manual || startup_expired) && result != auth_protocol_unsupported) {
                startup_modes.erase(startup_modes.begin());
                interrupted_ = false;
                log("startup_next_mode", int(startup_modes.front()));
                queue([this, token, startup_modes = std::move(startup_modes)] { start_auth(token, startup_modes); });
                return;
            }
            Event done;
            done.status = manual ? Status::Offline : Status::Error;
            done.username = std::move(attempted_username);
            done.account_id = std::move(attempted_account);
            if (!manual) {
                if (exhausted) {
                    done.message = failure_reason.empty() ? L"unknown" : utf8_to_wide(failure_reason);
                    log("accounts_exhausted");
                } else if (result == supervisor_crash_limit)
                    done.message = L"自动恢复已停止";
                else if (result == auth_server_terminated)
                    done.message = L"校园网已下线";
                else if (result == auth_protocol_unsupported)
                    done.message = failure_reason.empty() ? L"认证协议不兼容" : utf8_to_wide(failure_reason);
                else if (result == auth_rejected)
                    done.message = failure_reason.empty() ? L"unknown" : utf8_to_wide(failure_reason);
                else if (!environment_problem.empty())
                    done.message = environment_problem;
                else if (!failure_reason.empty())
                    done.message = utf8_to_wide(failure_reason);
                else
                    done.message = L"认证环境异常，请查看记录";
            }
            post(std::move(done));
        });
    } catch (...) {
        running_ = false;
        throw;
    }
}
void Backend::save_account(std::string id, std::shared_ptr<Credential> value, bool connect_after) {
    ++campus_epoch_;
    const auto token = generation_.load();
    queue([this, id = std::move(id), value = std::move(value), connect_after, token] {
        Event e;
        e.kind = EventKind::AccountsChanged;
        e.refresh_form = true;
        try {
            validate_account_edit(catalog_, id, *value);
            if (options_.demo) {
                auto saved = std::make_shared<Credential>();
                saved->username = value->username;
                saved->password = value->password.empty() ? demo_values_.at(id)->password : value->password;
                const auto *previous = catalog_.find(id);
                AccountInfo entry{previous ? previous->id : new_account_id(), new_account_id(),
                                  saved->username};
                if (previous) {
                    for (auto &row : catalog_.entries)
                        if (row.id == id)
                            row = entry;
                } else
                    catalog_.entries.push_back(entry);
                demo_values_[entry.id] = std::move(saved);
                e.account_id = entry.id;
            } else
                e.account_id = accounts_->save(catalog_, id, *value);
            e.message = L"已保存";
            log("credentials_saved");
        } catch (const std::exception &) {
            e.success = false;
            e.message = L"请检查重复账号、密码或凭据存储";
            e.account_id = id;
        }
        value->clear();
        const bool success = e.success;
        account_summary(e);
        post(std::move(e));
        if (success && connect_after && token == generation_.load())
            start_auth(token);
    });
}
void Backend::pin_account(std::string id) {
    queue([this, id = std::move(id)] {
        Event e;
        e.kind = EventKind::AccountsChanged;
        try {
            if (options_.demo)
                scau::desktop::pin_account(catalog_, id);
            else
                accounts_->pin(catalog_, id);
            log("account_pinned");
        } catch (const std::exception &) {
            e.success = false;
            e.message = L"账号置顶失败";
        }
        account_summary(e);
        post(std::move(e));
    });
}
void Backend::reorder_accounts(std::vector<std::string> ids) {
    queue([this, ids = std::move(ids)] {
        Event e;
        e.kind = EventKind::AccountsChanged;
        try {
            if (options_.demo)
                scau::desktop::reorder_accounts(catalog_, ids);
            else
                accounts_->reorder(catalog_, ids);
            log("account_order_changed");
        } catch (const std::exception &) {
            e.success = false;
            e.message = L"账号排序保存失败";
        }
        account_summary(e);
        post(std::move(e));
    });
}
void Backend::remove_account(std::string id) {
    ++campus_epoch_;
    queue([this, id = std::move(id)] {
        Event e;
        e.kind = EventKind::AccountsChanged;
        e.refresh_form = true;
        try {
            if (options_.demo) {
                remove_account_entry(catalog_, id);
                demo_values_.erase(id);
            } else
                accounts_->remove(catalog_, id);
            e.account_id = catalog_.entries.empty() ? std::string{} : catalog_.entries.front().id;
            log("account_removed");
        } catch (const std::exception &) {
            e.success = false;
            e.message = L"账号删除失败";
            e.account_id = id;
        }
        account_summary(e);
        post(std::move(e));
    });
}
void Backend::save_preferences(Settings value) {
    queue([this, value] {
        Event e;
        e.kind = EventKind::SettingsSaved;
        e.settings = value;
        try {
            if (value.mode != ConnectionMode::Wired && value.mode != ConnectionMode::WirelessWeb && value.mode != ConnectionMode::Wireless8021x)
                throw std::runtime_error("Unsupported connection mode");
            if (running_ && value.mode != mode_)
                throw std::runtime_error("Disconnect before changing the connection mode");
            if (!options_.demo) {
                const auto previous = load_settings(directory_);
                const bool startup_changed = options_.directory.empty() && previous.auto_start != value.auto_start;
                if (startup_changed) set_auto_start(value.auto_start, executable_);
                try {
                    save_settings(directory_, value);
                } catch (...) {
                    if (startup_changed) set_auto_start(previous.auto_start, executable_);
                    throw;
                }
            }
            mode_ = value.mode;
            preferences_ = value;
            log("preferences_saved");
        } catch (const std::exception &) {
            e.success = false;
            e.message = L"设置保存失败";
        }
        post(std::move(e));
    });
}
void Backend::load_logs(LogQuery query, unsigned request) {
    const auto generation = ++log_generation_;
    queue([this, query = std::move(query), request, generation] {
        if (generation != log_generation_)
            return;
        Event e;
        e.kind = EventKind::Logs;
        e.log_request = request;
        if (options_.demo) {
            const auto now = log_now_ms();
            auto snapshot = query;
            snapshot.now_ms = now;
            LogSelection selection(std::move(snapshot));
            for (unsigned i = 0; i < 96; ++i) {
                const auto age = i < 60 ? std::uint64_t(i) * 120000
                                 : i < 80 ? std::uint64_t(i - 58) * 3600000
                                          : std::uint64_t(i - 78) * 86400000;
                const bool error = i % 11 == 3, warning = i % 7 == 2, info = i % 5 == 1;
                selection.consider({now - age,
                    error ? LogLevel::Error : warning ? LogLevel::Warning : info ? LogLevel::Info : LogLevel::Success,
                    error ? L"登录失败" : warning ? L"正在自动恢复" : info ? L"开始登录" : L"互联网检查通过",
                    {}, error ? "desktop_authentication_error" : warning ? "worker_restart_scheduled"
                       : info ? "account_attempt" : "internet_probe_ok"});
            }
            e.logs = selection.finish();
        } else
            try {
                e.logs = read_log_records(logs_, query);
            } catch (const std::exception &) {
                e.message = L"记录读取失败";
                e.success = false;
            }
        if (generation == log_generation_)
            post(std::move(e));
    });
}
} // namespace scau::desktop
