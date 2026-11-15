#pragma once
#include "accounts.hpp"
#include "package_query.hpp"
#include "service_query.hpp"
#include "password_change.hpp"
#include "wireless_connection.hpp"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

namespace scau::desktop {
inline constexpr UINT backend_message = WM_APP + 20;
enum class Status { Loading, Offline, Connecting, Online, Recovering, Waiting, Stopping, Error };
enum class EventKind { Initialized, State, AccountsChanged, SettingsSaved, Logs, ConnectionReady, Package, Campus,
                       PortalDetected, PasswordChanged, ModeSelected };
struct PasswordEdit {
    std::wstring old_password, new_password, confirmation;
    void clear() noexcept {
        for (auto* value : {&old_password, &new_password, &confirmation}) {
            if (!value->empty()) SecureZeroMemory(value->data(),value->size()*sizeof(wchar_t));
            value->clear();
        }
    }
    ~PasswordEdit() { clear(); }
};
struct Event {
    EventKind kind = EventKind::State;
    Status status = Status::Offline;
    Settings settings;
    ConnectionMode connection_mode = ConnectionMode::Wired;
    bool credentials = false, profile = false, success = true;
    bool network_only = false;
    std::wstring username, adapter, message;
    AccountCatalog accounts;
    std::string account_id;
    bool refresh_form = false;
    unsigned login_attempt = 0;
    LogResult logs;
    unsigned log_request{};
    PackageInfo package;
    std::string package_secret;
    CampusView campus;
    CampusOutcome campus_outcome = CampusOutcome::None;
    CampusAction campus_action = CampusAction::Pause;
    bool campus_change = false, campus_request_sent = false;
    std::string campus_ticket;
    unsigned campus_request = 0;
    std::string portal_origin, portal_ticket;
    PasswordChangeResult password_change;
    bool password_local_saved = false;
    unsigned password_request = 0;
};
struct BackendOptions {
    // Explicit integration seam: isolate the catalog/cache/logs while exercising
    // the production backend and private worker. Empty is the real user store.
    std::filesystem::path directory;
    bool demo = false, demo_online = false, demo_failure = false, demo_failover = false, mini = false;
    unsigned demo_delay_ms = 750, retry_delay_ms = 1000, switch_delay_ms = 500;
    unsigned demo_package_delay_ms = 0;
    int demo_terminal = 0;
    std::string demo_failure_reason;
    bool demo_packages = false, demo_first_run = false, demo_wireless = false;
    bool demo_password_unknown = false, demo_password_rejected = false, demo_portal = false;
    bool demo_wireless_8021x = false;
    bool demo_network_only = false;
    bool startup = false;
    unsigned startup_timeout_ms = 45000;
    std::vector<ConnectionMode> demo_failed_modes;
};
class Backend {
    HWND window_;
    BackendOptions options_;
    std::filesystem::path directory_, executable_, profile_, logs_;
    std::unique_ptr<AccountStore> accounts_;
    AccountCatalog catalog_;
    ConnectionMode mode_ = ConnectionMode::Wired; // IO-thread owned; each authentication run captures a snapshot.
    std::atomic<ConnectionMode> session_mode_ = ConnectionMode::Wired;
    Settings preferences_;
    struct PendingPortal { WirelessNetwork network; std::string origin, ticket; unsigned generation{}; bool approved = false; };
    std::mutex portal_mutex_;
    std::optional<PendingPortal> pending_portal_;
    unsigned password_request_ = 0;
    std::map<std::string, std::shared_ptr<Credential>> demo_values_;
    std::mutex queue_mutex_, log_mutex_;
    std::condition_variable queue_cv_;
    std::deque<std::function<void()>> queue_;
    bool quitting_ = false;
    std::thread io_thread_, auth_thread_;
    enum class QueryKind { Package, CampusPrepare, CampusApply };
    struct PackageTask {
        AccountInfo account; std::array<unsigned char, 6> mac{};
        QueryKind kind = QueryKind::Package;
        std::string ticket;
        CampusAction action = CampusAction::Pause;
        unsigned request = 0, epoch = 0;
        unsigned connection_epoch = 0;
        unsigned interface_index = 0;
    };
    std::thread package_thread_;
    std::mutex package_mutex_;
    std::condition_variable package_cv_;
    std::deque<PackageTask> package_queue_;
    std::map<std::string, ULONGLONG> package_due_;
    std::set<std::string> package_inflight_;
    std::atomic<unsigned> package_connection_epoch_ = 0;
    std::atomic<bool> package_quit_ = false;
    std::atomic<unsigned> campus_epoch_ = 0;
    // Only the package worker owns the following private web-session state.
    std::unique_ptr<CampusSession> campus_session_;
    std::string campus_account_, campus_secret_, campus_ticket_;
    unsigned campus_snapshot_epoch_ = 0;
    std::map<std::string, CampusState> campus_demo_states_;
    void package_work();
    void campus_work(const PackageTask& task);
    void request_campus(std::string id, unsigned request, bool apply, std::string ticket, CampusAction action);
    std::atomic<bool> interrupted_ = false, running_ = false;
    std::atomic<unsigned> generation_ = 0;
    std::atomic<unsigned> log_generation_ = 0;
    void post(Event value) noexcept;
    void queue(std::function<void()> task);
    void work();
    void start_auth(unsigned token, std::vector<ConnectionMode> startup_modes = {});
    bool prepare_wireless(unsigned token, const AccountInfo& account, std::wstring& problem);
    void account_summary(Event &value) const;
    void log(std::string_view event, long long value = -1);

  public:
    Backend(HWND window, BackendOptions options);
    ~Backend();
    void initialize();
    void connect(bool startup = false);
    void disconnect();
    bool running() const noexcept { return running_.load(); }
    void save_account(std::string id, std::shared_ptr<Credential> value, bool connect_after = false);
    void pin_account(std::string id);
    void reorder_accounts(std::vector<std::string> ids);
    void remove_account(std::string id);
    void save_preferences(Settings value);
    void approve_portal(std::string ticket);
    void change_password(std::string id, std::string expected_secret, std::shared_ptr<PasswordEdit> input,
                         unsigned request);
    void load_logs(LogQuery query = {}, unsigned request = 0);
    void request_packages(std::string account_id = {});
    void prepare_campus(std::string account_id, unsigned request);
    void change_campus(std::string account_id, std::string ticket, CampusAction action, unsigned request);
};
} // namespace scau::desktop
