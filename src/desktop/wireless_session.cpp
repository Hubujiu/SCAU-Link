#include "wireless_session.hpp"
#include "platform.hpp"
#include "auth_result.hpp"
#include "campus_wifi.hpp"
#include <algorithm>
#include <thread>
#include <stdexcept>

namespace scau::desktop {
namespace {
using portal::State;
constexpr std::chrono::milliseconds network_interval{1000}, status_interval{30000};
constexpr std::string_view interception_probe = "http://1.1.1.1/";
bool stopped(const WirelessSessionOptions& options) {
    return options.cancel && options.cancel->load(std::memory_order_relaxed);
}
void pause(const WirelessSessionOptions& options, std::chrono::milliseconds duration) {
    if (options.pause) { options.pause(duration); return; }
    while (duration.count() > 0 && !stopped(options)) {
        const auto part = std::min(duration, std::chrono::milliseconds(50));
        std::this_thread::sleep_for(part); duration -= part;
    }
}
bool identity(const WirelessNetwork& left, const WirelessNetwork& right) {
    return left.found && left.link_up && left.ready && right.found && right.link_up && right.ready &&
        left.mac == right.mac && left.index == right.index && left.ipv4 == right.ipv4;
}
void wipe(std::string& value) noexcept {
    if (!value.empty()) SecureZeroMemory(value.data(), value.size()); value.clear();
}
struct Session {
    WirelessNetwork network;
    portal::Target target;
    std::string index;
    ~Session() { wipe(index); }
    void clear() { wipe(index); target = {}; network = {}; }
};
}

int run_wireless_session(const Credential& credential, const WirelessSessionOptions& options,
                         const WirelessCallbacks& callbacks, std::string* failure) {
    if (failure) failure->clear();
    const auto fail = [&](int code, std::string_view reason) {
        if (failure) *failure = reason; return code;
    };
    const auto event = [&](std::string_view name) { if (callbacks.event) callbacks.event(name); };
    const auto network = [&](const Mac& preferred) {
        return options.network_provider ? options.network_provider(preferred) : current_wireless_network(preferred);
    };
    Session session;
    std::unique_ptr<CampusWifi> wifi;
    Mac preferred = options.preferred_mac;
    bool environment_checked = false, recovering = false, found_once = false;
    const auto recover = [&] {
        if (!recovering) { recovering = true; if (callbacks.recovering) callbacks.recovering(); }
    };
    const auto cleanup = [&] {
        if (session.index.empty()) return;
        std::string owned_index;owned_index.swap(session.index);
        struct Clear {std::string& value;~Clear(){wipe(value);}} clear{owned_index};
        // Cancellation grants no ownership of a session merely discovered on
        // this IP. Only an index returned by our successful login reaches here.
        try {
            const auto current = network(session.network.mac);
            if (!identity(session.network, current) ||
                load_wireless_origin(options.directory, current) != session.target.origin) {
                event("wireless_logout_skipped_context_changed"); return;
            }
            portal::Options request_options;
            request_options.interface_index = current.index;
            request_options.timeout = std::chrono::seconds(2);
            request_options.trusted_origins = {session.target.origin};
            const auto result = portal::logout(session.target, owned_index, request_options, options.transport);
            event(result.state == State::Success ? "wireless_logout_acknowledged" : "wireless_logout_uncertain");
        } catch (...) {
            try { event("wireless_logout_uncertain"); } catch (...) {}
        }
    };
    struct CleanupOnExit {const decltype(cleanup)& invoke;~CleanupOnExit(){invoke();}} cleanup_on_exit{cleanup};
    try {
        if(options.manage_wifi) {
            // WLAN service/device enumeration can lag the shell at login.
            // Retry environment creation only; no credentials are sent here.
            for(unsigned attempt=0;!stopped(options);++attempt) {
                try {wifi=make_scau_web_wifi();break;}
                catch(const std::runtime_error&) {
                    if(attempt>=20)throw;
                    if(attempt==0)event("wireless_waiting_for_environment");
                    pause(options,std::chrono::milliseconds(250));
                }
            }
        }
        for (;;) {
            if (stopped(options)) { cleanup(); return 0; }
            if(wifi) {
                std::string reason;
                if(!wifi->connect(options.cancel,reason))return stopped(options)?0:fail(auth_environment_error,reason);
                for(const auto& adapter:connection_adapters())
                    if(adapter.index==wifi->interface_index() && adapter.physical && adapter.wireless)preferred=adapter.mac;
            }
            const auto current = network(preferred);
            if(wifi && current.found && current.index!=wifi->interface_index())
                return fail(auth_environment_error,"无线网卡已变化");
            if (!current.found && !found_once && !wifi)
                return fail(auth_environment_error, "wireless_adapter_missing");
            if (current.found && preferred == Mac{}) preferred = current.mac;
            if (current.found) found_once = true;
            if (!current.found || !current.link_up || !current.ready || current.mac != preferred) {
                session.clear(); recover(); pause(options, network_interval); continue;
            }
            if (!environment_checked) {
                if (options.environment_ready) options.environment_ready();
                environment_checked = true;
            }
            const auto origin = load_wireless_origin(options.directory, current);
            if (origin.empty() && !options.manage_wifi) return fail(auth_protocol_unsupported, wireless_origin_unconfirmed);
            portal::Options request_options;
            request_options.interface_index = current.index;
            request_options.cancel = options.cancel;
            request_options.trusted_origins = options.manage_wifi ? portal::school_portal_origins() : std::vector<std::string>{};
            if(!origin.empty())request_options.trusted_origins.push_back(origin);
            auto discovered = portal::discover(interception_probe, current.ipv4, request_options, options.transport);
            if (stopped(options)) { cleanup(); return 0; }
            if (!identity(current, network(preferred))) {
                session.clear(); recover(); pause(options, network_interval); continue;
            }
            if (discovered.state == State::UntrustedTarget)
                return fail(auth_protocol_unsupported, wireless_origin_changed);
            if (discovered.state == State::Unsupported || !discovered.target) {
                if(discovered.state==State::Unsupported && (options.manage_wifi || options.allow_existing_network) &&
                    portal::internet_available(current.ipv4,request_options,options.transport)==State::Success &&
                    identity(current,network(preferred))) {
                    // A cached NAS/MAC session can already provide internet.
                    // Prove it using bound DNS/TLS, without assigning it to a
                    // saved account or gaining permission to log it out.
                    recovering=false;session.clear();
                    event("wireless_network_available");
                    if(callbacks.network_available)callbacks.network_available();
                    std::chrono::milliseconds elapsed{};
                    while(!stopped(options)) {
                        pause(options,network_interval);elapsed+=network_interval;
                        if(!identity(current,network(preferred)))break;
                        if(elapsed>=std::chrono::minutes(2)) {
                            elapsed={};
                            if(portal::internet_available(current.ipv4,request_options,options.transport)!=State::Success)break;
                        }
                    }
                    if(stopped(options))return 0;
                    recover();continue;
                }
                if (discovered.state == State::Unsupported || discovered.state == State::InvalidResponse)
                    return fail(auth_protocol_unsupported, wireless_portal_unsupported);
                return fail(auth_environment_error, "wireless_discovery_failed");
            }
            auto target = std::move(*discovered.target);
            if(options.manage_wifi && origin.empty())save_wireless_origin(options.directory,current,target.origin);
            portal::Result page;
            if(options.manage_wifi) {
                target.protocol=portal::Protocol::InterFace;
                page=portal::page_info(target,request_options,options.transport);
                if(page.http_status==404 || page.state==State::InvalidResponse) {
                    target.protocol=portal::Protocol::AuthApi;
                    page=portal::page_info(target,request_options,options.transport);
                }
            }
            auto existing = portal::online(target, "", request_options, options.transport);
            if (stopped(options)) return 0;
            if (!identity(current, network(preferred))) { recover(); pause(options, network_interval); continue; }
            // A positive IP probe cannot identify the authenticated account.
            // It never emits Online, supplies ownership, or triggers logout.
            if (existing.state == State::Success) event("wireless_existing_session_unattributed");
            else if (existing.state != State::Offline) {
                if (existing.state == State::InvalidResponse || existing.state == State::UntrustedTarget ||
                    existing.state == State::Rejected)
                    return fail(auth_protocol_unsupported, wireless_portal_unsupported);
                return fail(auth_environment_error, "wireless_status_unavailable");
            }
            if(!options.manage_wifi)page=portal::page_info(target, request_options, options.transport);
            if (stopped(options)) return 0;
            if (!identity(current, network(preferred))) { recover(); pause(options, network_interval); continue; }
            if (page.state != State::Ready) {
                if (page.state == State::InvalidResponse || page.state == State::Rejected || page.state == State::UntrustedTarget)
                    return fail(auth_protocol_unsupported, wireless_portal_unsupported);
                return fail(auth_environment_error, "wireless_page_info_failed");
            }
            std::string service;
            if(page.captcha_required)return fail(auth_protocol_unsupported,"学校要求验证码，请在官方页面完成验证");
            target.password_encrypt=page.password_encrypt;
            target.public_exponent=std::move(page.public_exponent);target.public_modulus=std::move(page.public_modulus);
            auto count = std::count_if(page.services.begin(), page.services.end(), [](const auto& item) { return item.is_default; });
            if (count == 1) service = std::find_if(page.services.begin(), page.services.end(), [](const auto& item) { return item.is_default; })->name;
            else if (count == 0 && page.services.size() == 1) service = page.services.front().name;
            else if (!page.services.empty()) return fail(auth_protocol_unsupported, wireless_service_ambiguous);
            if (load_wireless_origin(options.directory, current) != target.origin)
                return fail(auth_protocol_unsupported, wireless_origin_changed);
            if (stopped(options)) return 0;
            auto result = portal::login(target, credential, service, request_options, options.transport);
            if (result.state == State::Success) {
                session.network = current; session.target = std::move(target);
                session.index = std::move(result.user_index);
                if (stopped(options)) { cleanup(); return 0; }
                if (!identity(current, network(preferred))) {
                    event("wireless_context_changed_after_login"); session.clear(); recover();
                    pause(options, network_interval); continue;
                }
            } else {
                if (stopped(options)) return 0;
                if (result.state == State::Rejected)
                    return fail(auth_rejected, result.message.empty() ? std::string_view("wireless_auth_rejected") : std::string_view(result.message));
                // The request may already have created a server session. No
                // automatic retry or account rotation may follow this result.
                return fail(auth_protocol_unsupported, wireless_login_uncertain);
            }
            recovering = false;
            event("wireless_authenticated");
            if (callbacks.online) callbacks.online();
            std::chrono::milliseconds since_status{};
            for (;;) {
                if (stopped(options)) { cleanup(); return 0; }
                pause(options, network_interval); since_status += network_interval;
                if (stopped(options)) { cleanup(); return 0; }
                const auto updated = network(preferred);
                if (!identity(session.network, updated)) {
                    event("wireless_link_context_changed"); session.clear(); recover(); break;
                }
                if (load_wireless_origin(options.directory, updated) != session.target.origin)
                    return fail(auth_protocol_unsupported, wireless_origin_changed);
                if (since_status < status_interval) continue;
                since_status = std::chrono::milliseconds{};
                // The deployed browser's observed keepalive endpoint uses
                // the login-owned userIndex. Legacy clients use status polls.
                auto status = session.target.protocol==portal::Protocol::InterFace
                    ? portal::keepalive(session.target,session.index,request_options,options.transport)
                    : portal::online(session.target, session.index, request_options, options.transport);
                if (stopped(options)) { cleanup(); return 0; }
                if (!identity(session.network, network(preferred))) {
                    event("wireless_link_context_changed"); session.clear(); recover(); break;
                }
                if (status.state == State::Offline)
                    return fail(auth_server_terminated, wireless_session_lost);
                if (status.state == State::Success) {
                    if (recovering) {
                        recovering = false; event("wireless_status_restored");
                        if (callbacks.online) callbacks.online();
                    }
                } else if (status.state == State::InvalidResponse || status.state == State::UntrustedTarget || status.state == State::Rejected) {
                    return fail(auth_protocol_unsupported, wireless_portal_unsupported);
                } else {
                    event("wireless_status_unavailable"); recover();
                }
            }
        }
    } catch (...) {
        if (stopped(options)) { cleanup(); return 0; }
        return fail(auth_environment_error, "wireless_runtime_error");
    }
}
} // namespace scau::desktop
