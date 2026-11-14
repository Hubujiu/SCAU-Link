#pragma once
#include "portal_auth.hpp"
#include "wireless_connection.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>

namespace scau::desktop {
struct Credential;
inline constexpr std::string_view wireless_origin_unconfirmed = "wireless_origin_unconfirmed";
inline constexpr std::string_view wireless_origin_changed = "wireless_origin_changed";
inline constexpr std::string_view wireless_portal_unsupported = "wireless_portal_unsupported";
inline constexpr std::string_view wireless_service_ambiguous = "wireless_service_ambiguous";
inline constexpr std::string_view wireless_login_uncertain = "wireless_login_uncertain";
inline constexpr std::string_view wireless_session_lost = "wireless_session_lost";

struct WirelessSessionOptions {
    std::filesystem::path directory;
    const std::atomic_bool* cancel{};
    Mac preferred_mac{};
    std::function<WirelessNetwork(const Mac&)> network_provider;
    portal::Transport transport;
    std::function<void(std::chrono::milliseconds)> pause;
    std::function<void()> environment_ready;
    bool manage_wifi = false;
    bool allow_existing_network = false;
};
struct WirelessCallbacks {
    std::function<void()> online;
    std::function<void()> network_available;
    std::function<void()> recovering;
    // Fixed event names only; no server text, URLs, query strings or credentials.
    std::function<void(std::string_view)> event;
};
// Blocking worker routine. Returns 0 after requested cancellation; only an
// explicit login rejection returns auth_rejected and permits account rotation.
// A submitted login whose outcome is unknown is never retried automatically.
int run_wireless_session(const Credential&, const WirelessSessionOptions&,
                         const WirelessCallbacks& = {}, std::string* failure = nullptr);
} // namespace scau::desktop
