#pragma once
#include "platform.hpp"
#include "wireless_session.hpp"
#include <wlanapi.h>
#include <chrono>
#include <memory>
#include <optional>

namespace scau::desktop {
inline constexpr std::wstring_view scau_8021x_ssid = L"SCAUNET_1x";
// Each supervisor run uses a random identifier; a restarted worker reuses it.
// No account name, password or password hash is used in a Windows profile name.
std::wstring wlan_8021x_profile_name(std::string_view identifier);
std::wstring wlan_8021x_profile_xml(std::wstring_view name);
std::wstring wlan_8021x_credentials_xml(const Credential& credential);

enum class WlanEventType { Connecting, Connected, Failed, Disconnected, OtherConnection, Removed, EapFailure, Overflow };
struct WlanEvent {
    WlanEventType type{};
    DWORD reason = 0, error = 0;
};
// Bounded decoding, exact interface/profile/SSID matching; no XML or identity
// strings in the returned event. ONEX detail is accepted only inside our ACM
// connection context and cannot by itself produce an authenticated state.
std::optional<WlanEvent> decode_wlan_8021x_notification(const WLAN_NOTIFICATION_DATA& data,
    const GUID& interface_id, std::wstring_view profile, bool own_context);
bool wlan_8021x_account_rejected(DWORD error) noexcept;
std::string wlan_8021x_failure_text(DWORD reason, DWORD error = 0);

struct WlanOperation { DWORD error = ERROR_SUCCESS, reason = 0; };
class Wlan8021xPort {
  public:
    virtual ~Wlan8021xPort() = default;
    virtual WlanOperation prepare(const Credential&) = 0;
    virtual WlanOperation connect() = 0;
    virtual std::optional<WlanEvent> wait(std::chrono::milliseconds) = 0;
    virtual void cleanup() noexcept = 0;
};
struct Wlan8021xOptions {
    std::string profile_id;
    // Production uses the SSID as the Windows display/profile name. Random
    // profiles are reserved for explicit, isolated credential-store probes.
    bool stable_profile = true;
    // Windows PEAP on the live campus accepts an all-user NETWORK profile.
    // EAP credentials remain caller-only (WlanSetProfileEapXmlUserData flags=0).
    // The current-user store remains available to explicit diagnostic probes.
    bool per_user_profile = false;
    Mac preferred_mac{};
    const std::atomic_bool* cancel = nullptr;
    std::chrono::milliseconds connect_timeout{60000};
    std::function<void()> environment_ready;
    std::function<std::uint64_t()> now;
    std::function<void(std::chrono::milliseconds)> pause;
};
using Wlan8021xFactory = std::function<std::unique_ptr<Wlan8021xPort>(const Wlan8021xOptions&)>;
std::unique_ptr<Wlan8021xPort> make_native_wlan_8021x_port(const Wlan8021xOptions&);
// No production factory/Windows calls are used when a fixture factory is supplied.
int run_wlan_8021x_session(const Credential&, const Wlan8021xOptions&, const WirelessCallbacks& = {},
                          std::string* failure = nullptr, Wlan8021xFactory = {});
} // namespace scau::desktop
