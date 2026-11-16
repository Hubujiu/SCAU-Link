#pragma once
#include "protocol.hpp"
#include <functional>
#include <optional>

namespace scau::desktop {
struct ConnectionAdapter {
    Mac mac{};
    std::string id;
    std::wstring name;
    unsigned index{}, metric{};
    bool physical = false, ethernet = false, link_up = false;
    bool ipv4 = false, gateway = false, dhcp = true;
    bool wireless = false;
    std::array<Byte,4> address{}; // Live address only; never included in the connection cache.
};
std::vector<ConnectionAdapter> connection_adapters();
std::optional<std::size_t> choose_connection_adapter(std::span<const ConnectionAdapter> adapters,
                                                     const Mac& preferred = {});
// Native, read-only storage-property query. No disk contents are read.
Bytes system_disk_identity();
Bytes scau_wired_service();
Profile make_connection_profile(const ConnectionAdapter& adapter, std::span<const Byte> disk_identity);
struct ConnectionSetup {
    std::filesystem::path path;
    std::wstring adapter;
    Mac mac{};
    bool found = false, link_up = false, created = false, migrated = false;
};
using DeviceIdentityReader = std::function<Bytes()>;
// Only app-owned cache/legacy files in this directory are considered. Never
// searches the installation's parents, captures, or another machine's profile.
ConnectionSetup prepare_connection(const std::filesystem::path& directory,
    std::span<const ConnectionAdapter> adapters, DeviceIdentityReader identity = {});
ConnectionSetup prepare_connection(const std::filesystem::path& directory);
bool capture_driver_available();
enum class CaptureDriverState { Ready, Starting, Missing, Stopped, AccessDenied, Failed };
CaptureDriverState capture_driver_state(bool start_if_stopped = false);
const wchar_t* capture_driver_message(CaptureDriverState state);
// Wakes immediately on interface changes; bounded waits also cover driver readiness.
class NetworkReadySignal {
    void* event_{};
    void* notification_{};
public:
    NetworkReadySignal();
    ~NetworkReadySignal();
    NetworkReadySignal(const NetworkReadySignal&) = delete;
    void wait(unsigned milliseconds) const;
};
} // namespace scau::desktop
