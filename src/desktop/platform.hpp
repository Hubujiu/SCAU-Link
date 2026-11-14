#pragma once
#include "logs.hpp"
#include <windows.h>
#include <array>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace scau::desktop {
enum class ConnectionMode { Wired, WirelessWeb, Wireless8021x };
inline const wchar_t* connection_mode_label(ConnectionMode mode) noexcept {
    return mode == ConnectionMode::Wireless8021x ? L"无线 802.1X" :
           mode == ConnectionMode::WirelessWeb ? L"无线 Web" : L"有线 802.1X";
}
struct Settings {
    bool mini = false, auto_start = false, silent = false;
    ConnectionMode mode = ConnectionMode::Wired;
    // Empty follows the last manually selected mode. Otherwise, ordered boot attempts.
    std::vector<ConnectionMode> startup_modes;
};
std::vector<ConnectionMode> parse_startup_modes(std::wstring_view text);
std::vector<ConnectionMode> startup_connection_modes(const Settings& settings);
struct Startup {
    bool show_window = true, notify = true, auto_login = false;
};
inline Startup startup_policy(bool silent, bool has_credentials) noexcept {
    return {!silent, !silent, has_credentials};
}
std::filesystem::path executable_path();
std::filesystem::path data_directory();
std::wstring quote_argument(std::wstring_view value);
std::wstring startup_command(const std::filesystem::path &executable);
Settings load_settings(const std::filesystem::path &directory);
void save_settings(const std::filesystem::path &directory, const Settings &settings);
bool auto_start_enabled();
void set_auto_start(bool enabled, const std::filesystem::path &executable);
bool original_client_running();
std::wstring adapter_name(const std::filesystem::path &profile);
bool adapter_ready(const std::array<unsigned char, 6> &mac);
std::filesystem::path locate_profile(const std::filesystem::path &directory,
                                     const std::filesystem::path &executable);
std::wstring utf8_to_wide(std::string_view value);
std::string to_gbk(std::wstring_view value);

struct Credential {
    std::wstring username, password;
    Credential() = default;
    ~Credential() {
        clear();
    }
    Credential(const Credential &) = delete;
    Credential &operator=(const Credential &) = delete;
    void clear() noexcept;
};
class CredentialStore {
    std::wstring target_;

  public:
    explicit CredentialStore(std::wstring target = L"SCAULink/Authentication/v1")
        : target_(std::move(target)) {}
    bool read(Credential &value) const;
    void write(const Credential &value) const;
    void erase() const;
};
std::vector<std::wstring> read_recent_logs(const std::filesystem::path &directory);
} // namespace scau::desktop
