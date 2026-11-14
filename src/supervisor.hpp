#pragma once

#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace scau {

inline constexpr int supervisor_crash_limit = 70;
inline constexpr int supervisor_error = 71;
inline constexpr std::size_t worker_failure_limit = 768;

// Neither type writes credentials to disk. The parent must remain alive: its
// encrypted session secret cannot be recovered after parent exit or reboot.
struct SessionCredentials {
    std::string username, password;
    SessionCredentials() = default;
    ~SessionCredentials();
    SessionCredentials(const SessionCredentials&) = delete;
    SessionCredentials& operator=(const SessionCredentials&) = delete;
    void clear() noexcept;
};

class EncryptedSessionSecret {
public:
    EncryptedSessionSecret(std::string_view username, std::string_view password);
    ~EncryptedSessionSecret();
    EncryptedSessionSecret(const EncryptedSessionSecret&) = delete;
    EncryptedSessionSecret& operator=(const EncryptedSessionSecret&) = delete;

    // Internal transfer to the private, bounded, write-only credential pipe.
    // Only a transient stack copy is decrypted; it is wiped before returning.
    bool write_to(HANDLE output, const std::array<unsigned char, 32>& nonce) const noexcept;

private:
    std::array<unsigned char, 560> protected_{};
};

// Owns the two inherited pipe handles. Closing this object never manufactures
// a Terminal result: an exit without finish() is an abnormal worker exit.
class WorkerChannel {
public:
    WorkerChannel(HANDLE input, HANDLE output);
    ~WorkerChannel();
    WorkerChannel(const WorkerChannel&) = delete;
    WorkerChannel& operator=(const WorkerChannel&) = delete;
    bool read_credentials(SessionCredentials& credentials);
    bool ready() noexcept;
    bool authenticated() noexcept;
    bool network_available() noexcept;
    bool unauthenticated() noexcept;
    bool finish(int result, std::string_view failure = {}) noexcept;

private:
    bool send(unsigned short kind, int result, std::string_view failure = {}) noexcept;
    HANDLE input_ = nullptr, output_ = nullptr;
    std::array<unsigned char, 32> nonce_{};
    unsigned long sequence_ = 0;
    bool read_ = false, ready_ = false, finished_ = false;
};

struct SupervisorPolicy {
    std::chrono::milliseconds backoff_initial{1000};
    std::chrono::milliseconds backoff_cap{30000};
    std::chrono::milliseconds crash_window{300000};
    std::chrono::milliseconds healthy_reset{60000};
    std::chrono::milliseconds stop_grace{5000};
    std::chrono::milliseconds poll_interval{20};
    unsigned maximum_restarts = 5;
};

struct SupervisorConfig {
    std::filesystem::path executable;
    // User arguments only; internal worker arguments are appended here.
    // Credentials must never be placed in arguments or environment variables.
    std::vector<std::wstring> arguments;
    std::wstring stop_event;
    SupervisorPolicy policy;
};

using SupervisorEvent = std::function<void(std::string_view, long long)>;

// No network work happens in the supervisor. It owns only its child/job, the
// stop event and private IPC. Explicit stop wins over Terminal and restart.
// Returns Terminal's result, 0 for stop, 70 for crash budget, or 71 for errors.
int supervise_worker(const SupervisorConfig& config, EncryptedSessionSecret& secret,
                     std::atomic<bool>& interrupted, SupervisorEvent event = {},
                     std::string* terminal_failure = nullptr);

} // namespace scau
