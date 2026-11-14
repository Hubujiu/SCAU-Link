#pragma once
#include <windows.h>
#include <array>
#include <atomic>
#include <condition_variable>
#include <compare>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

namespace scau::desktop::updates {
inline constexpr UINT changed_message = WM_APP + 23;
inline constexpr std::uint64_t maximum_installer_size = 256ull * 1024 * 1024;
inline constexpr unsigned invalid_signature = 0x40000001u;
enum class Phase { Idle, Checking, Current, Available, Downloading, Ready, Starting, InstallQueued, Failed };
struct Version {
    std::array<unsigned, 3> parts{};
    auto operator<=>(const Version&) const = default;
};
std::optional<Version> parse_version(std::wstring_view);
struct Manifest {
    std::wstring version, tag, filename, url;
    std::string sha256;
    std::uint64_t size{};
    bool preview{};
};
struct Candidate { std::wstring tag, manifest_url, signature_url; bool preview{}; };
// JSON parsing runs on a COM-initialized thread for its entire lifetime.
std::optional<Candidate> select_release(std::string_view json, std::wstring_view current, bool allow_preview);
std::optional<Manifest> verify_manifest(std::string_view payload, std::string_view signature,
                                      std::wstring_view tag, bool allow_preview,
                                      std::string_view public_key_hex);
bool allowed_download_url(std::wstring_view url, bool redirected = false);
bool can_install(bool backend_running, bool interaction_busy, bool idle) noexcept;
bool system_idle(DWORD milliseconds = 120000) noexcept;
std::wstring installer_arguments(const std::filesystem::path& directory);
bool verify_installer(const std::filesystem::path&, const Manifest&);

struct Snapshot {
    Phase phase = Phase::Idle;
    std::wstring version;
    unsigned progress{}, error{};
};
// Transport injection is for bounded offline fixtures; production always uses normal TLS.
using Sink = std::function<bool(const void*, std::size_t)>;
using Fetch = std::function<unsigned(std::wstring_view, std::size_t, const Sink&, const std::atomic_bool&)>;
unsigned fetch_https(std::wstring_view, std::size_t, const Sink&, const std::atomic_bool&);
struct Options {
    std::filesystem::path directory, installation;
    std::wstring current;
    bool allow_preview = true, restart_silent = false;
    std::string public_key;
    Fetch fetch;
    std::function<void()> changed;
};
class Manager {
    Options options_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic_bool cancel_ = false;
    Snapshot snapshot_;
    enum class Command { None, Check, Download, Install } command_ = Command::None;
    std::optional<Manifest> manifest_;
    std::string payload_, signature_;
    std::atomic<std::uint64_t> next_check_{};
    void work();
    void check();
    void download();
    void install();
    void set(Phase,unsigned error=0,unsigned progress=0);
    bool enqueue(Command);
    std::filesystem::path cache() const;
  public:
    explicit Manager(Options);
    ~Manager();
    Snapshot snapshot() const;
    void tick(bool idle);
    bool check_now();
    bool download_now();
    bool install_now();
};

// Native helper: inherits only a held parent-process handle and a ready event.
bool start_install_helper(const Options&, const Manifest&, const std::filesystem::path& cache,
                          const std::atomic_bool& cancelled);
int apply_update(int argc, wchar_t** argv, std::string_view trusted_key = {});
} // namespace scau::desktop::updates
