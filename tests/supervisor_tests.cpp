#include "supervisor.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace {
using namespace scau;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
constexpr std::string_view fixture_user = "offline-fixture-user-4821";
constexpr std::string_view fixture_password = "synthetic-only-password-#7158";

void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }

class Handle {
public:
    explicit Handle(HANDLE handle = nullptr) : value_(handle) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    void reset() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); value_ = nullptr; }
private:
    HANDLE value_;
};

std::wstring event_name() {
    static unsigned counter = 0;
    return L"Local\\ScauOfflineSupervisorTest-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(++counter);
}

SupervisorConfig config_for(const std::filesystem::path& fixture, std::wstring mode) {
    SupervisorConfig result;
    result.executable = fixture;
    result.arguments = {L"--fixture-mode", std::move(mode)};
    result.stop_event = event_name();
    result.policy.backoff_initial = 5ms;
    result.policy.backoff_cap = 20ms;
    result.policy.poll_interval = 2ms;
    result.policy.stop_grace = 30ms;
    result.policy.crash_window = 5s;
    result.policy.healthy_reset = 40ms;
    return result;
}

struct Event {
    std::string name;
    long long value;
};
struct Result {
    int code = -1;
    std::string failure;
    std::vector<Event> events;
    std::vector<long long> values(std::string_view name) const {
        std::vector<long long> found;
        for (const auto& item : events) if (item.name == name) found.push_back(item.value);
        return found;
    }
    std::size_t count(std::string_view name) const { return values(name).size(); }
};

Result run(SupervisorConfig config, std::function<void(std::string_view, std::atomic<bool>&)> action = {}) {
    EncryptedSessionSecret secret(fixture_user, fixture_password);
    std::atomic<bool> interrupted = false;
    Result result;
    result.code = supervise_worker(config, secret, interrupted, [&](std::string_view name, long long value) {
        require(name.find(fixture_user) == std::string_view::npos && name.find(fixture_password) == std::string_view::npos,
                "Supervisor events must not contain credentials");
        result.events.push_back({std::string(name), value});
        if (action) action(name, interrupted);
    }, &result.failure);
    return result;
}

void test_secret_and_bounds() {
    static_assert(!std::is_copy_constructible_v<SessionCredentials>);
    static_assert(!std::is_copy_constructible_v<EncryptedSessionSecret>);
    EncryptedSessionSecret secret(fixture_user, fixture_password);
    const std::string_view encrypted(reinterpret_cast<const char*>(&secret), sizeof(secret));
    require(encrypted.find(fixture_user) == std::string_view::npos && encrypted.find(fixture_password) == std::string_view::npos,
            "Parent-held secret must contain ciphertext only");
    for (const auto size : {0u, 257u}) {
        bool rejected = false;
        try { EncryptedSessionSecret invalid(std::string(size, 'x'), fixture_password); }
        catch (const std::exception&) { rejected = true; }
        require(rejected, "Credential lengths must be bounded");
    }
    bool nul_rejected = false;
    try { EncryptedSessionSecret invalid(fixture_user, std::string_view("a\0b", 3)); }
    catch (...) { nul_rejected = true; }
    require(nul_rejected, "Embedded NUL credentials must be rejected");
    SessionCredentials credentials;
    credentials.username = fixture_user; credentials.password = fixture_password;
    const auto* user_data = credentials.username.data(); const auto* password_data = credentials.password.data();
    const auto user_size = credentials.username.size(), password_size = credentials.password.size();
    credentials.clear();
    require(credentials.username.empty() && credentials.password.empty(), "clear must empty both credentials");
    require(std::all_of(user_data, user_data + user_size, [](char ch) { return ch == 0; }) &&
            std::all_of(password_data, password_data + password_size, [](char ch) { return ch == 0; }),
            "clear must wipe both previous buffers");
}

void test_malformed_credential_pipe() {
    for (const DWORD size : {2ul, 560ul, 561ul}) {
        HANDLE input = nullptr, writer = nullptr, reader = nullptr, output = nullptr;
        require(CreatePipe(&input, &writer, nullptr, 4096) != FALSE, "Create credential test pipe");
        Handle writer_handle(writer);
        require(CreatePipe(&reader, &output, nullptr, 4096) != FALSE, "Create control test pipe");
        Handle reader_handle(reader);
        std::array<unsigned char, 561> bytes{};
        DWORD written = 0;
        require(WriteFile(writer, bytes.data(), size, &written, nullptr) && written == size, "Write malformed record");
        writer_handle.reset();
        WorkerChannel channel(input, output);
        SessionCredentials credentials;
        credentials.username = "old-user"; credentials.password = "old-password";
        require(!channel.ready() && !channel.finish(0), "Uninitialized channel cannot authenticate controls");
        require(!channel.read_credentials(credentials) && credentials.username.empty() && credentials.password.empty(),
                "Malformed credential record must fail and wipe prior credentials");
    }
}

void test_recovery_and_terminal(const std::filesystem::path& fixture) {
    const auto capture = run(config_for(fixture,L"capture-open-failed"));
    require(capture.code==4 && capture.failure=="无法打开有线网卡：请检查抓包驱动和访问权限。" &&
        capture.count("worker_ready")==0 && capture.count("worker_crashed")==0 && capture.count("worker_started")==1,
        "Driver failure before worker ready must retain its reason without crash restart or account rejection");
    const auto available=run(config_for(fixture,L"network-only"));
    require(available.code==0 && available.count("worker_network_available")==1 &&
        available.count("worker_authenticated")==0,"Existing internet cannot authenticate a saved account");
    const auto reason = run(config_for(fixture, L"reject-reason"));
    require(reason.code == 1 && reason.failure == "已达到同时在线用户数量上限" &&
            reason.count("worker_started") == 1 && reason.count("worker_crashed") == 0,
            "Validated UTF-8 rejection must reach the parent without becoming a crash or a log event");
    const auto unknown = run(config_for(fixture, L"reject-unknown"));
    require(unknown.code == 1 && unknown.failure == "unknown", "Explicit unknown failure must reach the parent");
    const auto cancelled = run(config_for(fixture, L"reject-reason"), [](auto name, auto& interrupted) {
        if (name == "worker_terminal") interrupted = true;
    });
    require(cancelled.code == 0 && cancelled.failure.empty(), "Stop must discard a simultaneously buffered failure reason");
    for (const auto mode : {L"crash-once", L"exit-zero"}) {
        const auto result = run(config_for(fixture, mode));
        require(result.code == 0 && result.count("worker_started") == 2 && result.count("worker_crashed") == 1 &&
                result.count("worker_ready") == 2 && result.count("worker_terminal") == 1,
                "Abnormal exit, including zero, must reuse credentials through a fresh worker");
        require(result.values("worker_restart_scheduled") == std::vector<long long>{5}, "First crash delay must be initial backoff");
    }
    const auto rejection = run(config_for(fixture, L"reject"));
    require(rejection.code == 7 && rejection.count("worker_started") == 1 && rejection.count("worker_crashed") == 0 &&
            rejection.count("worker_restart_scheduled") == 0, "Authenticated Terminal rejection must never restart");
    const auto preflight = run(config_for(fixture, L"preflight-terminal"));
    require(preflight.code == 13 && preflight.count("worker_started") == 1 && preflight.count("worker_ready") == 0 &&
            preflight.count("worker_crashed") == 0, "Terminal preflight failure before ready must not restart");
    const auto terminal_crash = run(config_for(fixture, L"terminal-crash"));
    require(terminal_crash.code == 0 && terminal_crash.count("worker_started") == 1 && terminal_crash.count("worker_crashed") == 0,
            "Authenticated Terminal must take precedence over a later exceptional process exit");
    const auto terminal_hang = run(config_for(fixture, L"early-terminal"));
    require(terminal_hang.code == 19 && terminal_hang.count("worker_started") == 1 && terminal_hang.count("worker_crashed") == 0,
            "Terminal must stay terminal even if child must be killed after bounded grace");
}

void test_stop_priority(const std::filesystem::path& fixture) {
    const auto pending = run(config_for(fixture, L"crash-loop"), [](auto name, auto& interrupted) {
        if (name == "worker_restart_scheduled") interrupted = true;
    });
    require(pending.code == 0 && pending.count("worker_started") == 1 && pending.count("supervisor_stopped") == 1,
            "Stop must cancel a pending restart");
    for (const auto mode : {L"wait-stop", L"ignore-stop"}) {
        const auto active = run(config_for(fixture, mode), [](auto name, auto& interrupted) {
            if (name == "worker_authenticated") interrupted = true;
        });
        require(active.code == 0 && active.count("worker_started") == 1 && active.count("worker_restart_scheduled") == 0,
                "Stop must signal graceful workers and kill only owned unresponsive workers");
    }
    const auto terminal_race = run(config_for(fixture, L"early-terminal"), [](auto name, auto& interrupted) {
        if (name == "worker_terminal") interrupted = true;
    });
    require(terminal_race.code == 0 && terminal_race.count("supervisor_stopped") == 1, "Stop must beat simultaneous Terminal");

    auto config = config_for(fixture, L"crash-loop");
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, config.stop_event.c_str()));
    require(stop.get() != nullptr, "Create named stop event");
    const auto named_stop = run(config, [&](auto name, auto&) {
        if (name == "worker_restart_scheduled") SetEvent(stop.get());
    });
    require(named_stop.code == 0 && named_stop.count("worker_started") == 1, "Named stop must cancel pending restart");

    EncryptedSessionSecret secret(fixture_user, fixture_password);
    std::atomic<bool> interrupted = true;
    unsigned started = 0;
    require(supervise_worker(config_for(fixture, L"crash-loop"), secret, interrupted,
                [&](auto name, auto) { if (name == "worker_started") ++started; }) == 0 && started == 0,
            "Already requested stop must launch no worker");
}

void test_backoff_budget_and_health(const std::filesystem::path& fixture) {
    auto config = config_for(fixture, L"crash-loop");
    const auto exhausted = run(config);
    require(exhausted.code == supervisor_crash_limit && exhausted.count("worker_started") == 6 &&
            exhausted.count("worker_crashed") == 6 && exhausted.count("supervisor_retry_exhausted") == 1,
            "Five restarts within the window must stop a crash loop");
    require(exhausted.values("worker_restart_scheduled") == std::vector<long long>({5, 10, 20, 20, 20}),
            "Backoff must double and then remain capped");

    config = config_for(fixture, L"healthy-reset"); config.policy.maximum_restarts = 1;
    const auto healthy = run(config);
    require(healthy.code == 0 && healthy.count("worker_started") == 3 && healthy.count("worker_healthy_reset") == 1 &&
            healthy.values("worker_restart_scheduled") == std::vector<long long>({5, 5}),
            "Confirmed healthy interval must reset escalation and restart budget");
    config.arguments = {L"--fixture-mode", L"lost-health"}; config.stop_event = event_name();
    const auto lost = run(config);
    require(lost.code == supervisor_crash_limit && lost.count("worker_started") == 2 && lost.count("worker_healthy_reset") == 0,
            "Disconnected time must never count as confirmed healthy time");

    config = config_for(fixture, L"two-crashes");
    config.policy.maximum_restarts = 1; config.policy.crash_window = 20ms;
    config.policy.backoff_initial = 30ms; config.policy.backoff_cap = 30ms;
    // Child startup itself need not exceed the window; delay the first crash
    // callback so the rolling budget is unambiguously older on the next crash.
    unsigned crashes = 0;
    const auto rolled = run(config, [&](auto name, auto&) {
        if (name == "worker_crashed" && ++crashes == 2) Sleep(25);
    });
    require(rolled.code == 0 && rolled.count("worker_started") == 3, "Expired rolling-window restarts must leave the budget");
}

void test_bad_control_and_arguments(const std::filesystem::path& fixture) {
    for (const auto mode : {L"bad-ipc", L"partial-ipc", L"wrong-nonce"}) {
        const auto result = run(config_for(fixture, mode));
        require(result.code == supervisor_error && result.count("worker_started") == 1 &&
                result.count("supervisor_protocol_error") == 1 && result.count("worker_restart_scheduled") == 0,
                "Malformed or unauthenticated control must stop conservatively");
    }
    auto config = config_for(fixture, L"quoting");
    config.arguments.emplace_back(L"--quoted-argument"); config.arguments.emplace_back(L"space \\\"quote\\\\ trailing\\");
    config.arguments.emplace_back(L"--stop-event"); config.arguments.push_back(config.stop_event);
    require(run(config).code == 0, "Windows argument quoting and existing stop event must round-trip");
    config.stop_event = event_name();
    require(run(config).code == supervisor_error, "Mismatched stop events must fail before creating a worker");
    config = config_for(fixture, L"reject"); config.arguments.emplace_back(L"--worker-input"); config.arguments.emplace_back(L"123");
    require(run(config).code == supervisor_error, "Caller cannot forward internal worker handles");
    config = config_for(fixture, L"reject"); config.executable += L"-missing";
    require(run(config).code == supervisor_error, "Missing executable must fail without a restart storm");

    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    Handle forbidden(CreateEventW(&security, TRUE, FALSE, nullptr));
    require(forbidden.get() != nullptr, "Create unrelated inheritable event");
    config = config_for(fixture, L"reject");
    config.arguments.emplace_back(L"--forbidden-handle");
    config.arguments.push_back(std::to_wstring(reinterpret_cast<std::uintptr_t>(forbidden.get())));
    require(run(config).code == 7 && WaitForSingleObject(forbidden.get(), 0) == WAIT_TIMEOUT,
            "Handle allowlist must exclude unrelated inheritable handles");
}

std::wstring quote_path(std::wstring_view value) {
    // Helper paths in this offline test have no quote characters.
    require(value.find(L'"') == std::wstring_view::npos, "Unexpected quote in fixture path");
    return L"\"" + std::wstring(value) + L"\"";
}

int job_owner(const std::filesystem::path& fixture, HANDLE report) {
    auto config = config_for(fixture, L"ignore-stop");
    EncryptedSessionSecret secret(fixture_user, fixture_password);
    std::atomic<bool> interrupted = false;
    DWORD worker_pid = 0;
    return supervise_worker(config, secret, interrupted, [&](auto name, auto value) {
        if (name == "worker_started") worker_pid = static_cast<DWORD>(value);
        if (name == "worker_authenticated") {
            // Report only after the real worker has run inside the owned job.
            DWORD written = 0;
            WriteFile(report, &worker_pid, sizeof(worker_pid), &written, nullptr);
            CloseHandle(report);
        }
    });
}

void test_parent_job_cleanup(const std::filesystem::path& fixture, const std::filesystem::path& self) {
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE report_read = nullptr, report_write = nullptr;
    require(CreatePipe(&report_read, &report_write, &security, 4096) != FALSE, "Create owner report pipe");
    Handle reader(report_read), writer(report_write);
    require(SetHandleInformation(report_read, HANDLE_FLAG_INHERIT, 0) != FALSE, "Restrict owner report read handle");
    std::wstring command = quote_path(self.wstring()) + L" --job-owner " + quote_path(fixture.wstring()) + L" " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(report_write));
    SIZE_T size = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    std::vector<unsigned char> memory(size);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(memory.data());
    require(InitializeProcThreadAttributeList(attributes, 1, 0, &size) != FALSE, "Initialize owner launch attributes");
    const bool configured = UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                     &report_write, sizeof(report_write), nullptr, nullptr) != FALSE;
    if (!configured) { DeleteProcThreadAttributeList(attributes); require(false, "Restrict owner report inheritance"); }
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = attributes;
    PROCESS_INFORMATION process{};
    const bool created = CreateProcessW(self.c_str(), command.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr, &startup.StartupInfo, &process) != FALSE;
    DeleteProcThreadAttributeList(attributes);
    require(created, "Launch isolated supervisor owner");
    Handle owner(process.hProcess), thread(process.hThread);
    struct OwnerCleanup {
        HANDLE owner;
        ~OwnerCleanup() { TerminateProcess(owner, 93); WaitForSingleObject(owner, 5000); }
    } cleanup{owner.get()};

    DWORD available = 0;
    const auto deadline = Clock::now() + 10s;
    while (Clock::now() < deadline) {
        if (PeekNamedPipe(report_read, nullptr, 0, nullptr, &available, nullptr) && available >= sizeof(DWORD)) break;
        require(WaitForSingleObject(owner.get(), 0) == WAIT_TIMEOUT, "Supervisor owner exited before worker startup");
        Sleep(5);
    }
    require(available >= sizeof(DWORD), "Timed out waiting for owned offline worker");
    DWORD pid = 0, received = 0;
    require(ReadFile(report_read, &pid, sizeof(pid), &received, nullptr) && received == sizeof(pid), "Read owned worker PID");
    Handle child(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    require(child.get() != nullptr && WaitForSingleObject(child.get(), 0) == WAIT_TIMEOUT, "Offline worker must initially be alive");
    require(TerminateProcess(owner.get(), 92) != FALSE && WaitForSingleObject(owner.get(), 5000) == WAIT_OBJECT_0,
            "Terminate only isolated test owner");
    require(WaitForSingleObject(child.get(), 5000) == WAIT_OBJECT_0, "Closing killed parent's job must kill its worker");
}

DWORD handles() {
    DWORD count = 0; require(GetProcessHandleCount(GetCurrentProcess(), &count) != FALSE, "Read process handle count"); return count;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    try {
        if (argc == 4 && std::wstring_view(argv[1]) == L"--job-owner") {
            const auto report = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::stoull(argv[3])));
            return job_owner(argv[2], report);
        }
        require(argc == 2, "Usage: supervisor-tests.exe worker-fixture.exe");
        const auto fixture = std::filesystem::absolute(argv[1]);
        std::array<wchar_t, 32768> path{};
        require(GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())) != 0, "Get test executable path");
        test_secret_and_bounds();
        // Warm up Windows crypto/process support before measuring owned handles.
        require(run(config_for(fixture, L"reject")).code == 7, "Offline fixture warmup");
        // Windows caches loader/AppModel handles on its first failed process
        // lookup. Measure exact handle stability after that one-time OS setup.
        auto missing = config_for(fixture, L"reject"); missing.executable += L"-missing";
        require(run(missing).code == supervisor_error, "Failed-launch warmup");
        const auto before = handles();
        test_malformed_credential_pipe();
        test_recovery_and_terminal(fixture);
        test_stop_priority(fixture);
        test_backoff_budget_and_health(fixture);
        test_bad_control_and_arguments(fixture);
        test_parent_job_cleanup(fixture, path.data());
        require(handles() == before, "Supervisor must not leak handles across normal, crash, stop or malformed IPC paths");
        std::cout << "PASS: encrypted session-only credentials; private one-way allowlisted pipes; crash/zero-exit recovery; "
                     "Terminal and stop priority; bounded backoff/window/healthy reset; malformed IPC; parent job cleanup; no handle leaks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
