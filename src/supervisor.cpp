#include "supervisor.hpp"

#include <bcrypt.h>
#include <dpapi.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace scau {
namespace {
using Clock = std::chrono::steady_clock;
using Milliseconds = std::chrono::milliseconds;
using Nonce = std::array<unsigned char, 32>;
constexpr std::uint32_t credential_magic = 0x53434155;
constexpr std::uint32_t control_magic = 0x53434143;
constexpr std::uint16_t protocol_version = 1;
constexpr std::uint16_t control_version = 2;
constexpr std::uint16_t kind_ready = 1, kind_authenticated = 2, kind_terminal = 3, kind_unauthenticated = 4,
    kind_network_available = 5;

struct CredentialRecord {
    std::uint32_t magic;
    std::uint16_t version, reserved;
    std::uint32_t username_size, password_size;
    Nonce nonce;
    std::array<char, 256> username, password;
};
struct ControlRecord {
    std::uint32_t magic;
    std::uint16_t version, kind;
    std::uint32_t sequence;
    std::int32_t result;
    Nonce nonce;
    std::uint32_t failure_size;
    std::array<char, worker_failure_limit> failure;
};
static_assert(sizeof(CredentialRecord) == 560);
static_assert(sizeof(CredentialRecord) % CRYPTPROTECTMEMORY_BLOCK_SIZE == 0);
static_assert(sizeof(ControlRecord) == 52 + worker_failure_limit);

template<class T> struct Wiped {
    T value{};
    ~Wiped() { SecureZeroMemory(&value, sizeof(value)); }
};

class Handle {
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) reset(std::exchange(other.value_, nullptr));
        return *this;
    }
    HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
    void reset(HANDLE value = nullptr) noexcept {
        if (*this) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_;
};

bool valid_credential(std::string_view value) noexcept {
    return !value.empty() && value.size() <= 256 && value.find('\0') == std::string_view::npos;
}

bool valid_failure(std::string_view value) noexcept {
    if (value.size() > worker_failure_limit) return false;
    if (value.empty()) return true;
    for (unsigned char ch : value) if (ch < 32 || ch == 127) return false;
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), int(value.size()), nullptr, 0) > 0;
}

bool write_all(HANDLE output, const void* data, std::size_t size) noexcept {
    const auto* bytes = static_cast<const unsigned char*>(data);
    while (size) {
        DWORD written = 0;
        if (!WriteFile(output, bytes, static_cast<DWORD>(size), &written, nullptr) || !written) return false;
        bytes += written;
        size -= written;
    }
    return true;
}

bool nonzero(const Nonce& nonce) noexcept {
    unsigned char combined = 0;
    for (auto ch : nonce) combined |= ch;
    return combined != 0;
}

bool same_nonce(const Nonce& left, const Nonce& right) noexcept {
    unsigned char difference = 0;
    for (std::size_t i = 0; i < left.size(); ++i) difference |= left[i] ^ right[i];
    return difference == 0;
}

Nonce random_nonce() {
    Nonce result{};
    if (BCryptGenRandom(nullptr, result.data(), static_cast<ULONG>(result.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 || !nonzero(result))
        throw std::runtime_error("Cannot create private worker channel");
    return result;
}

// The sender closes its copy before resuming the worker. Peek first so manual
// or malformed invocations cannot block indefinitely on a supplied pipe.
bool read_record(HANDLE input, CredentialRecord& record) noexcept {
    const auto deadline = Clock::now() + std::chrono::seconds(5);
    auto* data = reinterpret_cast<unsigned char*>(&record);
    std::size_t used = 0;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr))
            return GetLastError() == ERROR_BROKEN_PIPE && used == sizeof(record);
        if (available) {
            if (used == sizeof(record)) return false;
            DWORD received = 0;
            const auto wanted = static_cast<DWORD>(std::min<std::size_t>(available, sizeof(record) - used));
            if (!ReadFile(input, data + used, wanted, &received, nullptr) || !received) return false;
            used += received;
            continue;
        }
        if (Clock::now() >= deadline) return false;
        Sleep(5);
    }
}

std::wstring quote_argument(std::wstring_view argument) {
    std::wstring result(1, L'"');
    std::size_t slashes = 0;
    for (const auto ch : argument) {
        if (ch == L'\\') { ++slashes; continue; }
        result.append(ch == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        slashes = 0;
        result += ch;
    }
    result.append(slashes * 2, L'\\');
    result += L'"';
    return result;
}

std::wstring handle_argument(HANDLE handle) {
    return std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
}

std::wstring effective_stop_event(const SupervisorConfig& config) {
    std::wstring from_arguments;
    for (std::size_t i = 0; i < config.arguments.size(); ++i) {
        const auto& argument = config.arguments[i];
        if (argument.find(L'\0') != std::wstring::npos) throw std::runtime_error("Invalid worker argument");
        if (argument == L"--worker-input" || argument == L"--worker-output" || argument == L"--recovery-attempt")
            throw std::runtime_error("Internal worker arguments cannot be forwarded");
        if (argument == L"--stop-event") {
            if (!from_arguments.empty() || i + 1 == config.arguments.size() || config.arguments[i + 1].empty())
                throw std::runtime_error("Invalid worker stop event");
            from_arguments = config.arguments[++i];
            if (from_arguments.find(L'\0') != std::wstring::npos) throw std::runtime_error("Invalid worker stop event");
        }
    }
    if (config.stop_event.find(L'\0') != std::wstring::npos) throw std::runtime_error("Invalid supervisor stop event");
    if (!from_arguments.empty()) {
        if (!config.stop_event.empty() && config.stop_event != from_arguments) throw std::runtime_error("Worker stop event mismatch");
        return from_arguments;
    }
    if (!config.stop_event.empty()) return config.stop_event;
    const auto nonce = random_nonce();
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring name = L"Local\\ScauAuthSupervisor-" + std::to_wstring(GetCurrentProcessId()) + L"-";
    for (const auto ch : nonce) { name += digits[ch >> 4]; name += digits[ch & 15]; }
    return name;
}

void validate_policy(const SupervisorPolicy& policy) {
    if (policy.backoff_initial.count() <= 0 || policy.backoff_cap < policy.backoff_initial ||
        policy.crash_window.count() <= 0 || policy.healthy_reset.count() <= 0 ||
        policy.stop_grace.count() < 0 || policy.poll_interval.count() <= 0 ||
        policy.poll_interval > std::chrono::seconds(1) || policy.maximum_restarts > 1000 ||
        policy.backoff_cap > std::chrono::hours(24) || policy.crash_window > std::chrono::hours(24) ||
        policy.healthy_reset > std::chrono::hours(24) || policy.stop_grace > std::chrono::minutes(1))
        throw std::runtime_error("Invalid supervisor policy");
}

class Attributes {
public:
    Attributes(HANDLE (&inherited)[2], HANDLE& job) {
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &size);
        memory_.resize(size);
        list_ = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(memory_.data());
        if (!InitializeProcThreadAttributeList(list_, 2, 0, &size)) {
            list_ = nullptr;
            throw std::runtime_error("Cannot initialize private worker attributes");
        }
        if (!UpdateProcThreadAttribute(list_, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr) ||
            !UpdateProcThreadAttribute(list_, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof(job), nullptr, nullptr)) {
            DeleteProcThreadAttributeList(list_);
            list_ = nullptr;
            throw std::runtime_error("Cannot restrict worker inheritance");
        }
    }
    ~Attributes() { if (list_) DeleteProcThreadAttributeList(list_); }
    LPPROC_THREAD_ATTRIBUTE_LIST get() const noexcept { return list_; }
private:
    std::vector<unsigned char> memory_;
    LPPROC_THREAD_ATTRIBUTE_LIST list_ = nullptr;
};

struct Child {
    // Destruction closes the job first, killing any owned worker/descendants.
    Handle process;
    Handle control;
    Handle job;
    DWORD pid = 0;
};

bool stopping(HANDLE stop, const std::atomic<bool>& interrupted) noexcept;

Child launch_worker(const SupervisorConfig& config, const std::wstring& stop_name,
                    const Nonce& nonce, std::uint64_t attempt, EncryptedSessionSecret& secret,
                    HANDLE stop, const std::atomic<bool>& interrupted) {
    Child child;
    child.job.reset(CreateJobObjectW(nullptr, nullptr));
    if (!child.job) throw std::runtime_error("Cannot create worker job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(child.job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        throw std::runtime_error("Cannot configure worker job");

    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE raw_input = nullptr, raw_secret = nullptr;
    if (!CreatePipe(&raw_input, &raw_secret, &security, 4096)) throw std::runtime_error("Cannot create private credential pipe");
    Handle input(raw_input), output(raw_secret);
    HANDLE raw_control = nullptr, raw_worker_output = nullptr;
    if (!CreatePipe(&raw_control, &raw_worker_output, &security, 4096)) throw std::runtime_error("Cannot create private control pipe");
    child.control.reset(raw_control);
    Handle worker_output(raw_worker_output);
    if (!SetHandleInformation(output.get(), HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(child.control.get(), HANDLE_FLAG_INHERIT, 0))
        throw std::runtime_error("Cannot restrict parent pipe inheritance");

    const auto executable = std::filesystem::absolute(config.executable).wstring();
    if (config.executable.empty() || executable.find(L'\0') != std::wstring::npos)
        throw std::runtime_error("Invalid worker executable");
    auto arguments = config.arguments;
    if (std::find(arguments.begin(), arguments.end(), L"--stop-event") == arguments.end()) {
        arguments.emplace_back(L"--stop-event");
        arguments.push_back(stop_name);
    }
    arguments.emplace_back(L"--worker-input"); arguments.push_back(handle_argument(input.get()));
    arguments.emplace_back(L"--worker-output"); arguments.push_back(handle_argument(worker_output.get()));
    arguments.emplace_back(L"--recovery-attempt"); arguments.push_back(std::to_wstring(attempt));
    std::wstring command = quote_argument(executable);
    for (const auto& argument : arguments) { command += L' '; command += quote_argument(argument); }
    if (command.size() >= 32767) throw std::runtime_error("Worker command is too long");

    HANDLE inherited[]{input.get(), worker_output.get()};
    HANDLE job_handle = child.job.get();
    Attributes attributes(inherited, job_handle);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes.get();
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup.StartupInfo, &process))
        throw std::runtime_error("Cannot create supervised worker");
    child.process.reset(process.hProcess);
    Handle thread(process.hThread);
    child.pid = process.dwProcessId;
    // JOB_LIST closes the parent-death race during CreateProcess itself. Verify
    // membership while suspended; never execute an unowned worker.
    BOOL in_job = FALSE;
    if (!IsProcessInJob(child.process.get(), child.job.get(), &in_job) ||
        (!in_job && !AssignProcessToJobObject(child.job.get(), child.process.get()))) {
        TerminateProcess(child.process.get(), supervisor_error);
        WaitForSingleObject(child.process.get(), 5000);
        throw std::runtime_error("Cannot contain supervised worker");
    }
    // This single fixed record fits entirely in the newly created 4096-byte
    // pipe, so no child execution is required to complete the bounded write.
    if (!secret.write_to(output.get(), nonce)) throw std::runtime_error("Cannot transfer session credentials");
    output.reset(); input.reset(); worker_output.reset();
    if (stopping(stop, interrupted)) {
        SetEvent(stop);
        TerminateJobObject(child.job.get(), 0);
        WaitForSingleObject(child.process.get(), 5000);
        return child;
    }
    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) throw std::runtime_error("Cannot resume supervised worker");
    return child;
}

struct ControlReader {
    Nonce nonce;
    std::array<unsigned char, sizeof(ControlRecord)> pending{};
    std::size_t used = 0;
    std::uint32_t sequence = 0;
    bool ready = false, error = false, eof = false;
    std::optional<int> terminal;
    std::string failure;
    std::optional<Clock::time_point> healthy_since;
    bool healthy_reset = false;
    std::optional<Clock::time_point> eof_since;

    ~ControlReader() {
        SecureZeroMemory(nonce.data(), nonce.size());
        SecureZeroMemory(pending.data(), pending.size());
    }

    template<class Emit> void drain(HANDLE input, Emit& emit) {
        // Bound work per pass so a misbehaving child cannot starve stop checks.
        for (unsigned count = 0; count < 64 && !error && !terminal; ++count) {
            DWORD available = 0;
            if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) {
                eof = GetLastError() == ERROR_BROKEN_PIPE;
                error = !eof || used != 0;
                if (eof && !eof_since) eof_since = Clock::now();
                return;
            }
            if (!available) return;
            DWORD received = 0;
            const auto wanted = static_cast<DWORD>(std::min<std::size_t>(available, pending.size() - used));
            if (!ReadFile(input, pending.data() + used, wanted, &received, nullptr) || !received) { error = true; return; }
            used += received;
            if (used != pending.size()) continue;
            Wiped<ControlRecord> record;
            std::memcpy(&record.value, pending.data(), pending.size());
            SecureZeroMemory(pending.data(), pending.size());
            used = 0;
            const auto& message = record.value;
            if (message.magic != control_magic || message.version != control_version ||
                sequence == std::numeric_limits<std::uint32_t>::max() || message.sequence != sequence + 1 ||
                !same_nonce(message.nonce, nonce) || (message.kind != kind_terminal && message.result != 0) ||
                message.failure_size > message.failure.size() ||
                (message.kind != kind_terminal && message.failure_size != 0)) {
                error = true; return;
            }
            const std::string_view reason(message.failure.data(), message.failure_size);
            if (!valid_failure(reason) || !std::all_of(message.failure.begin() + message.failure_size,
                                                      message.failure.end(), [](char ch) { return ch == 0; })) {
                error = true; return;
            }
            ++sequence;
            if (message.kind == kind_terminal) {
                terminal = message.result;
                failure.assign(reason);
                emit("worker_terminal", *terminal);
            } else if (message.kind == kind_ready && !ready) {
                ready = true;
                emit("worker_ready", 0);
            } else if (message.kind == kind_authenticated && ready) {
                if (!healthy_since) { healthy_since = Clock::now(); healthy_reset = false; }
                emit("worker_authenticated", 0);
            } else if (message.kind == kind_network_available && ready) {
                if (!healthy_since) { healthy_since = Clock::now(); healthy_reset = false; }
                emit("worker_network_available", 0);
            } else if (message.kind == kind_unauthenticated && ready) {
                healthy_since.reset(); healthy_reset = false;
                emit("worker_unauthenticated", 0);
            } else error = true;
        }
    }
};

bool stopping(HANDLE stop, const std::atomic<bool>& interrupted) noexcept {
    return interrupted.load(std::memory_order_relaxed) || WaitForSingleObject(stop, 0) == WAIT_OBJECT_0;
}

void settle_child(Child& child, HANDLE stop, const SupervisorPolicy& policy, bool request_stop,
                  const std::atomic<bool>& interrupted) noexcept {
    if (request_stop) SetEvent(stop);
    const auto deadline = Clock::now() + policy.stop_grace;
    while (WaitForSingleObject(child.process.get(), 0) == WAIT_TIMEOUT && Clock::now() < deadline) {
        // A stop arriving after Terminal still reaches the worker promptly.
        if (stopping(stop, interrupted)) SetEvent(stop);
        WaitForSingleObject(child.process.get(), static_cast<DWORD>(policy.poll_interval.count()));
    }
    if (WaitForSingleObject(child.process.get(), 0) == WAIT_TIMEOUT) {
        if (!TerminateJobObject(child.job.get(), supervisor_error)) TerminateProcess(child.process.get(), supervisor_error);
        WaitForSingleObject(child.process.get(), 5000);
    }
}
} // namespace

SessionCredentials::~SessionCredentials() { clear(); }

void SessionCredentials::clear() noexcept {
    SecureZeroMemory(username.data(), username.size());
    SecureZeroMemory(password.data(), password.size());
    username.clear(); password.clear();
}

EncryptedSessionSecret::EncryptedSessionSecret(std::string_view username, std::string_view password) {
    if (!valid_credential(username) || !valid_credential(password)) throw std::runtime_error("Invalid session credential length");
    Wiped<CredentialRecord> record;
    record.value.magic = credential_magic;
    record.value.version = protocol_version;
    record.value.username_size = static_cast<std::uint32_t>(username.size());
    record.value.password_size = static_cast<std::uint32_t>(password.size());
    std::memcpy(record.value.username.data(), username.data(), username.size());
    std::memcpy(record.value.password.data(), password.data(), password.size());
    if (!CryptProtectMemory(&record.value, sizeof(record.value), CRYPTPROTECTMEMORY_SAME_PROCESS))
        throw std::runtime_error("Cannot protect session credentials");
    std::memcpy(protected_.data(), &record.value, protected_.size());
}

EncryptedSessionSecret::~EncryptedSessionSecret() { SecureZeroMemory(protected_.data(), protected_.size()); }

bool EncryptedSessionSecret::write_to(HANDLE output, const Nonce& nonce) const noexcept {
    Wiped<CredentialRecord> record;
    std::memcpy(&record.value, protected_.data(), protected_.size());
    if (!nonzero(nonce) || !CryptUnprotectMemory(&record.value, sizeof(record.value), CRYPTPROTECTMEMORY_SAME_PROCESS)) return false;
    record.value.nonce = nonce;
    return write_all(output, &record.value, sizeof(record.value));
}

WorkerChannel::WorkerChannel(HANDLE input, HANDLE output) : input_(input), output_(output) {
    if (!input_ || input_ == INVALID_HANDLE_VALUE || !output_ || output_ == INVALID_HANDLE_VALUE || input_ == output_ ||
        GetFileType(input_) != FILE_TYPE_PIPE || GetFileType(output_) != FILE_TYPE_PIPE ||
        !SetHandleInformation(input_, HANDLE_FLAG_INHERIT, 0) || !SetHandleInformation(output_, HANDLE_FLAG_INHERIT, 0)) {
        if (input_ && input_ != INVALID_HANDLE_VALUE) CloseHandle(input_);
        if (output_ && output_ != INVALID_HANDLE_VALUE && output_ != input_) CloseHandle(output_);
        input_ = output_ = nullptr;
        throw std::runtime_error("Invalid inherited worker channel");
    }
}

WorkerChannel::~WorkerChannel() {
    if (input_) CloseHandle(input_);
    if (output_) CloseHandle(output_);
    SecureZeroMemory(nonce_.data(), nonce_.size());
}

bool WorkerChannel::read_credentials(SessionCredentials& credentials) {
    credentials.clear();
    if (read_ || !input_) return false;
    Wiped<CredentialRecord> record;
    const bool received = read_record(input_, record.value);
    CloseHandle(input_); input_ = nullptr;
    const auto& value = record.value;
    if (!received || value.magic != credential_magic || value.version != protocol_version || value.reserved != 0 ||
        value.username_size == 0 || value.username_size > value.username.size() ||
        value.password_size == 0 || value.password_size > value.password.size() || !nonzero(value.nonce)) return false;
    const std::string_view username(value.username.data(), value.username_size), password(value.password.data(), value.password_size);
    if (!valid_credential(username) || !valid_credential(password)) return false;
    try {
        credentials.username.assign(username);
        credentials.password.assign(password);
    } catch (...) { credentials.clear(); throw; }
    nonce_ = value.nonce;
    read_ = true;
    return true;
}

bool WorkerChannel::send(unsigned short kind, int result, std::string_view failure) noexcept {
    if (!read_ || !output_ || finished_ || sequence_ == std::numeric_limits<std::uint32_t>::max()) return false;
    if (!valid_failure(failure) || (kind != kind_terminal && !failure.empty())) return false;
    Wiped<ControlRecord> record;
    record.value = {control_magic, control_version, kind, ++sequence_, static_cast<std::int32_t>(result), nonce_,
                    static_cast<std::uint32_t>(failure.size()), {}};
    if (!failure.empty()) std::memcpy(record.value.failure.data(), failure.data(), failure.size());
    return write_all(output_, &record.value, sizeof(record.value));
}

bool WorkerChannel::ready() noexcept {
    if (ready_ || !send(kind_ready, 0)) return false;
    ready_ = true;
    return true;
}

bool WorkerChannel::authenticated() noexcept { return ready_ && send(kind_authenticated, 0); }
bool WorkerChannel::network_available() noexcept { return ready_ && send(kind_network_available, 0); }
bool WorkerChannel::unauthenticated() noexcept { return ready_ && send(kind_unauthenticated, 0); }

bool WorkerChannel::finish(int result, std::string_view failure) noexcept {
    if (!send(kind_terminal, result, failure)) return false;
    finished_ = true;
    return true;
}

int supervise_worker(const SupervisorConfig& config, EncryptedSessionSecret& secret,
                     std::atomic<bool>& interrupted, SupervisorEvent event, std::string* terminal_failure) {
    if (terminal_failure) terminal_failure->clear();
    const auto emit = [&](std::string_view name, long long value) noexcept {
        if (event) try { event(name, value); } catch (...) { /* Diagnostics cannot orphan the worker. */ }
    };
    Handle stop;
    try {
        validate_policy(config.policy);
        const auto stop_name = effective_stop_event(config);
        stop.reset(CreateEventW(nullptr, TRUE, FALSE, stop_name.c_str()));
        if (!stop) throw std::runtime_error("Cannot open supervisor stop event");
        std::deque<Clock::time_point> restarts;
        auto delay = config.policy.backoff_initial;
        std::uint64_t attempt = 0;
        for (;;) {
            if (stopping(stop.get(), interrupted)) { SetEvent(stop.get()); emit("supervisor_stopped", 0); return 0; }
            Wiped<Nonce> nonce;
            nonce.value = random_nonce();
            auto child = launch_worker(config, stop_name, nonce.value, attempt, secret, stop.get(), interrupted);
            ControlReader controls{nonce.value};
            emit("worker_started", child.pid);
            for (;;) {
                if (stopping(stop.get(), interrupted)) {
                    settle_child(child, stop.get(), config.policy, true, interrupted);
                    emit("supervisor_stopped", 0); return 0;
                }
                controls.drain(child.control.get(), emit);
                if (stopping(stop.get(), interrupted)) {
                    settle_child(child, stop.get(), config.policy, true, interrupted);
                    emit("supervisor_stopped", 0); return 0;
                }
                const auto process_state = WaitForSingleObject(child.process.get(), 0);
                if (controls.error || process_state == WAIT_FAILED ||
                    (controls.eof_since && process_state == WAIT_TIMEOUT && Clock::now() - *controls.eof_since >= config.policy.stop_grace)) {
                    emit("supervisor_protocol_error", 0);
                    settle_child(child, stop.get(), config.policy, false, interrupted);
                    if (stopping(stop.get(), interrupted)) {
                        emit("supervisor_stopped", 0); return 0;
                    }
                    return supervisor_error;
                }
                if (controls.terminal) {
                    settle_child(child, stop.get(), config.policy, false, interrupted);
                    if (stopping(stop.get(), interrupted)) { SetEvent(stop.get()); emit("supervisor_stopped", 0); return 0; }
                    if (terminal_failure) *terminal_failure = std::move(controls.failure);
                    return *controls.terminal;
                }
                if (process_state == WAIT_TIMEOUT && controls.healthy_since && !controls.healthy_reset &&
                    Clock::now() - *controls.healthy_since >= config.policy.healthy_reset) {
                    restarts.clear(); delay = config.policy.backoff_initial; controls.healthy_reset = true;
                    emit("worker_healthy_reset", 0);
                }
                if (process_state == WAIT_OBJECT_0) {
                    // Re-read after observing exit; buffered Terminal must beat
                    // even a nonzero/exceptional process exit code.
                    controls.drain(child.control.get(), emit);
                    if (stopping(stop.get(), interrupted)) { SetEvent(stop.get()); emit("supervisor_stopped", 0); return 0; }
                    if (controls.error) { emit("supervisor_protocol_error", 0); return supervisor_error; }
                    if (controls.terminal) {
                        if (terminal_failure) *terminal_failure = std::move(controls.failure);
                        return *controls.terminal;
                    }
                    DWORD available = 0;
                    if (PeekNamedPipe(child.control.get(), nullptr, 0, nullptr, &available, nullptr) && available) continue;
                    if (controls.used) { emit("supervisor_protocol_error", 0); return supervisor_error; }
                    DWORD code = 0;
                    if (!GetExitCodeProcess(child.process.get(), &code)) throw std::runtime_error("Cannot inspect worker exit");
                    emit("worker_crashed", code);
                    break;
                }
                HANDLE waits[]{stop.get(), child.process.get()};
                WaitForMultipleObjects(2, waits, FALSE, static_cast<DWORD>(config.policy.poll_interval.count()));
            }
            // Close the old job/control before allocating fresh IPC; descendants
            // of a crashed worker cannot remain alive through the restart delay.
            child.job.reset(); child.control.reset(); child.process.reset();
            if (stopping(stop.get(), interrupted)) { SetEvent(stop.get()); emit("supervisor_stopped", 0); return 0; }
            const auto now = Clock::now();
            while (!restarts.empty() && now - restarts.front() >= config.policy.crash_window) restarts.pop_front();
            if (restarts.size() >= config.policy.maximum_restarts || attempt == std::numeric_limits<std::uint64_t>::max()) {
                emit("supervisor_retry_exhausted", static_cast<long long>(restarts.size()));
                if (stopping(stop.get(), interrupted)) { SetEvent(stop.get()); emit("supervisor_stopped", 0); return 0; }
                return supervisor_crash_limit;
            }
            emit("worker_restart_scheduled", delay.count());
            const auto deadline = Clock::now() + delay;
            while (Clock::now() < deadline && !stopping(stop.get(), interrupted))
                WaitForSingleObject(stop.get(), static_cast<DWORD>(std::min(config.policy.poll_interval,
                    std::max(Milliseconds(1), std::chrono::duration_cast<Milliseconds>(deadline - Clock::now()))).count()));
            if (stopping(stop.get(), interrupted)) { SetEvent(stop.get()); emit("supervisor_stopped", 0); return 0; }
            restarts.push_back(Clock::now());
            ++attempt;
            delay = std::min(delay * 2, config.policy.backoff_cap);
        }
    } catch (...) {
        if (stopping(stop.get(), interrupted)) { if (stop) SetEvent(stop.get()); emit("supervisor_stopped", 0); return 0; }
        emit("supervisor_error", 0);
        return supervisor_error;
    }
}

} // namespace scau
