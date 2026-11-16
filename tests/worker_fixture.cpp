// Offline executable used only by supervisor-tests. It contains no auth or
// packet code, and deliberately exits/crashes only under fixture arguments.
#include "supervisor.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

namespace {
constexpr std::string_view fixture_user = "offline-fixture-user-4821";
constexpr std::string_view fixture_password = "synthetic-only-password-#7158";

void require(bool condition) { if (!condition) throw std::runtime_error("Offline worker fixture failed"); }

HANDLE parse_handle(const std::wstring& value) {
    std::size_t used = 0;
    const auto parsed = std::stoull(value, &used, 10);
    require(used == value.size() && parsed > 0 && parsed <= UINTPTR_MAX);
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(parsed));
}

struct Options {
    HANDLE input = nullptr, output = nullptr, forbidden = nullptr;
    std::wstring mode, stop, quoted;
    unsigned long long attempt = 0;
};

Options options(int argc, wchar_t** argv) {
    Options result;
    bool have_attempt = false;
    for (int i = 1; i < argc; ++i) {
        const std::wstring name = argv[i];
        require(i + 1 < argc);
        const std::wstring value = argv[++i];
        if (name == L"--worker-input") { require(!result.input); result.input = parse_handle(value); }
        else if (name == L"--worker-output") { require(!result.output); result.output = parse_handle(value); }
        else if (name == L"--forbidden-handle") result.forbidden = parse_handle(value);
        else if (name == L"--fixture-mode") result.mode = value;
        else if (name == L"--stop-event") { require(result.stop.empty()); result.stop = value; }
        else if (name == L"--quoted-argument") result.quoted = value;
        else if (name == L"--recovery-attempt") {
            require(!have_attempt); have_attempt = true;
            std::size_t used = 0; result.attempt = std::stoull(value, &used, 10); require(used == value.size());
        } else require(false);
    }
    require(result.input && result.output && have_attempt && !result.stop.empty() && !result.mode.empty());
    return result;
}

[[noreturn]] void crash(DWORD code) {
    TerminateProcess(GetCurrentProcess(), code);
    ExitProcess(code);
}

void bad_control(HANDLE output, bool partial, bool wrong_nonce) {
    std::array<unsigned char, 52 + scau::worker_failure_limit> bytes{};
    if (wrong_nonce) {
        // Valid protocol header and sequence, deliberately absent channel nonce.
        const std::uint32_t magic = 0x53434143, sequence = 2;
        const std::uint16_t version = 2, terminal = 3;
        std::memcpy(bytes.data(), &magic, 4);
        std::memcpy(bytes.data() + 4, &version, 2);
        std::memcpy(bytes.data() + 6, &terminal, 2);
        std::memcpy(bytes.data() + 8, &sequence, 4);
    }
    DWORD written = 0;
    require(WriteFile(output, bytes.data(), partial ? 2 : static_cast<DWORD>(bytes.size()), &written, nullptr) != FALSE);
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    try {
        const auto opt = options(argc, argv);
        // Pipe ends are deliberately one-way, and the handle allowlist excludes
        // an unrelated inheritable event owned by the test parent.
        DWORD transferred = 0;
        char byte = 0;
        require(!WriteFile(opt.input, &byte, 1, &transferred, nullptr) && GetLastError() == ERROR_ACCESS_DENIED);
        require(!ReadFile(opt.output, &byte, 1, &transferred, nullptr) && GetLastError() == ERROR_ACCESS_DENIED);
        if (opt.forbidden) require(!SetEvent(opt.forbidden));

        scau::WorkerChannel channel(opt.input, opt.output);
        scau::SessionCredentials credentials;
        require(channel.read_credentials(credentials));
        require(credentials.username == fixture_user && credentials.password == fixture_password);
        const std::wstring username(credentials.username.begin(), credentials.username.end());
        const std::wstring password(credentials.password.begin(), credentials.password.end());
        for (int i = 0; i < argc; ++i) {
            require(std::wstring_view(argv[i]).find(username) == std::wstring_view::npos);
            require(std::wstring_view(argv[i]).find(password) == std::wstring_view::npos);
        }
        DWORD flags = 0;
        require(GetHandleInformation(opt.output, &flags) && !(flags & HANDLE_FLAG_INHERIT));
        require(!channel.authenticated() && !channel.unauthenticated() && !channel.network_available());
        if (opt.mode == L"preflight-terminal") { credentials.clear(); require(channel.finish(13)); return 0; }
        if (opt.mode == L"capture-open-failed") {
            credentials.clear(); require(channel.finish(4,"无法打开有线网卡：请检查抓包驱动和访问权限。")); return 0;
        }
        require(channel.ready() && !channel.ready());
        credentials.clear();

        if (opt.mode == L"bad-ipc" || opt.mode == L"partial-ipc" || opt.mode == L"wrong-nonce") {
            bad_control(opt.output, opt.mode == L"partial-ipc", opt.mode == L"wrong-nonce");
            return 0;
        }
        if (opt.mode == L"reject") { require(channel.finish(7)); require(!channel.finish(0)); return 0; }
        if (opt.mode == L"reject-reason") {
            require(!channel.finish(1, std::string(scau::worker_failure_limit + 1, 'x')));
            require(!channel.finish(1, std::string_view("bad\0reason", 10)));
            require(!channel.finish(1, "\xff"));
            require(channel.finish(1, "已达到同时在线用户数量上限"));
            require(!channel.finish(1, "stale"));
            return 0;
        }
        if (opt.mode == L"reject-unknown") { require(channel.finish(1, "unknown")); return 0; }
        if (opt.mode == L"terminal-crash") { require(channel.finish(0)); crash(0xc0000005); }
        if (opt.mode == L"early-terminal") { require(channel.finish(19)); Sleep(INFINITE); }
        if (opt.mode == L"crash-loop") crash(0xc0000005);
        if (opt.mode == L"exit-zero" && opt.attempt == 0) crash(0);
        if (opt.mode == L"crash-once" && opt.attempt == 0) crash(0xc0000005);
        if (opt.mode == L"two-crashes" && opt.attempt < 2) crash(3);
        if ((opt.mode == L"healthy-reset" || opt.mode == L"lost-health") && opt.attempt == 0) crash(3);
        if(opt.mode==L"network-only") {
            require(channel.network_available());require(channel.finish(0));return 0;
        }
        require(channel.authenticated());
        if ((opt.mode == L"healthy-reset" || opt.mode == L"lost-health") && opt.attempt == 1) {
            if (opt.mode == L"lost-health") require(channel.unauthenticated());
            Sleep(100);
            crash(3);
        }
        if (opt.mode == L"wait-stop") {
            HANDLE stop = OpenEventW(SYNCHRONIZE, FALSE, opt.stop.c_str());
            require(stop != nullptr);
            const auto status = WaitForSingleObject(stop, 10000);
            CloseHandle(stop);
            require(status == WAIT_OBJECT_0);
            require(channel.finish(0));
            return 0;
        }
        if (opt.mode == L"ignore-stop") Sleep(INFINITE);
        if (opt.mode == L"quoting") require(opt.quoted == L"space \\\"quote\\\\ trailing\\");
        require(channel.finish(0));
        // A valid Terminal result remains authoritative over this different exit.
        return 23;
    } catch (...) {
        // No credentials, argv or exceptions are printed by this fixture.
        return 91;
    }
}
