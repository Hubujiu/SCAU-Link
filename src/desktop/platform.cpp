#include "platform.hpp"
#include "profile_store.hpp"
#include "protocol.hpp"
#include "connection_setup.hpp"
#include "package_query.hpp"
#include "startup.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <stdexcept>
#include <tlhelp32.h>
#include <wincred.h>

namespace scau::desktop {
namespace {
constexpr wchar_t run_key[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
struct RegKey {
    HKEY value{};
    ~RegKey() {
        if (value)
            RegCloseKey(value);
    }
};
bool bit(const std::filesystem::path &file, const wchar_t *key) {
    return GetPrivateProfileIntW(L"Desktop", key, 0, file.c_str()) != 0;
}
void set_bit(const std::filesystem::path &file, const wchar_t *key, bool value) {
    if (!WritePrivateProfileStringW(L"Desktop", key, value ? L"1" : L"0", file.c_str()))
        throw std::runtime_error("Cannot save preferences");
}
} // namespace
void Credential::clear() noexcept {
    if (!username.empty())
        SecureZeroMemory(username.data(), username.size() * sizeof(wchar_t));
    if (!password.empty())
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    username.clear();
    password.clear();
}
bool CredentialStore::read(Credential &value) const {
    value.clear();
    PCREDENTIALW raw = nullptr;
    if (!CredReadW(target_.c_str(), CRED_TYPE_GENERIC, 0, &raw)) {
        if (GetLastError() == ERROR_NOT_FOUND)
            return false;
        throw std::runtime_error("Cannot read Windows credential manager");
    }
    struct Free {
        PCREDENTIALW p;
        ~Free() {
            if (p) {
                if (p->CredentialBlob)
                    SecureZeroMemory(p->CredentialBlob, p->CredentialBlobSize);
                CredFree(p);
            }
        }
    } free{raw};
    if (!raw->UserName || !raw->CredentialBlob || raw->CredentialBlobSize % sizeof(wchar_t) ||
        raw->CredentialBlobSize > 512)
        throw std::runtime_error("Invalid saved credential");
    value.username = raw->UserName;
    value.password.assign(reinterpret_cast<wchar_t *>(raw->CredentialBlob),
                          raw->CredentialBlobSize / sizeof(wchar_t));
    if (value.username.empty() || value.password.empty())
        throw std::runtime_error("Invalid saved credential");
    return true;
}
void CredentialStore::write(const Credential &value) const {
    if (value.username.empty() || value.password.empty() || value.password.size() > 256 ||
        value.username.size() > 256 || value.password.find(L'\0') != std::wstring::npos ||
        value.username.find(L'\0') != std::wstring::npos)
        throw std::runtime_error("Invalid credential length");
    CREDENTIALW record{};
    record.Type = CRED_TYPE_GENERIC;
    record.TargetName = const_cast<wchar_t *>(target_.c_str());
    record.UserName = const_cast<wchar_t *>(value.username.c_str());
    record.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<wchar_t *>(value.password.data()));
    record.CredentialBlobSize = static_cast<DWORD>(value.password.size() * sizeof(wchar_t));
    record.Persist = CRED_PERSIST_LOCAL_MACHINE;
    if (!CredWriteW(&record, 0))
        throw std::runtime_error("Cannot save Windows credential");
}
void CredentialStore::erase() const {
    if (!CredDeleteW(target_.c_str(), CRED_TYPE_GENERIC, 0) && GetLastError() != ERROR_NOT_FOUND)
        throw std::runtime_error("Cannot remove saved credential");
}
std::filesystem::path executable_path() {
    std::array<wchar_t, 32768> text{};
    auto size = GetModuleFileNameW(nullptr, text.data(), DWORD(text.size()));
    if (!size || size >= text.size())
        throw std::runtime_error("Cannot locate application");
    return text.data();
}
std::filesystem::path data_directory() {
    PWSTR value{};
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &value)))
        throw std::runtime_error("Cannot locate application data");
    std::filesystem::path path = std::filesystem::path(value) / L"ScauLink";
    CoTaskMemFree(value);
    std::filesystem::create_directories(path);
    return path;
}
std::wstring quote_argument(std::wstring_view value) {
    std::wstring out = L"\"";
    std::size_t slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        out.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        slashes = 0;
        out += c;
    }
    out.append(slashes * 2, L'\\');
    out += L'"';
    return out;
}
std::wstring startup_command(const std::filesystem::path &path) {
    return quote_argument(std::filesystem::absolute(path).wstring()) + L" --startup";
}
bool auto_start_enabled() {
    try { if (startup_task_enabled(startup_task_name())) return true; } catch (const std::exception&) {}
    RegKey key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, run_key, 0, KEY_QUERY_VALUE, &key.value) != ERROR_SUCCESS)
        return false;
    DWORD type = 0, size = 0;
    return RegQueryValueExW(key.value, L"SCAULink", nullptr, &type, nullptr, &size) == ERROR_SUCCESS &&
           type == REG_SZ && size > sizeof(wchar_t);
}
void set_auto_start(bool enabled, const std::filesystem::path &executable) {
    // Keep the legacy Run entry if task registration fails.
    configure_startup_task(enabled, executable, startup_task_name());
    RegKey key;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, run_key, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key.value,
                        nullptr) != ERROR_SUCCESS)
        throw std::runtime_error("Cannot update Windows startup");
    {
        auto result = RegDeleteValueW(key.value, L"SCAULink");
        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND)
            throw std::runtime_error("Cannot disable Windows startup");
    }
}
std::vector<ConnectionMode> parse_startup_modes(std::wstring_view text) {
    std::vector<ConnectionMode> modes;
    if (text.empty() || text == L"last") return modes;
    while (!text.empty()) {
        if (text.front() < L'0' || text.front() > L'2') return {};
        const auto mode = ConnectionMode(text.front() - L'0');
        if (std::find(modes.begin(), modes.end(), mode) != modes.end()) return {};
        modes.push_back(mode);
        text.remove_prefix(1);
        if (text.empty()) break;
        if (text.front() != L',' || text.size() < 2 || modes.size() == 3) return {};
        text.remove_prefix(1);
    }
    return modes;
}
std::vector<ConnectionMode> startup_connection_modes(const Settings& settings) {
    return settings.startup_modes.empty() ? std::vector<ConnectionMode>{settings.mode} : settings.startup_modes;
}
Settings load_settings(const std::filesystem::path &directory) {
    const auto file = directory / L"settings.ini";
    Settings settings{bit(file, L"MiniMode"), auto_start_enabled(), bit(file, L"SilentStartup")};
    const auto mode = GetPrivateProfileIntW(L"Desktop", L"ConnectionMode", 0, file.c_str());
    settings.mode = mode == 2 ? ConnectionMode::Wireless8021x : mode == 1 ? ConnectionMode::WirelessWeb : ConnectionMode::Wired;
    wchar_t plan[32]{};
    GetPrivateProfileStringW(L"Desktop", L"StartupModes", L"last", plan, DWORD(std::size(plan)), file.c_str());
    settings.startup_modes = parse_startup_modes(plan);
    return settings;
}
void save_settings(const std::filesystem::path &directory, const Settings &s) {
    std::wstring plan;
    for (const auto mode : s.startup_modes) {
        if (mode != ConnectionMode::Wired && mode != ConnectionMode::WirelessWeb && mode != ConnectionMode::Wireless8021x)
            throw std::invalid_argument("Invalid startup connection mode");
        if (!plan.empty()) plan += L',';
        plan += wchar_t(L'0' + int(mode));
    }
    if (!plan.empty() && parse_startup_modes(plan).size() != s.startup_modes.size())
        throw std::invalid_argument("Duplicate startup connection mode");
    std::filesystem::create_directories(directory);
    const auto file = directory / L"settings.ini";
    set_bit(file, L"MiniMode", s.mini);
    set_bit(file, L"SilentStartup", s.silent);
    if (!WritePrivateProfileStringW(L"Desktop", L"StartupModes", plan.empty() ? L"last" : plan.c_str(), file.c_str()))
        throw std::runtime_error("Cannot save startup connection modes");
    if (!WritePrivateProfileStringW(L"Desktop", L"ConnectionMode",
            s.mode == ConnectionMode::Wireless8021x ? L"2" : s.mode == ConnectionMode::WirelessWeb ? L"1" : L"0", file.c_str()))
        throw std::runtime_error("Cannot save connection mode");
}
bool original_client_running() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return true;
    PROCESSENTRY32W entry{sizeof(entry)};
    bool found = false;
    if (Process32FirstW(snapshot, &entry))
        do {
            if (_wcsicmp(entry.szExeFile, L"8021x.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    return found;
}
std::wstring adapter_name(const std::filesystem::path &file) {
    const auto profile = load_profile(file);
    ULONG size = 16384;
    Bytes bytes(size);
    auto *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(bytes.data());
    auto status = GetAdaptersAddresses(AF_INET, 0, nullptr, adapters, &size);
    if (status == ERROR_BUFFER_OVERFLOW) {
        bytes.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(bytes.data());
        status = GetAdaptersAddresses(AF_INET, 0, nullptr, adapters, &size);
    }
    if (status != NO_ERROR)
        return L"以太网";
    for (auto *a = adapters; a; a = a->Next) {
        if (a->PhysicalAddressLength == 6 && a->IfType == IF_TYPE_ETHERNET_CSMACD &&
            std::equal(profile.local.begin(), profile.local.end(), a->PhysicalAddress))
            return a->FriendlyName ? a->FriendlyName : L"以太网";
    }
    return L"网卡未找到";
}
bool adapter_ready(const std::array<unsigned char, 6> &mac) {
    ULONG size = 16384;
    Bytes bytes(size);
    auto *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(bytes.data());
    auto status = GetAdaptersAddresses(
        AF_INET, GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr,
        adapters, &size);
    if (status == ERROR_BUFFER_OVERFLOW) {
        bytes.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(bytes.data());
        status = GetAdaptersAddresses(
            AF_INET, GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr,
            adapters, &size);
    }
    if (status != NO_ERROR)
        return false;
    for (auto *a = adapters; a; a = a->Next) {
        if (a->PhysicalAddressLength != 6 || a->IfType != IF_TYPE_ETHERNET_CSMACD ||
            a->OperStatus != IfOperStatusUp || !std::equal(mac.begin(), mac.end(), a->PhysicalAddress))
            continue;
        MIB_IF_ROW2 row{};
        row.InterfaceLuid = a->Luid;
        if (GetIfEntry2(&row) != NO_ERROR || !row.InterfaceAndOperStatusFlags.HardwareInterface)
            return false;
        return true; // EAPOL authentication precedes IPv4/DHCP readiness.
    }
    return false;
}
std::filesystem::path locate_profile(const std::filesystem::path &directory,
                                     const std::filesystem::path &executable) {
    (void)executable;
    return prepare_connection(directory).path;
}
std::wstring utf8_to_wide(std::string_view value) {
    if (value.empty())
        return {};
    auto n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), int(value.size()), nullptr, 0);
    if (!n)
        return L"记录无法显示";
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), int(value.size()), out.data(), n);
    return out;
}
std::string to_gbk(std::wstring_view value) {
    BOOL replaced = false;
    auto size = WideCharToMultiByte(936, WC_NO_BEST_FIT_CHARS, value.data(), int(value.size()), nullptr, 0,
                                    nullptr, &replaced);
    if (size <= 0 || size > 256)
        throw std::runtime_error("Credential length is invalid");
    std::string out(size, '\0');
    WideCharToMultiByte(936, WC_NO_BEST_FIT_CHARS, value.data(), int(value.size()), out.data(), size, nullptr,
                        &replaced);
    if (replaced)
        throw std::runtime_error("Credential characters cannot be encoded");
    return out;
}
namespace {
std::string json_field(std::string_view line, std::string_view key) {
    const auto marker = std::string("\"") + std::string(key) + "\":\"";
    auto offset = line.find(marker);
    if (offset == std::string_view::npos)
        return {};
    offset += marker.size();
    const auto end = line.find('"', offset);
    if (end == std::string_view::npos || end - offset > 128)
        return {};
    return std::string(line.substr(offset, end - offset));
}
std::optional<unsigned> json_number(std::string_view line, std::string_view key) {
    const auto marker = std::string("\"") + std::string(key) + "\":";
    const auto offset = line.find(marker);
    if (offset == line.npos) return {};
    const auto begin = line.data() + offset + marker.size();
    unsigned value{};
    const auto parsed = std::from_chars(begin, line.data() + line.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr == line.data() + line.size() ||
        (*parsed.ptr != ',' && *parsed.ptr != '}')) return {};
    return value;
}
std::wstring event_title(std::string_view event, std::string_view detail, std::optional<unsigned> value) {
    if (event == "package_query_state" && value) {
        switch (PackageState(*value)) {
        case PackageState::Ready: return L"套餐查询完成";
        case PackageState::Partial: return L"套餐查询：部分信息未提供";
        case PackageState::Loading: return L"套餐查询中";
        case PackageState::CertificateError: return L"套餐查询：证书校验失败";
        case PackageState::NetworkError: return L"套餐查询：网络异常";
        case PackageState::AuthError: return L"套餐查询：登录未通过";
        case PackageState::Unsupported: return L"套餐查询：数据不可用";
        case PackageState::TlsError: return L"套餐查询：TLS 连接失败";
        default: return {};
        }
    }
    if (event == "package_query_summary" && value) {
        switch (PackageSummaryResult(*value)) {
        case PackageSummaryResult::Empty: return L"套餐摘要：学校返回空内容";
        case PackageSummaryResult::DecodeError: return L"套餐摘要：内容编码无法解码";
        case PackageSummaryResult::Html: return L"套餐摘要：学校返回网页，未取得账号数据";
        case PackageSummaryResult::InvalidJson: return L"套餐摘要：返回格式无法解析";
        case PackageSummaryResult::MissingEnvelope: return L"套餐摘要：缺少账号摘要";
        case PackageSummaryResult::InvalidEnvelope: return L"套餐摘要：账号摘要格式不兼容";
        case PackageSummaryResult::MissingItems: return L"套餐摘要：缺少信息列表";
        case PackageSummaryResult::InvalidItems: return L"套餐摘要：信息列表格式不兼容";
        case PackageSummaryResult::EmptyItems: return L"套餐摘要：信息列表为空";
        case PackageSummaryResult::TooManyItems: return L"套餐摘要：信息列表超出限制";
        case PackageSummaryResult::UnrecognizedItems: return L"套餐摘要：未识别到余额等字段";
        case PackageSummaryResult::TooLarge: return L"套餐摘要：返回内容超出限制";
        case PackageSummaryResult::InvalidHttp: return L"套餐摘要：HTTP 响应不完整或格式异常";
        default: return {};
        }
    }
    static constexpr std::pair<std::string_view, const wchar_t *> names[]{
        {"worker_authenticated", L"连接成功"},
        {"worker_network_available", L"网络已连通，账号未确认"},
        {"worker_unauthenticated", L"正在重新连接"},
        {"worker_crashed", L"认证核心异常退出"},
        {"worker_restart_scheduled", L"正在自动恢复"},
        {"supervisor_stopped", L"已断开连接"},
        {"supervisor_retry_exhausted", L"自动恢复已停止"},
        {"supervisor_error", L"认证核心启动失败"},
        {"supervisor_protocol_error", L"认证核心通信失败"},
        {"desktop_authentication_error", L"登录失败"},
        {"original_client_conflict", L"锐捷客户端正在运行"},
        {"credentials_saved", L"登录凭据已保存"},
        {"account_attempt", L"开始登录"},
        {"account_retry", L"正在重试账号"},
        {"account_next", L"正在切换下一个账号"},
        {"accounts_exhausted", L"所有账号登录失败"},
        {"account_pinned", L"账号已置顶"},
        {"account_order_changed", L"账号排序已保存"},
        {"account_removed", L"账号已删除"},
        {"preferences_saved", L"设置已保存"},
        {"connection_ready", L"连接参数已准备"},
        {"connection_setup_failed", L"连接参数准备失败"},
        {"wireless_portal_approved", L"无线认证页面已确认"},
        {"wireless_preflight_ok", L"无线连接已准备"},
        {"wlan_8021x_connect_requested", L"正在连接 SCAUNET_1x"},
        {"wlan_8021x_authenticated", L"无线 802.1X 认证完成"},
        {"password_changed", L"校园网密码已修改"},
        {"password_change_unknown", L"修改密码结果未确认"},
        {"password_change_rejected", L"修改密码未完成"},
        {"campus_paused", L"校园网已暂停"},
        {"campus_resumed", L"校园网已恢复"},
        {"campus_change_unknown", L"校园网操作结果未确认"},
        {"campus_change_not_applied", L"校园网操作未完成"},
        {"waiting_for_network", L"等待有线网络"},
        {"internet_probe_ok", L"互联网检查通过"},
        {"internet_probe_failed", L"互联网检查未通过"},
        {"server_failure_with_reason", L"校园网拒绝认证"},
        {"server_failure_unrecognized", L"认证未通过"},
        {"server_failure_empty_reason", L"正在重试认证"},
        {"sam_server_terminated", L"校园网已下线"},
        {"transport_lost", L"网卡连接中断"},
        {"package_query_credential_unavailable", L"套餐查询：无法读取本机保存的凭据"},
        {"package_query_restarted_after_connection", L"连接已恢复，重新查询套餐"},
        {"startup_registration_failed", L"登录自启配置失败，保留原启动方式"},
        {"capture_driver_unavailable", L"有线抓包驱动未就绪，请检查服务和权限"},
        {"capture_adapter_open_failed", L"无法打开有线网卡，请检查抓包驱动和权限"},
        {"error", L"认证环境异常"}};
    for (const auto &[key, title] : names)
        if (event == key)
            return title;
    if (event == "connection_state") {
        if (detail == "waiting-for-link")
            return L"等待网线接入";
        if (detail == "suspended")
            return L"系统已休眠";
        if (detail == "resume-delay")
            return L"正在恢复网络";
        if (detail == "rejected")
            return L"认证已停止";
    }
    return {};
}
LogLevel event_level(std::string_view event, std::string_view detail, std::optional<unsigned> value) {
    if (event == "package_query_summary") return LogLevel::Warning;
    if (event == "package_query_credential_unavailable") return LogLevel::Error;
    if (event == "package_query_state" && value) {
        if (*value == unsigned(PackageState::Ready)) return LogLevel::Success;
        if (*value == unsigned(PackageState::Partial)) return LogLevel::Warning;
        if (*value == unsigned(PackageState::Idle) || *value == unsigned(PackageState::Loading)) return LogLevel::Info;
        return LogLevel::Error;
    }
    if (event == "worker_authenticated" || event == "worker_network_available" || event == "internet_probe_ok" ||
        event == "campus_paused" || event == "campus_resumed" || event == "password_changed")
        return LogLevel::Success;
    if (event == "worker_crashed" || event == "supervisor_retry_exhausted" || event == "supervisor_error" ||
        event == "supervisor_protocol_error" || event == "desktop_authentication_error" ||
        event == "original_client_conflict" || event == "accounts_exhausted" ||
        event == "connection_setup_failed" || event == "capture_driver_unavailable" ||
        event == "capture_adapter_open_failed" || event == "startup_registration_failed" || event == "server_failure_with_reason" ||
        event == "server_failure_unrecognized" || event == "password_change_rejected" || event == "error" ||
        (event == "connection_state" && detail == "rejected"))
        return LogLevel::Error;
    if (event == "worker_unauthenticated" || event == "worker_restart_scheduled" ||
        event == "account_retry" || event == "account_next" || event == "waiting_for_network" ||
        event == "internet_probe_failed" || event == "server_failure_empty_reason" ||
        event == "sam_server_terminated" || event == "transport_lost" ||
        event == "campus_change_unknown" || event == "campus_change_not_applied" || event == "password_change_unknown" ||
        (event == "connection_state" && detail == "waiting-for-link"))
        return LogLevel::Warning;
    return LogLevel::Info;
}
} // namespace
LogResult read_log_records(const std::filesystem::path &directory, const LogQuery &query, std::size_t limit) {
    LogSelection selection(query, limit);
    if (!std::filesystem::is_directory(directory))
        return selection.finish();
    std::vector<std::filesystem::path> paths;
    for (auto &entry : std::filesystem::directory_iterator(directory))
        if (entry.is_regular_file() && entry.path().extension() == L".jsonl" &&
            entry.path().filename().wstring().starts_with(L"session-"))
            paths.push_back(entry.path());
    std::sort(paths.rbegin(), paths.rend());
    if (std::filesystem::is_regular_file(directory / L"desktop.jsonl"))
        paths.push_back(directory / L"desktop.jsonl");
    for (const auto &path : paths) {
        std::ifstream in(path, std::ios::binary);
        if (!in)
            continue;
        std::string line;
        while (std::getline(in, line)) {
            if (line.size() > 2048)
                continue;
            const auto event = json_field(line, "event"), detail = json_field(line, "detail");
            const auto value = json_number(line, "value");
            const auto title = event_title(event, detail, value);
            if (title.empty())
                continue;
            const auto time = parse_log_time(json_field(line, "time"));
            if (time)
                selection.consider({time, event_level(event, detail, value), title, {}, event});
        }
    }
    return selection.finish();
}
std::vector<std::wstring> read_recent_logs(const std::filesystem::path &directory) {
    std::vector<std::wstring> lines;
    for (const auto &row : read_log_records(directory, {}, 200).entries)
        lines.push_back(row.time_label + L"  " + row.title);
    return lines;
}
} // namespace scau::desktop
