#include <winsock2.h>
#include "desktop/platform.hpp"
#include "desktop/wireless_connection.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <source_location>
#include <stdexcept>
#include <vector>

using namespace scau;
using namespace scau::desktop;

namespace {
unsigned checks{};
void require(bool value, const char* why,
             const std::source_location where = std::source_location::current()) {
    ++checks;
    if (!value) throw std::runtime_error(std::string(why) + " at line " + std::to_string(where.line()));
}
template<class Action> void rejected(Action action, const char* why) {
    bool threw = false;
    try { action(); } catch (const std::runtime_error&) { threw = true; }
    require(threw, why);
}
struct Fixture {
    std::filesystem::path root;
    std::vector<std::filesystem::path> directories;
    Fixture() {
        std::array<wchar_t, 32768> temporary{};
        const auto length = GetTempPathW(DWORD(temporary.size()), temporary.data());
        require(length && length < temporary.size(), "The temporary directory must be available");
        root = std::filesystem::path(temporary.data()) / (L"scau-wireless-test-" +
            std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
        require(std::filesystem::create_directory(root), "The test root must be fresh and isolated");
        directories.push_back(root);
    }
    std::filesystem::path directory(const std::wstring& name) {
        const auto result = root / name;
        require(std::filesystem::create_directory(result), "Each fixture directory must be fresh");
        directories.push_back(result);
        return result;
    }
    ~Fixture() {
        // Delete only known fixture files and empty fixture directories, never a recursive tree.
        std::error_code error;
        for (auto directory = directories.rbegin(); directory != directories.rend(); ++directory) {
            for (const auto* name : {L"settings.ini", L"wireless.ini"})
                std::filesystem::remove(*directory / name, error);
            std::filesystem::remove(*directory, error);
        }
    }
};
ConnectionAdapter wifi(Byte suffix = 1) {
    ConnectionAdapter adapter;
    adapter.mac = {2, 0, 0, 0, 0, suffix};
    adapter.id = "synthetic-wlan-" + std::to_string(suffix);
    adapter.name = L"Synthetic physical WLAN";
    adapter.index = suffix;
    adapter.metric = 20;
    adapter.physical = adapter.wireless = adapter.link_up = adapter.ipv4 = true;
    adapter.address = {10, 20, 30, suffix};
    return adapter;
}
WirelessNetwork selected(const ConnectionAdapter& adapter) {
    const std::array adapters{adapter};
    return choose_wireless_network(adapters);
}
Bytes read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(bool(input), "A saved fixture file must be readable");
    return Bytes(std::istreambuf_iterator<char>(input), {});
}
void write_file(const std::filesystem::path& path, std::string_view content) {
    std::ofstream output(path, std::ios::binary);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    require(bool(output), "The fixture file must be written completely");
}

void selection_filters() {
    const auto empty = choose_wireless_network({});
    require(!empty.found && !empty.link_up && !empty.ready && empty.ipv4.empty() &&
            empty.index == 0 && empty.mac == Mac{}, "An empty inventory has no usable wireless adapter");

    std::vector<ConnectionAdapter> excluded;
    auto candidate = wifi(2);
    candidate.wireless = false; candidate.ethernet = true;
    excluded.push_back(candidate); // Physical Ethernet, even when it has working IPv4.
    candidate = wifi(3); candidate.physical = candidate.wireless = false;
    candidate.name = L"VPN with a gateway"; candidate.gateway = true;
    excluded.push_back(candidate);
    candidate = wifi(4); candidate.physical = false;
    candidate.name = L"Virtual wireless adapter";
    excluded.push_back(candidate);
    candidate = wifi(5); candidate.ethernet = true;
    excluded.push_back(candidate); // Contradictory interface flags fail closed.
    candidate = wifi(6); candidate.mac = {};
    excluded.push_back(candidate);
    candidate = wifi(7); candidate.mac[0] = 1;
    excluded.push_back(candidate);
    candidate = wifi(8); candidate.mac.fill(255);
    excluded.push_back(candidate);
    candidate = wifi(9); candidate.index = 0;
    excluded.push_back(candidate);
    candidate = wifi(10); candidate.id.clear();
    excluded.push_back(candidate);
    candidate = wifi(11); candidate.wireless = false;
    excluded.push_back(candidate);
    for (const auto& invalid : excluded)
        require(!selected(invalid).found, "Only identified physical wireless interfaces may be selected");
    const auto physical = wifi(12);
    excluded.push_back(physical);
    const auto result = choose_wireless_network(excluded);
    require(result.found && result.ready && result.mac == physical.mac && result.index == physical.index,
            "Ethernet, VPN and virtual adapters cannot displace a physical WLAN adapter");
    require(result.name == physical.name && result.ipv4 == "10.20.30.12",
            "The selected snapshot keeps the adapter identity and live IPv4 address");
}

void selection_ranking() {
    auto active = wifi(20); active.metric = 200;
    auto disconnected = wifi(21); disconnected.link_up = false; disconnected.metric = 1;
    std::vector<ConnectionAdapter> adapters{disconnected, active};
    auto result = choose_wireless_network(adapters, disconnected.mac);
    require(result.mac == active.mac && result.ready,
            "An active WLAN adapter wins over a remembered disconnected adapter");
    auto no_address = wifi(22); no_address.ipv4 = false;
    adapters = {disconnected, no_address};
    result = choose_wireless_network(adapters, disconnected.mac);
    require(result.mac == no_address.mac && result.link_up && !result.ready && result.ipv4.empty(),
            "Link status takes priority over a stale IPv4 address on a disconnected interface");
    auto apipa = wifi(23); apipa.address = {169, 254, 1, 2}; apipa.metric = 1;
    adapters = {apipa, active};
    require(choose_wireless_network(adapters, apipa.mac).mac == active.mac,
            "Usable IPv4 takes priority over a remembered link-local adapter");
    for (const auto address : std::array<std::array<Byte, 4>, 5>{{
            {0, 0, 0, 0}, {127, 0, 0, 1}, {169, 254, 10, 20}, {224, 0, 0, 1}, {255, 255, 255, 255}}}) {
        auto unusable = wifi(24); unusable.address = address;
        const auto snapshot = selected(unusable);
        require(snapshot.found && snapshot.link_up && !snapshot.ready && snapshot.ipv4.empty(),
                "Unspecified, loopback, APIPA and multicast IPv4 do not make WLAN ready");
    }
    auto remembered = wifi(25); remembered.metric = 500;
    auto lower_metric = wifi(26); lower_metric.metric = 1;
    adapters = {lower_metric, remembered};
    require(choose_wireless_network(adapters, remembered.mac).mac == remembered.mac,
            "The remembered MAC wins among equally ready physical WLAN adapters");
    for (unsigned order = 0; order < 2; ++order) {
        require(choose_wireless_network(adapters).mac == lower_metric.mac,
                "Metric ordering is independent of adapter enumeration order");
        std::reverse(adapters.begin(), adapters.end());
    }
    remembered.metric = lower_metric.metric;
    remembered.index = 5; lower_metric.index = 8;
    adapters = {lower_metric, remembered};
    for (unsigned order = 0; order < 2; ++order) {
        require(choose_wireless_network(adapters).mac == remembered.mac,
                "Equal metrics use a stable interface-index order");
        std::reverse(adapters.begin(), adapters.end());
    }
    remembered.index = lower_metric.index;
    remembered.id = "adapter-a"; lower_metric.id = "adapter-b";
    adapters = {lower_metric, remembered};
    require(choose_wireless_network(adapters).mac == remembered.mac,
            "The adapter identifier resolves an otherwise equal rank consistently");
    std::reverse(adapters.begin(), adapters.end());
    require(choose_wireless_network(adapters).mac == remembered.mac,
            "The final rank tie-breaker is independent of enumeration order");
}

void origin_validation() {
    for (const auto* origin : {"http://portal.example", "https://portal.example", "http://portal.example:8080",
            "https://portal.example:8443", "http://192.0.2.40", "https://192.0.2.40:9443"})
        require(valid_wireless_origin(origin), "Canonical HTTP and HTTPS origins are accepted without a request");
    for (const auto* origin : {"", "portal.example", "ftp://portal.example", "file:///portal.example",
            "javascript:portal.example", "HTTP://portal.example", "https://PORTAL.example",
            "http://portal.example:80", "https://portal.example:443", "http://portal.example:08080",
            "http://portal.example/", "http://portal.example/eportal/index.jsp", "http://portal.example?x=1",
            "http://portal.example#fragment", "http://fixture-user:fixture-password@portal.example",
            "http://portal.example@attacker.example", "http://portal.example\r\nInjected: yes",
            "http://portal.example\n", " http://portal.example", "http://portal.example ",
            "http://portal.example\\path", "http://portal.example:0", "http://portal.example:65536",
            "http://[::1]", "http://", "https://.portal.example", "https://portal..example"})
        require(!valid_wireless_origin(origin), "Only an exact canonical origin can be approved");
    constexpr char embedded_nul[] = "http://portal.example\0.attacker.example";
    require(!valid_wireless_origin(std::string(embedded_nul, sizeof(embedded_nul) - 1)),
            "An embedded NUL cannot truncate an approved origin");
    require(!valid_wireless_origin("https://" + std::string(505, 'a')),
            "An oversized approval is rejected before persistence");
}

void origin_cache(Fixture& fixture) {
    const auto directory = fixture.directory(L"origin-cache");
    const auto first = selected(wifi(70));
    const auto second = selected(wifi(71));
    require(first.ready && second.ready, "Cache tests require synthetic ready physical snapshots");
    require(load_wireless_origin(directory, first).empty() && std::filesystem::is_empty(directory),
            "A fresh installation does not trust a portal or create a cache automatically");
    auto down = wifi(72); down.link_up = false;
    auto virtual_adapter = wifi(73); virtual_adapter.physical = false;
    auto local_only = wifi(74); local_only.address = {169, 254, 1, 9};
    auto invalid_mac = first; invalid_mac.mac = {};
    for (const auto& invalid : std::array{WirelessNetwork{}, selected(down), selected(virtual_adapter),
                                        selected(local_only), invalid_mac}) {
        rejected([&] { save_wireless_origin(directory, invalid, "https://portal.example"); },
                 "An absent, virtual, disconnected, APIPA or invalid-MAC snapshot cannot approve a portal");
        require(!std::filesystem::exists(directory / L"wireless.ini"),
                "Rejected approvals leave an empty installation unchanged");
    }
    save_wireless_origin(directory, first, "https://portal.example:8443");
    require(load_wireless_origin(directory, first) == "https://portal.example:8443" &&
            load_wireless_origin(directory, second).empty(), "Portal approval is scoped to the selected MAC");
    auto renamed = first; renamed.name = L"Renamed WLAN"; renamed.index = 999; renamed.ipv4 = "10.0.0.99";
    require(load_wireless_origin(directory, renamed) == "https://portal.example:8443",
            "A changed display name, interface index or DHCP address does not change the MAC scope");
    save_wireless_origin(directory, second, "http://other-portal.example:8080");
    require(load_wireless_origin(directory, first) == "https://portal.example:8443" &&
            load_wireless_origin(directory, second) == "http://other-portal.example:8080",
            "Saving a second MAC does not overwrite the first adapter approval");
    const auto before = read_file(directory / L"wireless.ini");
    for (const auto* invalid : {"http://fixture-user:fixture-password@portal.example",
            "http://portal.example?username=fixture-user&password=fixture-password",
            "https://portal.example/eportal/index.jsp?wlanuserip=10.20.30.70",
            "https://portal.example#fragment", "https://portal.example\r\nOrigin=attacker"}) {
        rejected([&] { save_wireless_origin(directory, first, invalid); },
                 "Credentials, discovery queries, paths and injected text are not cacheable origins");
        require(read_file(directory / L"wireless.ini") == before &&
                load_wireless_origin(directory, first) == "https://portal.example:8443",
                "An invalid approval cannot modify an existing cache");
    }
    std::array<wchar_t, 1024> section{};
    const auto file = directory / L"wireless.ini";
    auto size = GetPrivateProfileSectionW(L"Wireless-020000000046", section.data(), DWORD(section.size()), file.c_str());
    require(size && std::wstring(section.data()) == L"Origin=https://portal.example:8443" &&
            section[std::wstring(section.data()).size() + 1] == L'\0',
            "The first MAC section contains only the approved origin, without account or network-session data");
    section.fill(0);
    size = GetPrivateProfileSectionW(L"Wireless-020000000047", section.data(), DWORD(section.size()), file.c_str());
    require(size && std::wstring(section.data()) == L"Origin=http://other-portal.example:8080",
            "Different MAC addresses use different cache sections");
    std::string visible;
    for (const auto byte : before) if (byte) visible += static_cast<char>(byte);
    for (const auto* forbidden : {"fixture-user", "fixture-password", "username", "password", "wlanuserip", "10.20.30.70"})
        require(visible.find(forbidden) == visible.npos, "The approval cache does not retain credentials, query or live client IP");
    const auto poisoned = fixture.directory(L"invalid-origin-cache");
    write_file(poisoned / L"wireless.ini", "[Wireless-020000000046]\r\nOrigin=http://portal.example/eportal/?secret=fixture-password\r\n");
    require(load_wireless_origin(poisoned, first).empty(), "An invalid persisted value cannot become a trusted origin");
}

void settings_persistence(Fixture& fixture) {
    require(Settings{}.mode == ConnectionMode::Wired, "The settings object defaults to wired authentication");
    const auto empty = fixture.directory(L"settings-empty");
    const auto defaults = load_settings(empty);
    require(defaults.mode == ConnectionMode::Wired && !defaults.mini && !defaults.silent &&
            std::filesystem::is_empty(empty), "Missing settings use wired defaults without creating preferences");
    const auto legacy = fixture.directory(L"settings-legacy");
    write_file(legacy / L"settings.ini", "[Desktop]\r\nMiniMode=1\r\nSilentStartup=1\r\n");
    auto previous = load_settings(legacy);
    require(previous.mode == ConnectionMode::Wired && previous.mini && previous.silent,
            "A pre-mode settings file keeps mini/silent preferences and defaults to wired");
    previous.mode = ConnectionMode::WirelessWeb;
    save_settings(legacy, previous);
    previous = load_settings(legacy);
    require(previous.mode == ConnectionMode::WirelessWeb && previous.mini && previous.silent,
            "Changing the mode preserves existing mini and silent preferences");
    unsigned sequence{};
    for (const auto* invalid : {"", "garbage", "WirelessWeb", "-1", "3", "999"}) {
        const auto directory = fixture.directory(L"settings-invalid-" + std::to_wstring(++sequence));
        write_file(directory / L"settings.ini", std::string("[Desktop]\r\nMiniMode=1\r\nSilentStartup=0\r\nConnectionMode=") + invalid + "\r\n");
        const auto loaded = load_settings(directory);
        require(loaded.mode == ConnectionMode::Wired && loaded.mini && !loaded.silent,
                "An invalid stored mode falls back to wired without discarding other preferences");
    }
    const auto wrong_key = fixture.directory(L"settings-wrong-key");
    write_file(wrong_key / L"settings.ini", "[Desktop]\r\nMode=1\r\nMiniMode=0\r\nSilentStartup=1\r\n");
    const auto unknown = load_settings(wrong_key);
    require(unknown.mode == ConnectionMode::Wired && !unknown.mini && unknown.silent,
            "An unrelated preference key cannot enable wireless authentication");
    const auto roundtrip = fixture.directory(L"settings-roundtrip");
    for (const auto mode : {ConnectionMode::Wired, ConnectionMode::WirelessWeb, ConnectionMode::Wireless8021x})
        for (const bool mini : {false, true}) for (const bool silent : {false, true}) {
            Settings expected; expected.mode = mode; expected.mini = mini; expected.silent = silent;
            save_settings(roundtrip, expected);
            const auto loaded = load_settings(roundtrip);
            require(loaded.mode == mode && loaded.mini == mini && loaded.silent == silent,
                    "Both modes round-trip with every mini/silent combination");
        }
    // Only load_settings/save_settings are exercised: no startup registration or credential API is called.
}
} // namespace

int main() { try {
    selection_filters();
    selection_ranking();
    origin_validation();
    Fixture fixture;
    origin_cache(fixture);
    settings_persistence(fixture);
    std::cout << "wireless connection tests passed (" << checks << " checks)\n";
    return 0;
} catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; } }
