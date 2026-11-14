#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "wireless_connection.hpp"
#include "portal_auth.hpp"
#include <algorithm>
#include <tuple>
#include <stdexcept>

namespace scau::desktop {
namespace {
bool usable_ipv4(const ConnectionAdapter& adapter) {
    const auto& ip = adapter.address;
    return adapter.ipv4 && ip[0] != 0 && ip[0] != 127 && ip[0] < 224 &&
           !(ip[0] == 169 && ip[1] == 254);
}
std::wstring section(const Mac& mac) {
    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring result = L"Wireless-";
    for (auto byte : mac) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
} // namespace
WirelessNetwork choose_wireless_network(std::span<const ConnectionAdapter> adapters, const Mac& preferred) {
    const auto rank = [&](const ConnectionAdapter& a) {
        return std::tuple{!a.link_up, !usable_ipv4(a), a.mac != preferred, a.metric, a.index, a.id};
    };
    const ConnectionAdapter* chosen = nullptr;
    for (const auto& a : adapters) {
        if (!a.physical || !a.wireless || a.ethernet || !unicast_mac(a.mac) || !a.index || a.id.empty()) continue;
        if (!chosen || rank(a) < rank(*chosen)) chosen = &a;
    }
    WirelessNetwork result;
    if (!chosen) return result;
    result.found = true; result.mac = chosen->mac; result.index = chosen->index; result.name = chosen->name;
    result.link_up = chosen->link_up; result.ready = chosen->link_up && usable_ipv4(*chosen);
    if (usable_ipv4(*chosen)) {
        char address[INET_ADDRSTRLEN]{};
        if (InetNtopA(AF_INET, chosen->address.data(), address, sizeof(address))) result.ipv4 = address;
        else result.ready = false;
    }
    return result;
}
WirelessNetwork current_wireless_network(const Mac& preferred) {
    const auto adapters = connection_adapters();
    return choose_wireless_network(adapters, preferred);
}
bool valid_wireless_origin(std::string_view origin) {
    if (origin.empty() || origin.size() > 512) return false;
    portal::Options options; options.interface_index = 1; options.trusted_origins = {std::string(origin)};
    const auto target = portal::target_from_url(std::string(origin) + "/eportal/index.jsp?localCheck=1",
                                               "192.0.2.1", options);
    return target && target->origin == origin && target->query_string == "localCheck=1";
}
std::string load_wireless_origin(const std::filesystem::path& directory, const WirelessNetwork& network) {
    if (!network.found || !unicast_mac(network.mac)) return {};
    wchar_t value[514]{};
    const auto size = GetPrivateProfileStringW(section(network.mac).c_str(), L"Origin", L"", value,
                                              DWORD(std::size(value)), (directory / L"wireless.ini").c_str());
    if (!size || size >= std::size(value)-1) return {};
    std::string origin; origin.reserve(size);
    for (unsigned i = 0; i < size; ++i) { if (value[i] > 127) return {}; origin += char(value[i]); }
    return valid_wireless_origin(origin) ? origin : std::string{};
}
void save_wireless_origin(const std::filesystem::path& directory, const WirelessNetwork& network,
                          std::string_view origin) {
    if (!network.found || !network.ready || !unicast_mac(network.mac) || !valid_wireless_origin(origin))
        throw std::runtime_error("Invalid wireless portal approval");
    std::filesystem::create_directories(directory);
    const std::wstring value(origin.begin(), origin.end());
    if (!WritePrivateProfileStringW(section(network.mac).c_str(), L"Origin", value.c_str(),
                                     (directory / L"wireless.ini").c_str()))
        throw std::runtime_error("Cannot save the selected wireless portal");
}
} // namespace scau::desktop
