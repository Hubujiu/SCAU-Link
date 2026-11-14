#pragma once
#include "connection_setup.hpp"

namespace scau::desktop {
struct WirelessNetwork {
    Mac mac{};
    unsigned index{};
    std::wstring name;
    std::string ipv4;
    bool found = false, link_up = false, ready = false;
};
WirelessNetwork choose_wireless_network(std::span<const ConnectionAdapter> adapters, const Mac& preferred = {});
WirelessNetwork current_wireless_network(const Mac& preferred = {});
bool valid_wireless_origin(std::string_view origin);
std::string load_wireless_origin(const std::filesystem::path& directory, const WirelessNetwork& network);
void save_wireless_origin(const std::filesystem::path& directory, const WirelessNetwork& network,
                          std::string_view origin);
} // namespace scau::desktop
