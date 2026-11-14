#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <winioctl.h>
#include "connection_setup.hpp"
#include "profile_store.hpp"
#include <algorithm>
#include <cstring>
#include <tuple>
#include <stdexcept>

namespace scau::desktop {
namespace {
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
std::optional<Profile> cached_profile(const std::filesystem::path& path) {
    try {
        if (!std::filesystem::is_regular_file(path) || std::filesystem::file_size(path) != 141) return {};
        return load_profile(path);
    } catch (const std::exception&) { return {}; }
}
void normalize(Profile& profile, const ConnectionAdapter& adapter) {
    profile.local = adapter.mac;
    // Discovery starts at the standard PAE multicast. Pin the authenticator
    // from the live Identity exchange, never from a stale capture or cache.
    profile.server = {}; profile.username.clear();
    profile.network = {0, 0, 0x13, 0x11, Byte(adapter.dhcp ? 1 : 0)};
    const auto crc = crc16(std::span(profile.network).first(21));
    profile.network[21] = Byte(crc >> 8); profile.network[22] = Byte(crc);
}
bool same_parameters(const Profile& left, const Profile& right) {
    return left.local == right.local && left.server == right.server && left.network == right.network &&
           left.service == right.service && left.device_id == right.device_id && left.username.empty();
}
} // namespace

std::vector<ConnectionAdapter> connection_adapters() {
    ULONG size = 16384;
    Bytes storage(size);
    auto get = [&] {
        return GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_ANYCAST, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()), &size);
    };
    auto error = get();
    if (error == ERROR_BUFFER_OVERFLOW && size <= 4 * 1024 * 1024) { storage.resize(size); error = get(); }
    if (error == ERROR_NO_DATA) return {};
    if (error != NO_ERROR) throw std::runtime_error("Cannot enumerate Ethernet adapters");
    std::vector<ConnectionAdapter> result;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()); a; a = a->Next) {
        if (a->PhysicalAddressLength != 6 || !a->AdapterName) continue;
        MIB_IF_ROW2 row{}; row.InterfaceLuid = a->Luid;
        if (GetIfEntry2(&row) != NO_ERROR) continue;
        ConnectionAdapter item;
        std::copy_n(a->PhysicalAddress, 6, item.mac.begin());
        item.id = a->AdapterName; item.name = a->FriendlyName ? a->FriendlyName : L"以太网";
        item.index = a->IfIndex; item.metric = a->Ipv4Metric;
        item.physical = row.InterfaceAndOperStatusFlags.HardwareInterface != 0;
        item.ethernet = a->IfType == IF_TYPE_ETHERNET_CSMACD;
        item.wireless = a->IfType == IF_TYPE_IEEE80211;
        item.link_up = a->OperStatus == IfOperStatusUp;
        item.dhcp = a->Dhcpv4Enabled != 0;
        item.gateway = a->FirstGatewayAddress && a->FirstGatewayAddress->Address.lpSockaddr &&
            a->FirstGatewayAddress->Address.lpSockaddr->sa_family == AF_INET;
        for (auto* ip = a->FirstUnicastAddress; ip; ip = ip->Next)
            if (ip->Address.lpSockaddr && ip->Address.lpSockaddr->sa_family == AF_INET &&
                ip->DadState != IpDadStateTentative && ip->DadState != IpDadStateDuplicate &&
                reinterpret_cast<sockaddr_in*>(ip->Address.lpSockaddr)->sin_addr.s_addr) {
                const auto* address = reinterpret_cast<sockaddr_in*>(ip->Address.lpSockaddr);
                // Prefer a routable lease over an APIPA address during DHCP.
                std::array<Byte,4> candidate{};
                std::memcpy(candidate.data(), &address->sin_addr, 4);
                if (!item.ipv4 || (item.address[0] == 169 && item.address[1] == 254)) item.address = candidate;
                item.ipv4 = true;
            }
        result.push_back(std::move(item));
    }
    return result;
}
std::optional<std::size_t> choose_connection_adapter(std::span<const ConnectionAdapter> adapters,
                                                    const Mac& preferred) {
    const auto rank = [&](const ConnectionAdapter& a) {
        return std::tuple{!a.link_up, !a.ipv4, a.mac != preferred, !a.gateway, a.metric, a.index, a.id};
    };
    std::optional<std::size_t> chosen;
    for (std::size_t i = 0; i < adapters.size(); ++i) {
        const auto& a = adapters[i];
        if (!a.physical || !a.ethernet || !unicast_mac(a.mac) || a.id.empty()) continue;
        if (!chosen || rank(a) < rank(adapters[*chosen])) chosen = i;
    }
    return chosen;
}
Bytes scau_wired_service() {
    // School-wide service name observed in both the authenticator's service
    // advertisement and the original client, encoded as a 32-byte GBK field.
    constexpr Byte name[]{0xd3,0xd0,0xcf,0xdf,0x31,0x78,0xc9,0xcf,0xcd,0xf8}; // 有线1x上网
    Bytes service(32, 0); std::copy(std::begin(name), std::end(name), service.begin()); return service;
}
Bytes system_disk_identity() {
    Bytes result(64, 0);
    wchar_t windows[MAX_PATH]{};
    if (!GetWindowsDirectoryW(windows, MAX_PATH) || windows[1] != L':') return result;
    const std::wstring volume = L"\\\\.\\" + std::wstring(windows, 2);
    Handle device{CreateFileW(volume.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr)};
    if (device.value == INVALID_HANDLE_VALUE) return result;
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty; query.QueryType = PropertyStandardQuery;
    STORAGE_DESCRIPTOR_HEADER header{}; DWORD received = 0;
    if (!DeviceIoControl(device.value, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            &header, sizeof(header), &received, nullptr) || received < sizeof(header) ||
            header.Size < sizeof(STORAGE_DEVICE_DESCRIPTOR) || header.Size > 65536) return result;
    Bytes buffer(header.Size, 0);
    struct Wipe { Bytes& value; ~Wipe() { SecureZeroMemory(value.data(), value.size()); } } wipe{buffer};
    if (!DeviceIoControl(device.value, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            buffer.data(), DWORD(buffer.size()), &received, nullptr) || received < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return result;
    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    const auto limit = std::min<std::size_t>(received, buffer.size());
    if (descriptor->SerialNumberOffset < sizeof(STORAGE_DEVICE_DESCRIPTOR) || descriptor->SerialNumberOffset >= limit) return result;
    auto serial = std::span(buffer).subspan(descriptor->SerialNumberOffset, limit - descriptor->SerialNumberOffset);
    const auto end = std::find(serial.begin(), serial.end(), Byte{});
    if (end == serial.end()) return result;
    serial = serial.first(std::size_t(end - serial.begin()));
    while (!serial.empty() && serial.front() == ' ') serial = serial.subspan(1);
    while (!serial.empty() && serial.back() == ' ') serial = serial.first(serial.size() - 1);
    if (serial.empty() || serial.size() > 63 || std::any_of(serial.begin(), serial.end(), [](Byte ch) { return ch < 32 || ch > 126; })) return result;
    std::copy(serial.begin(), serial.end(), result.begin());
    return result;
}
Profile make_connection_profile(const ConnectionAdapter& adapter, std::span<const Byte> identity) {
    if (!adapter.physical || !adapter.ethernet || !unicast_mac(adapter.mac) || adapter.id.empty())
        throw std::runtime_error("An eligible physical Ethernet adapter is required");
    if (identity.size() > 64) throw std::runtime_error("Device identity field exceeds the wire format");
    Profile result; normalize(result, adapter);
    result.service = scau_wired_service(); result.device_id.resize(64, 0);
    std::copy(identity.begin(), identity.end(), result.device_id.begin());
    return result;
}
ConnectionSetup prepare_connection(const std::filesystem::path& directory,
    std::span<const ConnectionAdapter> adapters, DeviceIdentityReader identity) {
    auto current = cached_profile(directory / L"connection.scau");
    const auto legacy = cached_profile(directory / L"profile.scau");
    const auto preferred = current ? current->local : legacy ? legacy->local : Mac{};
    const auto selected = choose_connection_adapter(adapters, preferred);
    if (!selected) return {};
    const auto& adapter = adapters[*selected];
    ConnectionSetup setup; setup.path = directory / L"connection.scau"; setup.adapter = adapter.name;
    setup.mac = adapter.mac; setup.found = true; setup.link_up = adapter.link_up;
    Profile profile;
    if (current && current->local == adapter.mac) { profile = *current; normalize(profile, adapter); }
    else if (legacy && legacy->local == adapter.mac) { profile = *legacy; normalize(profile, adapter); setup.migrated = true; }
    else {
        auto device = identity ? identity() : system_disk_identity();
        struct Wipe { Bytes& value; ~Wipe() { if (!value.empty()) SecureZeroMemory(value.data(), value.size()); } } wipe{device};
        profile = make_connection_profile(adapter, device);
    }
    if (!current || !same_parameters(profile, *current)) {
        std::filesystem::create_directories(directory);
        save_native_profile(setup.path, profile); setup.created = true;
    }
    return setup;
}
ConnectionSetup prepare_connection(const std::filesystem::path& directory) {
    const auto adapters = connection_adapters();
    return prepare_connection(directory, adapters);
}
bool capture_driver_available() {
    wchar_t system[MAX_PATH]{};
    if (!GetSystemDirectoryW(system, MAX_PATH)) return false;
    return std::filesystem::is_regular_file(std::filesystem::path(system) / L"Npcap/wpcap.dll") ||
           std::filesystem::is_regular_file(std::filesystem::path(system) / L"wpcap.dll");
}
} // namespace scau::desktop
