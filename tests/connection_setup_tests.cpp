#include "desktop/connection_setup.hpp"
#include "profile_store.hpp"
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace scau;
using namespace scau::desktop;
void require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
struct Fixture {
    std::filesystem::path root;
    std::vector<std::filesystem::path> directories;
    Fixture() {
        wchar_t temporary[MAX_PATH]{}; GetTempPathW(MAX_PATH, temporary);
        root = std::filesystem::path(temporary) / (L"scau-setup-test-" +
            std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
        require(std::filesystem::create_directory(root), "Fresh isolated test directory is required");
        directories.push_back(root);
    }
    std::filesystem::path directory(const wchar_t* name) {
        const auto path = root / name;
        require(std::filesystem::create_directory(path), "Test subdirectory must be fresh");
        directories.push_back(path); return path;
    }
    ~Fixture() {
        // Remove only known fixture files. Never recursively delete a computed path.
        std::error_code error;
        for (auto i = directories.rbegin(); i != directories.rend(); ++i) {
            for (const auto* file : {L"connection.scau", L"connection.scau.tmp", L"profile.scau", L"eapol-only.pcapng"})
                std::filesystem::remove(*i / file, error);
            std::filesystem::remove(*i, error);
        }
    }
};
ConnectionAdapter ethernet(Byte suffix = 1) {
    ConnectionAdapter a; a.mac = {2,0,0,0,0,suffix}; a.id = "synthetic-adapter-" + std::to_string(suffix);
    a.name = L"测试有线网卡"; a.index = suffix; a.metric = 20;
    a.physical = a.ethernet = a.link_up = a.dhcp = true; return a;
}
Bytes read(const std::filesystem::path& file) {
    std::ifstream input(file, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(input), {});
}
Bytes property(const std::vector<Property>& values, Byte type) {
    const auto found = std::find_if(values.begin(), values.end(), [&](const auto& p) { return p.type == type; });
    require(found != values.end(), "Required protocol property is absent"); return found->value;
}
int main() { try {
    Fixture f;
    const Bytes identity{'L','O','C','A','L','-','T','E','S','T'};
    auto local = ethernet();
    std::vector<ConnectionAdapter> adapters{local};
    unsigned queries = 0;
    const auto reader = [&] { ++queries; return identity; };
    const auto fresh = f.directory(L"fresh");
    require(std::filesystem::is_empty(fresh), "Fresh installation must have no imported inputs");
    const auto setup = prepare_connection(fresh, adapters, reader);
    const auto profile = load_profile(setup.path);
    require(setup.found && setup.link_up && setup.created && !setup.migrated && queries == 1,
            "Fresh install must prepare its own adapter without an imported profile");
    require(read(setup.path).size() == 141 && profile.username.empty() && profile.local == local.mac &&
            profile.server == Mac{} && profile.device_id.size() == 64 &&
            std::equal(identity.begin(), identity.end(), profile.device_id.begin()),
            "Cache contains local device fields, no account, and no stale authenticator");
    const Bytes school{0xd3,0xd0,0xcf,0xdf,0x31,0x78,0xc9,0xcf,0xcd,0xf8};
    require(profile.service.size() == 32 && std::equal(school.begin(), school.end(), profile.service.begin()) &&
            std::all_of(profile.service.begin()+school.size(), profile.service.end(), [](Byte b) { return b == 0; }),
            "SCAU wired service must be exact GBK with zero padding");
    require(profile.network[4] == 1 && std::all_of(profile.network.begin()+5, profile.network.begin()+21,
            [](Byte b) { return b == 0; }) && crc16(std::span(profile.network).first(21)) ==
            ((unsigned(profile.network[21]) << 8) | profile.network[22]), "Address-free DHCP header must have valid CRC");
    const auto old_time = std::filesystem::file_time_type::clock::now() - std::chrono::hours(1);
    std::filesystem::last_write_time(setup.path, old_time);
    const auto stable = prepare_connection(fresh, adapters, [&]() -> Bytes { throw std::runtime_error("Unexpected hardware query"); });
    require(!stable.created && !stable.migrated && std::filesystem::last_write_time(setup.path) == old_time,
            "An unchanged cache must not query storage or rewrite files while waiting");

    auto vpn = ethernet(2); vpn.physical = false; vpn.ipv4 = vpn.gateway = true; vpn.metric = 0;
    auto wifi = ethernet(3); wifi.ethernet = false; wifi.ipv4 = true;
    auto invalid = ethernet(4); invalid.mac = {};
    auto multicast = ethernet(5); multicast.mac[0] = 1;
    const std::vector<ConnectionAdapter> ineligible{vpn,wifi,invalid,multicast};
    const auto none = f.directory(L"none");
    require(!choose_connection_adapter(ineligible) && !prepare_connection(none, ineligible, reader).found &&
            std::filesystem::is_empty(none), "VPN, Wi-Fi, invalid and multicast adapters cannot become wired authentication targets");
    auto down = ethernet(6); down.link_up = false; down.ipv4 = down.gateway = true;
    std::vector<ConnectionAdapter> choices{vpn,wifi,down,local};
    require(choose_connection_adapter(choices, down.mac) == 3,
            "A live physical Ethernet link wins over the disconnected cached adapter without requiring IPv4");
    local.ipv4 = local.gateway = true;
    auto usb = ethernet(7); usb.ipv4 = usb.gateway = true; usb.metric = 10;
    choices = {local,usb};
    require(choose_connection_adapter(choices) == 1 && choose_connection_adapter(choices,local.mac) == 0,
            "Multiple ready Ethernet adapters use stable metrics and keep a usable preferred interface");
    const auto waiting = f.directory(L"waiting");
    const auto waiting_setup = prepare_connection(waiting, std::span(&down,1), reader);
    require(waiting_setup.found && !waiting_setup.link_up && waiting_setup.created,
            "An unplugged adapter is prepared once and may wait for cable insertion");

    const auto legacy_dir = f.directory(L"legacy");
    auto legacy = make_connection_profile(local, Bytes(64,42)); legacy.server = {2,0,0,0,0,99};
    save_native_profile(legacy_dir / L"profile.scau", legacy);
    const auto legacy_bytes = read(legacy_dir / L"profile.scau");
    const auto migrated = prepare_connection(legacy_dir, std::span(&local,1), reader);
    require(migrated.migrated && migrated.created && load_profile(migrated.path).device_id == legacy.device_id &&
            load_profile(migrated.path).server == Mac{} && read(legacy_dir / L"profile.scau") == legacy_bytes,
            "Same-machine migration preserves compatibility fields and the original file, but discovers its server anew");
    const auto foreign_dir = f.directory(L"foreign");
    save_native_profile(foreign_dir / L"profile.scau", legacy);
    auto foreign = ethernet(8);
    const auto replaced = prepare_connection(foreign_dir, std::span(&foreign,1), reader);
    require(!replaced.migrated && load_profile(replaced.path).device_id != legacy.device_id &&
            load_profile(replaced.path).local == foreign.mac, "Another adapter cannot inherit a capture's device identity");
    const auto corrupt_dir = f.directory(L"corrupt");
    for (auto length : {30,141,4096}) {
        { std::ofstream output(corrupt_dir / L"connection.scau", std::ios::binary|std::ios::trunc);
          const std::string invalid_bytes(length,'x'); output.write(invalid_bytes.data(), length); }
        require(prepare_connection(corrupt_dir, adapters, reader).created,
                "Truncated, corrupt and oversized caches are regenerated from local information");
    }
    save_native_profile(f.root / L"profile.scau", legacy);
    const auto child = f.directory(L"parent-isolation");
    require(!prepare_connection(child, adapters, reader).migrated &&
            load_profile(child / L"connection.scau").device_id != legacy.device_id,
            "An installation must never search parent folders for someone else's profile");

    auto static_adapter = ethernet(9); static_adapter.dhcp = false;
    const auto no_serial = make_connection_profile(static_adapter, {});
    require(no_serial.network[4] == 0 && no_serial.device_id == Bytes(64,0),
            "Static IPv4 mode and unavailable storage identity have bounded, explicit fields");
    bool rejected = false;
    try { make_connection_profile(local, Bytes(65,1)); } catch (const std::exception&) { rejected = true; }
    require(rejected, "Oversized storage identity cannot overflow its wire field");

    const Mac server{2,0,0,0,0,99};
    const std::array<Byte,16> challenge{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    for (const bool md5_phase : {false,true}) {
        const auto wire = make_response(profile, server, 7, "synthetic-user", "synthetic-password",
            md5_phase ? std::span<const Byte>(challenge) : std::span<const Byte>{}, md5_phase);
        const auto frame = parse_frame(wire); const auto properties = parse_client_properties(frame.trailing);
        require(frame.source == local.mac && frame.destination == server && frame.identifier == 7 &&
                property(properties,0x2d) == Bytes(local.mac.begin(),local.mac.end()) &&
                property(properties,0x39) == profile.service && property(properties,0x54) == profile.device_id,
                "Fresh profiles must construct both Identity and MD5 wire responses with local fields");
        if (md5_phase) {
            const auto digest = md5_response(7,"synthetic-password",challenge);
            require(std::equal(digest.begin(),digest.end(),frame.eap.begin()+6),
                    "Authentication responses must use the live challenge rather than saved exchanges");
        }
    }
    require(!initial_logoff(profile,false) && !initial_logoff(legacy,true),
            "Fresh discovery and crash recovery must never emit a speculative initial logoff");
    const auto cleanup = initial_logoff(legacy,false);
    require(cleanup && parse_frame(*cleanup).type == 2 && parse_frame(*cleanup).destination == server,
            "Explicit known-server legacy cleanup remains a unicast logoff");
    legacy.server = {1,0x80,0xc2,0,0,3};
    require(!initial_logoff(legacy,false), "Initial cleanup cannot log off a multicast target");
    std::cout << "PASS: empty-directory setup, local wire fields, adapter selection/waiting, cache/migration isolation, corruption and discovery\n";
    return 0;
} catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; } }
