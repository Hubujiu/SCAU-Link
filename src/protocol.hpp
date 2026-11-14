#pragma once
#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace scau {
using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using Mac = std::array<Byte, 6>;
using Digest = std::array<Byte, 16>;
struct Property { Byte type; Bytes value; };
struct Frame {
    Mac destination{}, source{};
    Byte version{}, type{}, code{}, identifier{}, method{};
    std::span<const Byte> eap{}, trailing{};
};
struct Profile {
    Mac local{}, server{};
    std::array<Byte, 23> network{}; // decoded header, without publishing its addresses
    std::string username;
    Bytes service, device_id;
};
bool unicast_mac(const Mac& address) noexcept;
std::optional<Bytes> initial_logoff(const Profile& profile, bool recovering);
Digest md5(std::span<const Byte> data);
Digest md5_response(Byte identifier, std::string_view password, std::span<const Byte> challenge);
std::uint16_t crc16(std::span<const Byte> data);
void encode_network(std::span<Byte> data);
Frame parse_frame(std::span<const Byte> packet);
std::vector<Property> parse_client_properties(std::span<const Byte> trailing);
Profile load_profile(const std::filesystem::path& capture);
Bytes legacy_trailer(const Profile& profile, std::string_view username,
                     std::string_view password, std::span<const Byte> challenge, bool md5_phase);
Bytes make_simple(const Mac& local, const Mac& remote, Byte eapol_type);
Bytes make_response(const Profile& profile, const Mac& server, Byte identifier,
                    std::string_view username, std::string_view password,
                    std::span<const Byte> challenge, bool md5_phase);
}
