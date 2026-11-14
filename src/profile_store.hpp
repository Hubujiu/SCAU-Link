#pragma once
#include "protocol.hpp"

namespace scau {
// Fixed-size native profile: protocol parameters only; never credentials or
// captured challenge/response/session material. IPv4 fields are refreshed live.
void save_native_profile(const std::filesystem::path& path,const Profile& profile);
Profile load_native_profile(std::span<const Byte> bytes);
inline constexpr std::array<Byte,8> native_profile_magic{'S','C','A','U','P','R','F','1'};
}
