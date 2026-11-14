#pragma once

#include "protocol.hpp"

namespace scau {

using SamBlock = std::array<Byte, 8>;
using SamIntegrity = std::array<Byte, 128>;
using SamSeed = std::array<Byte, 16>;

// Non-elidable clearing for caller-owned session material. Returned keys,
// seeds and decrypted bodies remain the caller's responsibility to clear.
void sam_clear_secret(std::span<Byte> bytes) noexcept;

// Success properties 0x5c (key) and 0x5d (IV) each start a fresh RC4 stream.
// The fixed protocol wrapping key is unrelated to the user's password.
SamBlock unwrap_success_key(std::span<const Byte> wrapped);

// Native mode-name mapping EAPMD5 -> 4, IF_TYPE_WIRED -> 0 retains the
// current Request-MD5 challenge as the SAM integrity seed. Other native modes
// use a different fallback; this helper is deliberately specific to wired MD5.
SamSeed sam_seed_for_wired_md5(std::span<const Byte> challenge);

// SAM uses standard DES-CBC. The sender zero-pads a partial block, and sends
// no extra block for an already aligned or empty body. Decryption retains
// zero padding: the wire parser owns the unpadded message/TLV boundaries.
Bytes sam_encrypt_body(const SamBlock& key, const SamBlock& iv,
                       std::span<const Byte> body);
Bytes sam_decrypt_body(const SamBlock& key, const SamBlock& iv,
                       std::span<const Byte> ciphertext);

// The 42-byte wire header's authenticator field [8,24) is treated as zero.
// Hash input is that header, the current fragment's ciphertext, key, then IV.
Digest sam_packet_authenticator(const SamBlock& key, const SamBlock& iv,
                                std::span<const Byte> packet);
bool sam_verify_packet_authenticator(const SamBlock& key, const SamBlock& iv,
                                     std::span<const Byte> packet);

// Optional type-0x14 integrity attribute. session_id is the logical message
// serial (not the per-fragment packet serial); seed belongs to this EAP round.
SamIntegrity sam_integrity_attribute(std::uint32_t session_id,
                                     std::span<const Byte, 16> seed);

} // namespace scau
