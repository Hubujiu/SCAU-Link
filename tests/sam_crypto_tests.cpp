#include "sam_crypto.hpp"

#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>

using namespace scau;

namespace {
void require(bool value, const char* description) {
    if (!value) throw std::runtime_error(description);
}
Bytes hex(std::string_view value) {
    require(value.size() % 2 == 0, "Invalid test hex");
    const auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return unsigned(c - '0');
        if (c >= 'a' && c <= 'f') return unsigned(c - 'a' + 10);
        throw std::runtime_error("Invalid test hex digit");
    };
    Bytes result;
    for (std::size_t i = 0; i < value.size(); i += 2)
        result.push_back(Byte(digit(value[i]) * 16 + digit(value[i + 1])));
    return result;
}
SamBlock block(std::string_view value) {
    const auto bytes = hex(value);
    require(bytes.size() == 8, "Invalid test block");
    SamBlock result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}
void rejects(const std::function<void()>& operation) {
    try { operation(); } catch (const std::runtime_error&) { return; }
    throw std::runtime_error("Malformed input was accepted");
}
void test_unwrap() {
    for (const auto& pair : {
            std::pair{"0000000000000000", "12e8fcd8a2942973"},
            std::pair{"0001020304050607", "12e9fedba6912f74"},
            std::pair{"fedcba9876543210", "ec344640d4c01b63"}}) {
        const auto input = block(pair.first), expected = block(pair.second);
        require(unwrap_success_key(input) == expected, "RC4 original DLL vector mismatch");
        require(unwrap_success_key(expected) == input, "RC4 fresh stream symmetry");
        require(unwrap_success_key(input) == expected, "RC4 field state leaked between calls");
    }
    rejects([] { unwrap_success_key(Bytes(7)); });
    rejects([] { unwrap_success_key(Bytes(9)); });
}
void test_des() {
    // Classic standard DES vector; CBC with an all-zero IV has the same first block.
    const auto key = block("133457799bbcdff1");
    require(sam_encrypt_body(key, {}, hex("0123456789abcdef")) == hex("85e813540f0ab405"),
            "Standard DES vector mismatch");
    struct Vector { const char* key; const char* iv; const char* plain; const char* cipher; };
    const Vector vectors[] = {
        {"88b1e8e00b1e313a", "f6dd59e72522428f", "7008b8964cb9a9d6", "d2ea37d57e00088b"},
        {"03d4b35d0ccaafdc", "dc83a5f20b76da51", "8fc4822d2700906f5e71732ff72b360d", "82da7a487aa775c476f6c992d9e16aa6"},
        {"b917f7e6a5fede86", "89815984301ac6cd", "07345f4b1e5bb65b9299f4d5c5fa7e2d1a6283cb228bcb1a", "6bdb6261d8012c6b32389470c311c96203fcf4be64220a7a"}};
    for (const auto& vector : vectors) {
        const auto k = block(vector.key), iv = block(vector.iv);
        const auto plain = hex(vector.plain), cipher = hex(vector.cipher);
        require(sam_encrypt_body(k, iv, plain) == cipher, "Original SAM CBC oracle mismatch");
        require(sam_decrypt_body(k, iv, cipher) == plain, "CBC decryption mismatch");
        require(sam_encrypt_body(k, iv, plain) == cipher, "CBC IV state leaked across messages");
    }
    require(sam_encrypt_body({}, {}, {}).empty(), "Empty body gained padding");
    require(sam_decrypt_body({}, {}, {}).empty(), "Empty ciphertext gained plaintext");
    for (const std::size_t length : {1u, 7u, 8u, 9u, 15u, 16u, 1358u, 1360u, 65535u}) {
        Bytes body(length);
        for (std::size_t i = 0; i < length; ++i) body[i] = Byte(i * 37);
        const auto cipher = sam_encrypt_body({}, {}, body);
        require(cipher.size() == ((length + 7) & ~std::size_t(7)), "Zero padding length mismatch");
        auto expected = body;
        expected.resize(cipher.size(), 0);
        require(sam_decrypt_body({}, {}, cipher) == expected, "Zero padding round trip mismatch");
    }
    rejects([] { sam_decrypt_body({}, {}, Bytes(7)); });
    rejects([] { sam_decrypt_body({}, {}, Bytes(9)); });
}
void test_authenticator() {
    SamBlock key{}, iv{};
    Bytes packet(58);
    for (unsigned i = 0; i < 8; ++i) { key[i] = Byte(i); iv[i] = Byte(i + 8); }
    for (std::size_t i = 0; i < packet.size(); ++i) packet[i] = Byte(i);
    const auto expected = hex("2481c13d1e5080894b621f5c678b48b3");
    const auto actual = sam_packet_authenticator(key, iv, packet);
    require(std::equal(actual.begin(), actual.end(), expected.begin()), "Independent packet MD5 vector mismatch");
    std::copy(actual.begin(), actual.end(), packet.begin() + 8);
    require(sam_verify_packet_authenticator(key, iv, packet), "Valid authenticator rejected");
    packet.back() ^= 1;
    require(!sam_verify_packet_authenticator(key, iv, packet), "Modified ciphertext accepted");
    packet.back() ^= 1;
    packet[0] ^= 1;
    require(!sam_verify_packet_authenticator(key, iv, packet), "Modified header accepted");
    require(!sam_verify_packet_authenticator(key, iv, Bytes(41)), "Truncated verifier accepted");
    rejects([&] { sam_packet_authenticator(key, iv, Bytes(41)); });
}
void test_integrity_domain() {
    Bytes challenge(16);
    for (std::size_t i = 0; i < challenge.size(); ++i) challenge[i] = Byte(i * 13);
    const auto current_seed = sam_seed_for_wired_md5(challenge);
    require(std::equal(current_seed.begin(), current_seed.end(), challenge.begin()),
            "Wired MD5 challenge was not retained as the integrity seed");
    rejects([] { sam_seed_for_wired_md5(Bytes(15)); });
    rejects([] { sam_seed_for_wired_md5(Bytes(17)); });
    std::array<SamIntegrity, 53> selected{};
    std::array<Byte, 16> seed{};
    // For serials 0..52, multiplication by 727 is a permutation modulo 53.
    // Recover every row through the public selector, then compare the entire
    // 6784-byte domain with the independently recorded original-function oracle.
    for (std::uint32_t serial = 0; serial < 53; ++serial)
        selected[(serial * 727u) % 53] = sam_integrity_attribute(serial, seed);
    std::uint64_t digest = 0xcbf29ce484222325ull;
    for (const auto& row : selected) {
        for (const auto byte : row) {
            require((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'),
                    "Integrity must be 128 ASCII hexadecimal bytes");
            digest = (digest ^ byte) * 0x100000001b3ull;
        }
    }
    require(digest == 0x61e65a31e0d87678ull, "Integrity exhaustive original oracle mismatch");
    seed.fill(0);
    seed[15] = 1;
    require(sam_integrity_attribute(0, seed) == selected[727u % 53],
            "Integrity EAP seed was ignored");
    seed.fill(255);
    require(sam_integrity_attribute(0xffffffffu, seed) == selected[(5100u * 727u) % 53],
            "Integrity high-byte sum changed signedness or overflowed");
    seed.fill(0);
    require(sam_integrity_attribute(0x01020304u, seed) == selected[(10u * 727u) % 53],
            "Integrity message serial used incorrect bytes");
}
void test_explicit_secret_clear() {
    SamBlock key{};
    key.fill(0xa5);
    sam_clear_secret(key);
    require(std::all_of(key.begin(), key.end(), [](Byte byte) { return byte == 0; }),
            "Session key clear did not overwrite caller storage");
    Bytes plaintext(257, 0x5a);
    const auto* original_storage = plaintext.data();
    sam_clear_secret(plaintext);
    require(plaintext.data() == original_storage && plaintext.size() == 257 &&
            std::all_of(plaintext.begin(), plaintext.end(), [](Byte byte) { return byte == 0; }),
            "Plaintext clear must overwrite before the caller releases storage");
    sam_clear_secret({});
}
} // namespace

int main() {
    try {
        test_unwrap(); test_des(); test_authenticator(); test_integrity_domain();
        test_explicit_secret_clear();
        std::cout << "SAM crypto tests passed (offline synthetic data)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
