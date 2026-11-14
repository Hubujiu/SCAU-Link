#include "maintenance.hpp"
#include "sam_crypto.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace scau {
namespace {
constexpr std::array<Byte, 4> vendor{0, 0, 0x13, 0x11};

class Reader {
public:
    explicit Reader(std::span<const Byte> data) : data_(data) {}
    [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
    std::span<const Byte> take(std::size_t length) {
        if (length > remaining()) throw std::runtime_error("Truncated maintenance parameters");
        auto result = data_.subspan(offset_, length);
        offset_ += length;
        return result;
    }
    Byte byte() { return take(1)[0]; }
    std::uint16_t word() {
        const auto value = take(2);
        return (std::uint16_t(value[0]) << 8) | value[1];
    }
    void require_vendor() {
        const auto value = take(vendor.size());
        if (!std::equal(vendor.begin(), vendor.end(), value.begin()))
            throw std::runtime_error("Unrecognized maintenance vendor format");
    }
private:
    std::span<const Byte> data_;
    std::size_t offset_{};
};

std::uint32_t be32(std::span<const Byte> value) {
    if (value.size() != 4) throw std::runtime_error("Invalid maintenance property length");
    return (std::uint32_t(value[0]) << 24) | (std::uint32_t(value[1]) << 16)
         | (std::uint32_t(value[2]) << 8) | value[3];
}

Byte transform(Byte value) {
    value = Byte(((value & 0x55u) << 1) | ((value & 0xaau) >> 1));
    value = Byte(((value & 0x33u) << 2) | ((value & 0xccu) >> 2));
    value = Byte((value << 4) | (value >> 4));
    return Byte(~value);
}

std::span<const Byte> success_extension(std::span<const Byte> frame) {
    Reader ethernet(frame);
    ethernet.take(12);
    auto ether_type = ethernet.word();
    while (ether_type == 0x8100 || ether_type == 0x88a8 || ether_type == 0x9100) {
        ethernet.take(2);
        ether_type = ethernet.word();
    }
    if (ether_type != 0x888e) throw std::runtime_error("Not an EAPOL frame");
    ethernet.byte(); // EAPOL version is independent of the private extension.
    if (ethernet.byte() != 0) throw std::runtime_error("Not an EAP packet");
    const auto eapol_length = ethernet.word();
    const auto eapol = ethernet.take(eapol_length);
    Reader eap(eapol);
    if (eap.byte() != 3) throw std::runtime_error("Not an EAP Success packet");
    eap.byte(); // Identifier belongs to the authentication exchange.
    const auto eap_length = eap.word();
    if (eap_length < 4 || eap_length > eapol.size()) throw std::runtime_error("Invalid EAP Success length");
    return eapol.subspan(4, eap_length - 4);
}

void put32(Bytes& output, std::size_t offset, std::uint32_t value) {
    for (unsigned i = 0; i != 4; ++i) output[offset + i] = Byte(value >> (24 - i * 8));
}
}

MaintenanceParameters parse_success_maintenance(std::span<const Byte> ethernet_frame) {
    MaintenanceParameters result{};
    Reader input(success_extension(ethernet_frame));
    if (!input.remaining()) return result;
    result.vendor_parameters_present = true;

    input.require_vendor();
    const auto message_length = input.word();
    input.take(message_length);

    // The older server information segment has three fixed 32-byte slots and a
    // count of additional 32-byte records. Its length byte is not a TLV length.
    input.require_vendor();
    input.take(106);
    const auto additional_records = input.byte();
    input.take(std::size_t(additional_records) * 32);
    for (unsigned i = 0; i != 2; ++i) {
        input.require_vendor();
        if (input.byte() != 1 || input.byte() > 1)
            throw std::runtime_error("Invalid legacy maintenance switch");
    }

    std::array<Byte, 15> echo{};
    const auto encoded = input.take(echo.size());
    std::transform(encoded.begin(), encoded.end(), echo.begin(), transform);
    if (!std::equal(vendor.begin(), vendor.end(), echo.begin()) || echo[4] != 10)
        throw std::runtime_error("Invalid legacy echo parameters");
    result.echo_enabled = echo[5] != 0;
    result.echo_interval_seconds = be32(std::span(echo).subspan(10, 4));
    if (result.echo_enabled) result.echo_key = be32(std::span(echo).subspan(6, 4));

    while (input.remaining()) {
        input.require_vendor();
        const auto type = input.byte();
        const auto length = input.byte();
        if (length < 2) throw std::runtime_error("Invalid maintenance property length");
        const auto value = input.take(length - 2);
        switch (type) {
        case 0x56: {
            const auto minutes = be32(value);
            if (minutes > std::numeric_limits<std::uint32_t>::max() / 60)
                throw std::runtime_error("Reauthentication interval exceeds supported range");
            result.reauth_interval_seconds = minutes * 60;
            break;
        }
        case 0x59: result.sam_hello_interval_seconds = be32(value); break;
        case 0x5a: result.sam_server_port=be32(value);break;
        case 0x5b:
            result.sam_server_advertised=be32(value)!=0;
            std::copy(value.begin(),value.end(),result.sam_server_ipv4.begin());break;
        case 0x5c:
            if(value.size()!=8)throw std::runtime_error("Invalid SAM wrapped key length");
            result.sam_key=unwrap_success_key(value);result.sam_key_present=true;break;
        case 0x5d:
            if(value.size()!=8)throw std::runtime_error("Invalid SAM wrapped IV length");
            result.sam_iv=unwrap_success_key(value);result.sam_iv_present=true;break;
        case 0x5e:
            if(value.size()!=8)throw std::runtime_error("Invalid SAM server time length");
            result.sam_server_utc=0;
            for(const auto byte:value)result.sam_server_utc=(result.sam_server_utc<<8)|byte;
            result.sam_time_present=true;break;
        case 0x6e: result.sam_client_port=be32(value);break;
        case 0x79:
            if (value.size() != 1) throw std::runtime_error("Invalid direct communication version length");
            result.direct_communication_version = value[0];
            break;
        case 0x80: result.direct_heartbeat_flags = be32(value); break;
        default: break;
        }
    }
    return result;
}

Bytes make_echo(const Mac& local, const Mac& peer, std::uint32_t key,
                std::uint32_t sequence, std::uint32_t ring_value) {
    // The original format advertises a 30-byte EAPOL body and sends 27 bytes.
    Bytes result(45);
    std::copy(peer.begin(), peer.end(), result.begin());
    std::copy(local.begin(), local.end(), result.begin() + 6);
    constexpr std::array<Byte, 33> body{
        0x88,0x8e, 1,0xbf, 0,30,
        0,0,0x13,0x11,1,6, 0,0,0,0,
        0,0,0x13,0x11,1,6, 0,0,0,0,
        0,0,0x13,0x11,1,3,0
    };
    std::copy(body.begin(), body.end(), result.begin() + 12);
    put32(result, 24, key + sequence);
    put32(result, 34, sequence + std::uint32_t(0x474) - ring_value);
    std::transform(result.begin() + 18, result.end(), result.begin() + 18, transform);
    return result;
}

}
