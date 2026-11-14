#pragma once

#include "sam_crypto.hpp"

#include <optional>

namespace scau {

using SamIpv4 = std::array<Byte, 4>;

struct SamEndpoint {
    SamIpv4 address{};
    std::uint16_t port{};
    bool operator==(const SamEndpoint&) const = default;
};

struct SamTime {
    std::uint64_t monotonic_ms{};
    std::uint64_t unix_seconds{};
};

struct SamConfig {
    SamEndpoint local{}, server{};
    Mac local_mac{};
    std::string username;
    SamBlock key{}, iv{};
    Byte version{2};
    std::uint64_t server_utc{};
    std::uint32_t hello_interval_seconds{};
    std::uint32_t retry_timeout_ms{2000};
    std::uint32_t max_attempts{2};
    bool append_integrity_attribute{};
    std::array<Byte, 16> integrity_seed{};
};

struct SamDatagram {
    SamEndpoint source{}, destination{};
    Bytes payload;
};

struct SamAttribute {
    Byte type{};
    Bytes value;
};

enum class SamEventKind {
    server_message,
    server_termination,
    send_confirmed,
    send_failed,
};

struct SamEvent {
    SamEventKind kind{};
    std::uint32_t session_id{};
    Byte command{};
    // Server supplied values can contain personal or session information.
    // The caller must not write these bytes to an ordinary diagnostic log.
    // Callers retaining events own clearing these values after consuming them.
    std::vector<SamAttribute> attributes;
};

struct SamOutput {
    std::vector<SamDatagram> datagrams;
    std::vector<SamEvent> events;
};

// Offline protocol engine. No sockets, captures, timers, password access or
// automatic EAP login occurs here. Each configure starts a new generation.
class SamSession {
public:
    SamSession() = default;
    ~SamSession();
    SamSession(const SamSession&) = delete;
    SamSession& operator=(const SamSession&) = delete;
    SamOutput configure(const SamConfig& config, SamTime now);
    SamOutput receive(const SamEndpoint& source, const SamEndpoint& destination,
                      std::span<const Byte> payload, SamTime now);
    SamOutput tick(SamTime now);
    SamOutput send_message(std::span<const Byte> body, bool reliable, SamTime now);
    void stop() noexcept;
    bool active() const noexcept { return active_; }
    std::optional<std::uint64_t> next_deadline_ms() const noexcept;

private:
    struct Pending {
        std::uint32_t session_id{}, packet_id{};
        Bytes ciphertext;
        std::size_t offset{};
        std::uint32_t attempts{};
        std::uint64_t deadline{};
    };
    struct Assembly {
        std::uint32_t session_id{}, last_packet_id{}, total{};
        std::uint64_t touched{};
        Bytes ciphertext;
        std::size_t last_offset{}, last_size{};
        Byte last_fragment{};
        bool complete{}, suppress_ack{};
    };

    SamConfig config_{};
    bool active_{};
    SamTime configured_at_{};
    std::uint64_t send_stamp_{}, receive_stamp_{}, hello_deadline_{};
    std::uint32_t receive_nonincreasing_{};
    std::uint32_t next_session_id_{1};
    std::optional<Pending> pending_;
    std::vector<Pending> queued_;
    std::vector<Assembly> assemblies_;

    std::uint64_t timestamp(SamTime now);
    Bytes packet(Byte type, std::uint32_t packet_id, std::uint32_t session_id,
                 Byte fragment, std::uint32_t total,
                 std::span<const Byte> ciphertext, SamTime now);
    SamDatagram datagram(Bytes payload) const;
    SamOutput hello(SamTime now);
    void send_fragment(SamOutput& output, SamTime now);
    void advance_queue(SamOutput& output, SamTime now);
};

} // namespace scau
