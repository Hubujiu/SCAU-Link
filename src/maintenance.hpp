#pragma once
#include "protocol.hpp"

namespace scau {

enum class MaintenanceCapability { disabled, supported, unsupported };

struct MaintenanceParameters {
    std::uint32_t reauth_interval_seconds{};
    std::uint32_t sam_hello_interval_seconds{};
    bool echo_enabled{};
    std::uint32_t echo_key{}; // Session material; never include in diagnostics.
    std::uint32_t echo_interval_seconds{};
    bool vendor_parameters_present{};
    bool sam_server_advertised{};
    std::array<Byte,4> sam_server_ipv4{};
    std::uint32_t sam_server_port{};
    std::uint32_t sam_client_port{80};
    std::array<Byte,8> sam_key{},sam_iv{}; // Decoded session material; never log.
    std::uint64_t sam_server_utc{};
    bool sam_key_present{},sam_iv_present{},sam_time_present{};
    Byte direct_communication_version{1};
    std::uint32_t direct_heartbeat_flags{};

    [[nodiscard]] MaintenanceCapability echo_capability() const noexcept {
        if (!echo_enabled) return MaintenanceCapability::disabled;
        return echo_interval_seconds ? MaintenanceCapability::supported : MaintenanceCapability::unsupported;
    }
    [[nodiscard]] MaintenanceCapability sam_hello_capability() const noexcept {
        return sam_hello_interval_seconds ? sam_capability() : MaintenanceCapability::disabled;
    }
    [[nodiscard]] MaintenanceCapability sam_capability() const noexcept {
        if(!sam_server_advertised && !sam_hello_interval_seconds)return MaintenanceCapability::disabled;
        if(!sam_server_advertised || !sam_key_present || !sam_iv_present || !sam_time_present ||
           !sam_server_port || sam_server_port>65535 || !sam_client_port || sam_client_port>65535 ||
           !sam_server_ipv4[0] || sam_server_ipv4[0]==127 || sam_server_ipv4[0]>=224 ||
           !direct_communication_version || sam_server_utc==UINT64_MAX)return MaintenanceCapability::unsupported;
        return MaintenanceCapability::supported;
    }
};

// Returns fresh parameters for this Success only. Plain EAP Success disables all
// maintenance. Malformed or unrecognized private extensions throw runtime_error;
// callers must clear their previous session parameters before parsing a new one.
MaintenanceParameters parse_success_maintenance(std::span<const Byte> ethernet_frame);

// sequence is the current wire counter, after the sender's increment. The
// default ring value produces the ordinary counter; nondefault values preserve
// the original client's explicitly supplied counter adjustment. No I/O occurs.
Bytes make_echo(const Mac& local, const Mac& peer, std::uint32_t key,
                std::uint32_t sequence, std::uint32_t ring_value = 0x474);

}
