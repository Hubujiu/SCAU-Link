#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace scau {

enum class RecoveryActionKind {
    BeginExchange,
    RetryStart,
    ReopenTransport,
    Connected,
    Rejected,
    Waiting,
    Stopped
};

enum class RecoveryState {
    Idle,
    Connecting,
    Authenticating,
    Connected,
    NoServerWait,
    TransientBackoff,
    WaitingForLink,
    LinkDebounce,
    Suspended,
    ResumeDelay,
    TransportBackoff,
    ReopeningTransport,
    Rejected,
    Stopped
};

enum class RecoveryReason {
    None,
    NoServerResponse,
    TransientFailure,
    LinkDown,
    LinkDebounce,
    Suspended,
    ResumeDelay,
    TransportRetry,
    TransportPending,
    ServerRejected,
    RetryExhausted,
    PeriodicReauth
};

struct RecoveryAction {
    RecoveryActionKind kind{};
    RecoveryReason reason{RecoveryReason::None};
    std::optional<std::uint64_t> deadline_ms{};
};

using RecoveryActions = std::vector<RecoveryAction>;

// Pure policy: no wall clock, credentials, Windows calls, packets, or logoff.
// The caller supplies monotonic milliseconds and executes returned actions.
// BeginExchange clears the previous exchange/cache/maintenance and sends Start;
// RetryStart only retransmits Start. ReopenTransport opens the SAME chosen NIC;
// report success with transport_ready(), or failure with transport_error().
// A controller whose stop() was called cannot be restarted; create a new one.
// Native policy enables 10..29 s no-server waits on every started exchange;
// the original enabled that policy conditionally on its link-recovery flag.
class RecoveryController {
public:
    static constexpr std::uint64_t start_period_ms = 3000;
    static constexpr unsigned max_start_attempts = 3;
    static constexpr std::uint64_t response_timeout_ms = 9000;
    static constexpr unsigned max_backoff_attempts = 3;
    static constexpr std::uint64_t link_debounce_ms = 3000;
    static constexpr std::uint64_t resume_delay_ms = 5000;
    static constexpr std::uint64_t transport_open_timeout_ms = 5000;
    static constexpr std::uint64_t max_transport_backoff_ms = 30000;

    RecoveryActions start(std::uint64_t now, bool link_up);
    RecoveryActions link_changed(std::uint64_t now, bool link_up);
    RecoveryActions suspend(std::uint64_t now);
    RecoveryActions resume(std::uint64_t now);
    // First Identity: 9 s; first validated MD5 before expiry: another 9 s once.
    // Direct MD5: 9 s. Duplicate/same-phase/regressive requests never extend it.
    RecoveryActions request(std::uint64_t now, bool md5);
    RecoveryActions success(std::uint64_t now, std::uint64_t reauth_interval_ms);
    RecoveryActions failure(std::uint64_t now, bool has_reason);
    // A separately authenticated SAM termination remains terminal even after
    // the physical link/suspend state changes while its ACK is pending.
    RecoveryActions server_terminated(std::uint64_t now);
    RecoveryActions transport_error(std::uint64_t now);
    RecoveryActions transport_ready(std::uint64_t now);
    RecoveryActions tick(std::uint64_t now, unsigned jitter_0_19);
    RecoveryActions stop(std::uint64_t now);

    [[nodiscard]] RecoveryState state() const noexcept { return state_; }
    [[nodiscard]] RecoveryReason reason() const noexcept { return reason_; }
    [[nodiscard]] std::optional<std::uint64_t> next_deadline_ms() const noexcept { return deadline_; }
    [[nodiscard]] unsigned start_attempts() const noexcept { return start_attempts_; }
    [[nodiscard]] unsigned backoff_attempts() const noexcept { return backoff_attempts_; }
    [[nodiscard]] unsigned transport_failures() const noexcept { return transport_failures_; }
    [[nodiscard]] std::uint64_t exchange_generation() const noexcept { return generation_; }
    [[nodiscard]] std::uint64_t no_server_waits() const noexcept { return no_server_waits_; }
    [[nodiscard]] std::uint64_t successful_exchanges() const noexcept { return successful_exchanges_; }
    [[nodiscard]] std::uint64_t reauth_interval_ms() const noexcept { return reauth_interval_ms_; }
    [[nodiscard]] bool link_up() const noexcept { return link_up_; }
    // Remains true during server-requested/periodic reauth until it fails or
    // times out, even though BeginExchange asks the caller to pause maintenance.
    // Only success() can first establish or re-establish this confirmation.
    [[nodiscard]] bool connected() const noexcept { return connected_; }
    [[nodiscard]] bool reauth_pending() const noexcept { return reauth_pending_; }
    [[nodiscard]] bool md5_seen() const noexcept { return md5_seen_; }
    [[nodiscard]] bool stopped() const noexcept { return state_ == RecoveryState::Stopped; }

private:
    RecoveryState state_{RecoveryState::Idle};
    RecoveryReason reason_{RecoveryReason::None};
    std::optional<std::uint64_t> deadline_{};
    std::optional<std::uint64_t> link_ready_at_{};
    std::optional<std::uint64_t> resume_not_before_{};
    std::uint64_t last_now_{};
    std::uint64_t generation_{};
    std::uint64_t no_server_waits_{};
    std::uint64_t successful_exchanges_{};
    std::uint64_t reauth_interval_ms_{};
    unsigned start_attempts_{};
    unsigned backoff_attempts_{};
    unsigned transport_failures_{};
    bool started_{};
    bool link_up_{};
    bool connected_{};
    bool reauth_pending_{};
    bool md5_seen_{};
    bool reopen_needed_{};

    std::uint64_t observe_time(std::uint64_t now) noexcept;
    [[nodiscard]] bool terminal() const noexcept;
    [[nodiscard]] bool accepts_packet() const noexcept;
    void clear_session() noexcept;
    RecoveryActions wait(RecoveryState state, RecoveryReason reason,
                         std::optional<std::uint64_t> deadline = {});
    RecoveryActions begin_exchange(std::uint64_t now,
                                   RecoveryReason reason = RecoveryReason::None);
    RecoveryActions reopen_transport(std::uint64_t now);
    RecoveryActions transient_failure(std::uint64_t now);
    RecoveryActions schedule_transport_retry(std::uint64_t now);
    RecoveryActions reject(RecoveryReason reason);
};

const char* recovery_state_name(RecoveryState state) noexcept;
const char* recovery_reason_name(RecoveryReason reason) noexcept;

}
