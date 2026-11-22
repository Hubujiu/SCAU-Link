#pragma once

#include <cstdint>
#include <optional>

namespace scau {

enum class RecoveryActionKind : std::uint8_t {
    BeginExchange,
    RetryStart,
    ReopenTransport,
    Connected,
    Rejected,
    Waiting,
    Stopped
};

enum class RecoveryState : std::uint8_t {
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

enum class RecoveryReason : std::uint8_t {
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

using RecoveryTransition = std::optional<RecoveryAction>;

struct RecoveryRustState;
// Layout shared with rust/core/src/recovery.rs. Snapshots let read-only queries
// stay in the Windows worker and keep all transitions in Rust.
struct RecoverySnapshot {
    std::uint64_t deadline{}, generation{}, no_server_waits{}, successful_exchanges{}, reauth_interval{};
    std::uint32_t start_attempts{}, backoff_attempts{}, transport_failures{};
    RecoveryState state{};
    RecoveryReason reason{};
    std::uint8_t action{};
    bool has_deadline{}, link_up{}, connected{}, reauth_pending{}, md5_seen{};
};

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
    RecoveryController();
    ~RecoveryController();
    RecoveryController(const RecoveryController&) = delete;
    RecoveryController& operator=(const RecoveryController&) = delete;

    static constexpr std::uint64_t start_period_ms = 3000;
    static constexpr unsigned max_start_attempts = 3;
    static constexpr std::uint64_t response_timeout_ms = 9000;
    static constexpr unsigned max_backoff_attempts = 3;
    static constexpr std::uint64_t link_debounce_ms = 3000;
    static constexpr std::uint64_t resume_delay_ms = 5000;
    static constexpr std::uint64_t transport_open_timeout_ms = 5000;
    static constexpr std::uint64_t max_transport_backoff_ms = 30000;

    RecoveryTransition start(std::uint64_t now, bool link_up);
    RecoveryTransition link_changed(std::uint64_t now, bool link_up);
    RecoveryTransition suspend(std::uint64_t now);
    RecoveryTransition resume(std::uint64_t now);
    // First Identity: 9 s; first validated MD5 before expiry: another 9 s once.
    // Direct MD5: 9 s. Duplicate/same-phase/regressive requests never extend it.
    RecoveryTransition request(std::uint64_t now, bool md5);
    RecoveryTransition success(std::uint64_t now, std::uint64_t reauth_interval_ms);
    RecoveryTransition failure(std::uint64_t now, bool has_reason);
    // A separately authenticated SAM termination remains terminal even after
    // the physical link/suspend state changes while its ACK is pending.
    RecoveryTransition server_terminated(std::uint64_t now);
    RecoveryTransition transport_error(std::uint64_t now);
    RecoveryTransition transport_ready(std::uint64_t now);
    RecoveryTransition tick(std::uint64_t now, unsigned jitter_0_19);
    RecoveryTransition stop(std::uint64_t now);

    [[nodiscard]] RecoveryState state() const noexcept { return snapshot_.state; }
    [[nodiscard]] RecoveryReason reason() const noexcept { return snapshot_.reason; }
    [[nodiscard]] std::optional<std::uint64_t> next_deadline_ms() const noexcept {
        return snapshot_.has_deadline ? std::optional{snapshot_.deadline} : std::nullopt;
    }
    [[nodiscard]] unsigned start_attempts() const noexcept { return snapshot_.start_attempts; }
    [[nodiscard]] unsigned backoff_attempts() const noexcept { return snapshot_.backoff_attempts; }
    [[nodiscard]] unsigned transport_failures() const noexcept { return snapshot_.transport_failures; }
    [[nodiscard]] std::uint64_t exchange_generation() const noexcept { return snapshot_.generation; }
    [[nodiscard]] std::uint64_t no_server_waits() const noexcept { return snapshot_.no_server_waits; }
    [[nodiscard]] std::uint64_t successful_exchanges() const noexcept { return snapshot_.successful_exchanges; }
    [[nodiscard]] std::uint64_t reauth_interval_ms() const noexcept { return snapshot_.reauth_interval; }
    [[nodiscard]] bool link_up() const noexcept { return snapshot_.link_up; }
    // Remains true during server-requested/periodic reauth until it fails or
    // times out, even though BeginExchange asks the caller to pause maintenance.
    // Only success() can first establish or re-establish this confirmation.
    [[nodiscard]] bool connected() const noexcept { return snapshot_.connected; }
    [[nodiscard]] bool reauth_pending() const noexcept { return snapshot_.reauth_pending; }
    [[nodiscard]] bool md5_seen() const noexcept { return snapshot_.md5_seen; }
    [[nodiscard]] bool stopped() const noexcept { return state() == RecoveryState::Stopped; }

private:
    enum class Operation : std::uint8_t {
        Start, LinkChanged, Suspend, Resume, Request, Success, Failure,
        ServerTerminated, TransportError, TransportReady, Tick, Stop
    };
    RecoveryRustState* rust_;
    RecoverySnapshot snapshot_;
    RecoveryTransition step(Operation operation, std::uint64_t now, std::uint64_t argument = 0);
};

const char* recovery_state_name(RecoveryState state) noexcept;
const char* recovery_reason_name(RecoveryReason reason) noexcept;

}
