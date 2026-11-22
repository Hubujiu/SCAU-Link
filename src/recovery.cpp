#include "recovery.hpp"

#include <cstddef>

namespace scau {
extern "C" RecoveryRustState* scau_recovery_create();
extern "C" void scau_recovery_destroy(RecoveryRustState*);
extern "C" void scau_recovery_step(RecoveryRustState*, std::uint8_t, std::uint64_t, std::uint64_t,
                                   RecoverySnapshot*);

static_assert(sizeof(RecoverySnapshot) == 64);
static_assert(offsetof(RecoverySnapshot, state) == 52);

RecoveryController::RecoveryController() : rust_(scau_recovery_create()) {}
RecoveryController::~RecoveryController() { scau_recovery_destroy(rust_); }

RecoveryTransition RecoveryController::step(Operation operation, std::uint64_t now, std::uint64_t argument) {
    scau_recovery_step(rust_, static_cast<std::uint8_t>(operation), now, argument, &snapshot_);
    if (!snapshot_.action) return {};
    const auto kind = static_cast<RecoveryActionKind>(snapshot_.action - 1);
    return RecoveryAction{kind, kind == RecoveryActionKind::RetryStart ? RecoveryReason::None : reason(), next_deadline_ms()};
}

RecoveryTransition RecoveryController::start(std::uint64_t now, bool up) {
    return step(Operation::Start, now, up);
}
RecoveryTransition RecoveryController::link_changed(std::uint64_t now, bool up) {
    return step(Operation::LinkChanged, now, up);
}
RecoveryTransition RecoveryController::suspend(std::uint64_t now) {
    return step(Operation::Suspend, now);
}
RecoveryTransition RecoveryController::resume(std::uint64_t now) {
    return step(Operation::Resume, now);
}
RecoveryTransition RecoveryController::request(std::uint64_t now, bool md5) {
    return step(Operation::Request, now, md5);
}
RecoveryTransition RecoveryController::success(std::uint64_t now, std::uint64_t interval) {
    return step(Operation::Success, now, interval);
}
RecoveryTransition RecoveryController::failure(std::uint64_t now, bool has_reason) {
    return step(Operation::Failure, now, has_reason);
}
RecoveryTransition RecoveryController::server_terminated(std::uint64_t now) {
    return step(Operation::ServerTerminated, now);
}
RecoveryTransition RecoveryController::transport_error(std::uint64_t now) {
    return step(Operation::TransportError, now);
}
RecoveryTransition RecoveryController::transport_ready(std::uint64_t now) {
    return step(Operation::TransportReady, now);
}
RecoveryTransition RecoveryController::tick(std::uint64_t now, unsigned jitter) {
    return step(Operation::Tick, now, jitter);
}
RecoveryTransition RecoveryController::stop(std::uint64_t now) {
    return step(Operation::Stop, now);
}

const char* recovery_state_name(RecoveryState state) noexcept {
    switch (state) {
    case RecoveryState::Idle: return "idle";
    case RecoveryState::Connecting: return "connecting";
    case RecoveryState::Authenticating: return "authenticating";
    case RecoveryState::Connected: return "connected";
    case RecoveryState::NoServerWait: return "no-server-wait";
    case RecoveryState::TransientBackoff: return "transient-backoff";
    case RecoveryState::WaitingForLink: return "waiting-for-link";
    case RecoveryState::LinkDebounce: return "link-debounce";
    case RecoveryState::Suspended: return "suspended";
    case RecoveryState::ResumeDelay: return "resume-delay";
    case RecoveryState::TransportBackoff: return "transport-backoff";
    case RecoveryState::ReopeningTransport: return "reopening-transport";
    case RecoveryState::Rejected: return "rejected";
    case RecoveryState::Stopped: return "stopped";
    }
    return "unknown";
}

const char* recovery_reason_name(RecoveryReason reason) noexcept {
    switch (reason) {
    case RecoveryReason::None: return "none";
    case RecoveryReason::NoServerResponse: return "no-server-response";
    case RecoveryReason::TransientFailure: return "transient-failure";
    case RecoveryReason::LinkDown: return "link-down";
    case RecoveryReason::LinkDebounce: return "link-debounce";
    case RecoveryReason::Suspended: return "suspended";
    case RecoveryReason::ResumeDelay: return "resume-delay";
    case RecoveryReason::TransportRetry: return "transport-retry";
    case RecoveryReason::TransportPending: return "transport-pending";
    case RecoveryReason::ServerRejected: return "server-rejected";
    case RecoveryReason::RetryExhausted: return "retry-exhausted";
    case RecoveryReason::PeriodicReauth: return "periodic-reauth";
    }
    return "unknown";
}

}
