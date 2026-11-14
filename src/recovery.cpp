#include "recovery.hpp"

#include <algorithm>
#include <limits>

namespace scau {
namespace {

// An unrepresentable deadline waits for an external event instead of wrapping
// into the past and repeatedly producing immediate actions at UINT64_MAX.
std::optional<std::uint64_t> after(std::uint64_t now, std::uint64_t delay) noexcept {
    if (delay > std::numeric_limits<std::uint64_t>::max() - now) return {};
    return now + delay;
}

void increment(std::uint64_t& value) noexcept {
    if (value != std::numeric_limits<std::uint64_t>::max()) ++value;
}

std::optional<std::uint64_t> later(std::optional<std::uint64_t> first,
                                 std::optional<std::uint64_t> second) noexcept {
    // Missing here means the requested delay cannot be represented.
    if (!first || !second) return {};
    return std::max(*first, *second);
}

}

std::uint64_t RecoveryController::observe_time(std::uint64_t now) noexcept {
    last_now_ = std::max(last_now_, now);
    return last_now_;
}

bool RecoveryController::terminal() const noexcept {
    return state_ == RecoveryState::Stopped || state_ == RecoveryState::Rejected;
}

bool RecoveryController::accepts_packet() const noexcept {
    return state_ == RecoveryState::Connecting || state_ == RecoveryState::Authenticating ||
           state_ == RecoveryState::Connected || state_ == RecoveryState::NoServerWait;
}

void RecoveryController::clear_session() noexcept {
    connected_ = false;
    reauth_pending_ = false;
    reauth_interval_ms_ = 0;
    md5_seen_ = false;
    start_attempts_ = 0;
    deadline_.reset();
}

RecoveryActions RecoveryController::wait(RecoveryState state, RecoveryReason reason,
                                         std::optional<std::uint64_t> deadline) {
    state_ = state;
    reason_ = reason;
    deadline_ = deadline;
    return {{RecoveryActionKind::Waiting, reason_, deadline_}};
}

RecoveryActions RecoveryController::begin_exchange(std::uint64_t now, RecoveryReason reason) {
    const bool existing_lease = connected_;
    clear_session();
    connected_ = existing_lease;
    reauth_pending_ = existing_lease || reason == RecoveryReason::PeriodicReauth;
    state_ = RecoveryState::Connecting;
    reason_ = reason;
    start_attempts_ = 1;
    deadline_ = after(now, start_period_ms);
    increment(generation_);
    return {{RecoveryActionKind::BeginExchange, reason_, deadline_}};
}

RecoveryActions RecoveryController::reopen_transport(std::uint64_t now) {
    clear_session();
    state_ = RecoveryState::ReopeningTransport;
    reason_ = RecoveryReason::TransportPending;
    deadline_ = after(now, transport_open_timeout_ms);
    return {{RecoveryActionKind::ReopenTransport, reason_, deadline_}};
}

RecoveryActions RecoveryController::reject(RecoveryReason reason) {
    clear_session();
    state_ = RecoveryState::Rejected;
    reason_ = reason;
    return {{RecoveryActionKind::Rejected, reason_, {}}};
}

RecoveryActions RecoveryController::transient_failure(std::uint64_t now) {
    clear_session();
    if (backoff_attempts_ >= max_backoff_attempts) return reject(RecoveryReason::RetryExhausted);
    const auto delay = std::uint64_t{1000} << backoff_attempts_;
    ++backoff_attempts_;
    return wait(RecoveryState::TransientBackoff, RecoveryReason::TransientFailure, after(now, delay));
}

RecoveryActions RecoveryController::schedule_transport_retry(std::uint64_t now) {
    clear_session();
    reopen_needed_ = true;
    // Do not reset this counter merely because an open succeeded. A handle that
    // repeatedly opens and fails before authentication must also be rate limited.
    const auto shift = std::min(transport_failures_, 5u);
    const auto delay = std::min(std::uint64_t{1000} << shift, max_transport_backoff_ms);
    if (transport_failures_ != std::numeric_limits<unsigned>::max()) ++transport_failures_;
    return wait(RecoveryState::TransportBackoff, RecoveryReason::TransportRetry, after(now, delay));
}

RecoveryActions RecoveryController::start(std::uint64_t now, bool link_up) {
    if (stopped()) return {};
    now = observe_time(now);
    // start() is a deliberate new attempt after rejection, not a timer reset
    // that a caller may accidentally invoke every iteration of its event loop.
    if (started_ && state_ != RecoveryState::Rejected) return {};
    started_ = true;
    link_up_ = link_up;
    backoff_attempts_ = 0;
    transport_failures_ = 0;
    resume_not_before_.reset();
    link_ready_at_.reset();
    reopen_needed_ = !link_up;
    clear_session();
    if (!link_up) return wait(RecoveryState::WaitingForLink, RecoveryReason::LinkDown);
    // The initial caller has already opened its selected transport. Subsequent
    // link and suspend recovery explicitly asks it to reopen that same adapter.
    return begin_exchange(now);
}

RecoveryActions RecoveryController::link_changed(std::uint64_t now, bool link_up) {
    if (stopped()) return {};
    now = observe_time(now);
    if (link_up_ == link_up) return {};
    link_up_ = link_up;
    if (!started_ || terminal()) return {};
    reopen_needed_ = true;
    if (!link_up) {
        link_ready_at_.reset();
        clear_session();
        if (state_ == RecoveryState::Suspended) return {};
        return wait(RecoveryState::WaitingForLink, RecoveryReason::LinkDown);
    }
    link_ready_at_ = after(now, link_debounce_ms);
    if (state_ == RecoveryState::Suspended) return {};
    auto ready = link_ready_at_;
    if (resume_not_before_) ready = later(ready, resume_not_before_);
    return wait(RecoveryState::LinkDebounce, RecoveryReason::LinkDebounce, ready);
}

RecoveryActions RecoveryController::suspend(std::uint64_t now) {
    if (!started_ || terminal() || state_ == RecoveryState::Suspended) return {};
    observe_time(now);
    clear_session();
    reopen_needed_ = true;
    resume_not_before_.reset();
    return wait(RecoveryState::Suspended, RecoveryReason::Suspended);
}

RecoveryActions RecoveryController::resume(std::uint64_t now) {
    if (state_ != RecoveryState::Suspended) return {};
    now = observe_time(now);
    resume_not_before_ = after(now, resume_delay_ms);
    if (!link_up_) return wait(RecoveryState::WaitingForLink, RecoveryReason::LinkDown);
    auto ready = resume_not_before_;
    if (link_ready_at_) ready = later(ready, link_ready_at_);
    return wait(RecoveryState::ResumeDelay, RecoveryReason::ResumeDelay, ready);
}

RecoveryActions RecoveryController::request(std::uint64_t now, bool md5) {
    if (!accepts_packet() || !link_up_) return {};
    now = observe_time(now);
    if (state_ == RecoveryState::Authenticating && deadline_ && now >= *deadline_)
        return transient_failure(now);
    if (state_ == RecoveryState::Authenticating) {
        // Only forward progress from Identity to the first validated MD5 may
        // start another nine-second phase. Duplicates, changed identifiers,
        // and a later Identity cannot move this deadline again. The expiry
        // check above prevents MD5 from reviving an expired Identity phase.
        if (md5 && !md5_seen_) {
            md5_seen_ = true;
            deadline_ = after(now, response_timeout_ms);
        }
        return {};
    }
    // A server-requested reauth starts a new phase even when the previous
    // authenticated exchange already completed MD5.
    md5_seen_ = md5;
    reauth_pending_ = reauth_pending_ || connected_;
    state_ = RecoveryState::Authenticating;
    reason_ = RecoveryReason::None;
    // Identity and MD5 each get nine seconds once; direct MD5 gets only its
    // own nine seconds. Forward progress must occur before Identity expires,
    // so the total pending window cannot exceed eighteen seconds.
    deadline_ = after(now, response_timeout_ms);
    return {};
}

RecoveryActions RecoveryController::success(std::uint64_t now, std::uint64_t reauth_interval_ms) {
    if (!accepts_packet() || state_ == RecoveryState::Connected || !link_up_) return {};
    now = observe_time(now);
    if (state_ == RecoveryState::Authenticating && deadline_ && now >= *deadline_)
        return transient_failure(now);
    state_ = RecoveryState::Connected;
    reason_ = RecoveryReason::None;
    connected_ = true;
    reauth_pending_ = false;
    backoff_attempts_ = 0;
    transport_failures_ = 0;
    reauth_interval_ms_ = reauth_interval_ms;
    deadline_ = reauth_interval_ms ? after(now, reauth_interval_ms) : std::nullopt;
    resume_not_before_.reset();
    link_ready_at_.reset();
    increment(successful_exchanges_);
    return {{RecoveryActionKind::Connected, reason_, deadline_}};
}

RecoveryActions RecoveryController::failure(std::uint64_t now, bool has_reason) {
    // A reason arriving just after our response timeout still cancels the
    // queued transient retry; the caller validates packet peer/generation.
    if ((!accepts_packet() && !(has_reason && state_ == RecoveryState::TransientBackoff)) ||
        !link_up_) return {};
    now = observe_time(now);
    if (has_reason) return reject(RecoveryReason::ServerRejected);
    return transient_failure(now);
}

RecoveryActions RecoveryController::transport_error(std::uint64_t now) {
    if (!started_ || terminal() || state_ == RecoveryState::Suspended) return {};
    now = observe_time(now);
    reopen_needed_ = true;
    // Keep link/resume gates and an already scheduled retry deadline intact.
    if (!link_up_ || state_ == RecoveryState::WaitingForLink ||
        state_ == RecoveryState::LinkDebounce || state_ == RecoveryState::ResumeDelay ||
        state_ == RecoveryState::TransportBackoff) return {};
    return schedule_transport_retry(now);
}

RecoveryActions RecoveryController::server_terminated(std::uint64_t now) {
    if(!started_ || terminal())return {};
    observe_time(now);
    return reject(RecoveryReason::ServerRejected);
}

RecoveryActions RecoveryController::transport_ready(std::uint64_t now) {
    if (state_ != RecoveryState::ReopeningTransport || !link_up_) return {};
    now = observe_time(now);
    if (deadline_ && now >= *deadline_) return schedule_transport_retry(now);
    reopen_needed_ = false;
    return begin_exchange(now);
}

RecoveryActions RecoveryController::tick(std::uint64_t now, unsigned jitter_0_19) {
    if (!started_ || terminal() || state_ == RecoveryState::Suspended) return {};
    now = observe_time(now);
    if (!deadline_ || now < *deadline_) return {};
    // At most one output-producing transition per call. A delayed scheduler
    // never catches up by sending several Start packets in a burst.
    switch (state_) {
    case RecoveryState::Connecting:
        if (start_attempts_ < max_start_attempts) {
            ++start_attempts_;
            deadline_ = after(now, start_period_ms);
            return {{RecoveryActionKind::RetryStart, RecoveryReason::None, deadline_}};
        }
        // A normal reauth preserves the existing lease while awaiting replies;
        // a complete unanswered Start cycle is a timeout, not renewed evidence
        // of connectivity. Continue the no-server retry without that lease.
        connected_ = false;
        reauth_pending_ = false;
        reauth_interval_ms_ = 0;
        increment(no_server_waits_);
        return wait(RecoveryState::NoServerWait, RecoveryReason::NoServerResponse,
                    after(now, 10000 + std::uint64_t{1000} * std::min(jitter_0_19, 19u)));
    case RecoveryState::Authenticating:
        return transient_failure(now);
    case RecoveryState::Connected:
        return begin_exchange(now, RecoveryReason::PeriodicReauth);
    case RecoveryState::NoServerWait:
    case RecoveryState::TransientBackoff:
        return begin_exchange(now);
    case RecoveryState::LinkDebounce:
    case RecoveryState::ResumeDelay:
        if (!link_up_) return wait(RecoveryState::WaitingForLink, RecoveryReason::LinkDown);
        resume_not_before_.reset();
        link_ready_at_.reset();
        return reopen_needed_ ? reopen_transport(now) : begin_exchange(now);
    case RecoveryState::TransportBackoff:
        return reopen_transport(now);
    case RecoveryState::ReopeningTransport:
        return schedule_transport_retry(now);
    default:
        return {};
    }
}

RecoveryActions RecoveryController::stop(std::uint64_t now) {
    if (stopped()) return {};
    observe_time(now);
    clear_session();
    state_ = RecoveryState::Stopped;
    reason_ = RecoveryReason::None;
    link_ready_at_.reset();
    resume_not_before_.reset();
    return {{RecoveryActionKind::Stopped, reason_, {}}};
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
