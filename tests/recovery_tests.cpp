#include "recovery.hpp"
#include "observation.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {
using namespace scau;
using Time = std::uint64_t;

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void empty(const RecoveryActions& actions, const char* message) {
    require(actions.empty(), message);
}

void one(const RecoveryActions& actions, RecoveryActionKind kind, const char* message) {
    require(actions.size() == 1 && actions.front().kind == kind, message);
}

void wait_for(const RecoveryActions& actions, RecoveryReason reason, const char* message) {
    one(actions, RecoveryActionKind::Waiting, message);
    require(actions.front().reason == reason, message);
}

void deadline(const RecoveryController& controller, Time expected, const char* message) {
    require(controller.next_deadline_ms() == expected, message);
}

void establish(RecoveryController& controller, Time now = 0, Time reauth = 0) {
    one(controller.start(now, true), RecoveryActionKind::BeginExchange, "Initial start must begin one exchange");
    empty(controller.request(now + 1, true), "Request only changes policy; runtime sends the response");
    one(controller.success(now + 2, reauth), RecoveryActionKind::Connected, "A matched Success confirms the exchange");
}

void test_start_period_and_no_server() {
    RecoveryController controller;
    one(controller.start(100, true), RecoveryActionKind::BeginExchange, "Start must be sent immediately");
    require(!controller.connected() && controller.start_attempts() == 1, "Start does not establish connectivity");
    empty(controller.start(200, true), "Repeated start must not reset an active exchange");
    deadline(controller, 3100, "First retry is three seconds after the actual Start");
    empty(controller.tick(3099, 0), "No early Start retry");
    one(controller.tick(3100, 0), RecoveryActionKind::RetryStart, "Second Start is due");
    require(controller.start_attempts() == 2, "Second Start count");
    one(controller.tick(6100, 0), RecoveryActionKind::RetryStart, "Third Start is due");
    require(controller.start_attempts() == 3, "Exactly three Starts per cycle");
    wait_for(controller.tick(9100, 7), RecoveryReason::NoServerResponse, "No response enters jittered wait");
    deadline(controller, 26100, "No-server jitter seven means seventeen seconds");
    require(controller.backoff_attempts() == 0, "No-server wait never consumes failure backoff");
    empty(controller.tick(26099, 0), "No premature no-server restart");
    one(controller.tick(26100, 0), RecoveryActionKind::BeginExchange, "Jitter expiry begins a fresh Start cycle");
    require(controller.exchange_generation() == 2 && controller.start_attempts() == 1, "Fresh cycle has fresh count/generation");
    one(controller.tick(29100, 0), RecoveryActionKind::RetryStart, "Second cycle second Start");
    one(controller.tick(32100, 0), RecoveryActionKind::RetryStart, "Second cycle third Start");
    wait_for(controller.tick(35100, 500), RecoveryReason::NoServerResponse, "Out-of-range jitter is bounded");
    deadline(controller, 64100, "Jitter is clamped to nineteen, not allowed to overflow");

    // A late authenticator reply during the no-server wait is still useful.
    empty(controller.request(36000, false), "Identity reply may arrive while waiting for a server");
    require(controller.state() == RecoveryState::Authenticating, "Late valid reply cancels no-server waiting");
    deadline(controller, 45000, "Late server reply gets a bounded response phase");
}

void test_response_deadline_and_backoff_limit() {
    RecoveryController controller;
    controller.start(0, true);
    controller.request(1000, false);
    deadline(controller, 10000, "Identity begins nine-second pending window");
    empty(controller.request(8000, false), "Duplicate Identity has no extra actions");
    empty(controller.request(9500, false), "Another Identity cannot postpone the same phase");
    require(!controller.md5_seen(), "An unanswered Identity phase has not reached MD5");
    deadline(controller, 10000, "Repeated Identity never postpones Identity expiry");
    wait_for(controller.tick(10000, 0), RecoveryReason::TransientFailure, "Response timeout schedules first backoff");
    require(controller.backoff_attempts() == 1, "First bounded retry consumed");
    deadline(controller, 11000, "First backoff is one second");
    empty(controller.failure(10500, false), "Duplicate failure during backoff must not consume retries");
    deadline(controller, 11000, "Duplicate failure must not extend backoff");
    one(controller.tick(11000, 0), RecoveryActionKind::BeginExchange, "First retry starts at deadline");
    wait_for(controller.failure(12000, false), RecoveryReason::TransientFailure, "Second failure schedules backoff");
    deadline(controller, 14000, "Second backoff is two seconds");
    one(controller.tick(14000, 0), RecoveryActionKind::BeginExchange, "Second retry begins");
    wait_for(controller.failure(15000, false), RecoveryReason::TransientFailure, "Third failure schedules backoff");
    deadline(controller, 19000, "Third backoff is four seconds");
    one(controller.tick(19000, 0), RecoveryActionKind::BeginExchange, "Third and last retry begins");
    one(controller.failure(20000, false), RecoveryActionKind::Rejected, "Fourth transient failure must stop automatic retries");
    require(controller.reason() == RecoveryReason::RetryExhausted && controller.backoff_attempts() == 3,
            "Exhaustion is distinct from explicit account rejection");
    empty(controller.tick(8 * 60 * 60 * 1000ULL, 0), "Exhaustion stays quiet even after hours");
}

void test_identity_and_md5_have_bounded_separate_windows() {
    RecoveryController progressed;
    progressed.start(0, true);
    progressed.request(100, false);
    deadline(progressed, 9100, "Identity gets its first nine seconds");
    empty(progressed.request(8100, true), "First MD5 may progress after eight seconds of Identity");
    deadline(progressed, 17100, "First MD5 receives a separate nine-second window");
    one(progressed.success(10100, 0), RecoveryActionKind::Connected,
        "Success after the old Identity deadline remains valid during the MD5 phase");

    RecoveryController bounded;
    bounded.start(1000, true);
    bounded.request(1001, false);
    bounded.request(9999, false);
    deadline(bounded, 10001, "Different Identity requests still cannot extend their phase");
    bounded.request(10000, true);
    deadline(bounded, 19000, "Last-moment MD5 receives nine seconds exactly once");
    require(*bounded.next_deadline_ms() <= 1001 + 18000,
            "Two phases together must never exceed eighteen seconds from first Identity");
    for (Time now = 10500; now < 19000; now += 500) {
        empty(bounded.request(now, now % 1000 == 0),
              "Repeated MD5 and regressive Identity only reuse the current phase");
        deadline(bounded, 19000, "Requests after first MD5 cannot create a third window");
    }
    empty(bounded.tick(18999, 0), "MD5 has its full window before timeout");
    wait_for(bounded.tick(19000, 0), RecoveryReason::TransientFailure,
             "Total pending time stays below eighteen seconds even under request flood");

    RecoveryController expired_identity;
    expired_identity.start(0, true);
    expired_identity.request(1000, false);
    wait_for(expired_identity.request(10000, true), RecoveryReason::TransientFailure,
             "MD5 at an expired Identity deadline cannot revive the exchange before tick");
    require(expired_identity.state() == RecoveryState::TransientBackoff && !expired_identity.md5_seen(),
            "Expired Identity must clear phase state and schedule bounded recovery");
    empty(expired_identity.success(10001, 0), "Late Success cannot bypass expired Identity recovery");
    empty(expired_identity.request(10002, true), "Further MD5 cannot bypass the queued backoff");
    deadline(expired_identity, 11000, "Late challenges cannot alter timeout backoff");

    RecoveryController direct_md5;
    direct_md5.start(0, true);
    direct_md5.request(1000, true);
    direct_md5.request(2000, false);
    direct_md5.request(9000, true);
    deadline(direct_md5, 10000, "Direct MD5 plus regressive Identity cannot gain a second window");
    wait_for(direct_md5.tick(10000, 0), RecoveryReason::TransientFailure,
             "Direct MD5 expires after nine seconds");

    RecoveryController online;
    establish(online);
    require(online.md5_seen(), "Previous successful exchange completed MD5");
    online.request(1000, false);
    require(!online.md5_seen() && online.connected() && online.reauth_pending(),
            "Online Identity resets this round's phase marker while retaining the authenticated lease");
    deadline(online, 10000, "Online reauth begins a fresh Identity window");
    online.request(9000, true);
    deadline(online, 18000, "Online MD5 gets a fresh window despite prior successful MD5");
    one(online.success(11000, 0), RecoveryActionKind::Connected,
        "Success to a new online MD5 remains valid past this round's Identity deadline");
    require(online.connected() && !online.reauth_pending() && online.successful_exchanges() == 2,
            "Online phase progression confirms exactly one new successful exchange");
    empty(online.success(12000, 1), "Duplicate Success after two-phase reauth remains ignored");
    require(online.successful_exchanges() == 2 && !online.next_deadline_ms(),
            "Duplicate Success cannot add a new periodic deadline or success count");
}

void test_explicit_rejection() {
    RecoveryController controller;
    controller.start(0, true);
    controller.request(1, true);
    one(controller.failure(2, true), RecoveryActionKind::Rejected, "Server reason must stop authentication retries");
    require(controller.reason() == RecoveryReason::ServerRejected && !controller.connected(), "Rejection clears the lease");
    require(!controller.next_deadline_ms() && controller.backoff_attempts() == 0, "Rejection queues no retry");
    empty(controller.link_changed(10, false), "Link changes cannot revive a rejected account");
    empty(controller.link_changed(20, true), "Link up cannot revive a rejected account");
    empty(controller.suspend(30), "Suspend cannot hide a terminal rejection");
    empty(controller.resume(40), "Resume cannot revive a rejected account");
    empty(controller.success(50, 1000), "Late Success after rejection is ignored");
    empty(controller.transport_error(60), "Transport recovery cannot revive rejection");
    empty(controller.tick(100000, 0), "Rejected account never enters no-server retry");
    one(controller.start(100001, true), RecoveryActionKind::BeginExchange, "A deliberate new start may retry after rejection");

    RecoveryController late_reason;
    late_reason.start(0, true);
    late_reason.request(1, true);
    late_reason.tick(9001, 0);
    one(late_reason.failure(9002, true), RecoveryActionKind::Rejected, "Late authoritative reason cancels queued timeout retry");
    empty(late_reason.tick(10001, 0), "Late rejection cannot leave a stale retry armed");
}

void test_success_resets_and_duplicate_success() {
    RecoveryController controller;
    controller.start(0, true);
    controller.failure(1, false);
    controller.tick(1001, 0);
    controller.failure(1002, false);
    controller.tick(3002, 0);
    require(controller.backoff_attempts() == 2, "Backoff persists across BeginExchange");
    controller.request(3003, true);
    one(controller.success(3004, 60000), RecoveryActionKind::Connected, "Valid Success confirms connectivity");
    require(controller.backoff_attempts() == 0 && controller.successful_exchanges() == 1,
            "Success resets failure budget and increments once");
    deadline(controller, 63004, "Periodic reauth is anchored to first valid Success");
    empty(controller.success(5000, 1), "Duplicate Success has no action");
    require(controller.successful_exchanges() == 1 && controller.reauth_interval_ms() == 60000,
            "Duplicate Success cannot change counters or server maintenance interval");
    deadline(controller, 63004, "Duplicate Success cannot postpone or accelerate reauth");
    wait_for(controller.failure(6000, false), RecoveryReason::TransientFailure, "Failure after Success has renewed retry budget");
    deadline(controller, 7000, "First post-Success retry is one second again");
}

void test_periodic_and_requested_reauth_keep_lease() {
    RecoveryController controller;
    establish(controller, 0, 60000);
    empty(controller.tick(60001, 0), "Periodic reauth waits for its full interval");
    const auto periodic = controller.tick(60002, 0);
    one(periodic, RecoveryActionKind::BeginExchange, "Periodic reauth sends Start with fresh exchange state");
    require(periodic.front().reason == RecoveryReason::PeriodicReauth, "Periodic action is identifiable");
    require(controller.connected() && controller.reauth_pending(), "Periodic Start retains existing authenticated lease");
    controller.request(60003, false);
    controller.request(68000, true);
    deadline(controller, 77000, "Periodic MD5 progresses to its separate nine-second window");
    require(controller.connected(), "Normal challenge handling cannot break continuous online observation");
    one(controller.success(68001, 0), RecoveryActionKind::Connected, "Success completes pending periodic reauth");
    require(controller.connected() && !controller.reauth_pending() && !controller.next_deadline_ms(),
            "A fresh zero interval disables periodic reauth");

    controller.request(70000, false);
    require(controller.connected() && controller.reauth_pending(), "Server-requested Identity retains confirmed lease");
    deadline(controller, 79000, "Server-requested reauth gets its own pending deadline");
    controller.request(78999, true);
    deadline(controller, 87999, "First MD5 before Identity expiry receives one new window");
    controller.request(80000, true);
    controller.request(87000, false);
    deadline(controller, 87999, "Duplicate MD5 and later Identity cannot extend online reauth again");
    wait_for(controller.tick(87999, 0), RecoveryReason::TransientFailure, "Pending reauth timeout must clear the lease");
    require(!controller.connected() && !controller.reauth_pending(), "Timeout ends confirmed online state");

    RecoveryController late_success;
    establish(late_success);
    late_success.request(100, true);
    wait_for(late_success.success(9100, 0), RecoveryReason::TransientFailure,
             "Late Success cannot win over an already expired pending deadline");
    require(!late_success.connected(), "An expired lease cannot be silently renewed by a late packet");

    RecoveryController unanswered_periodic;
    establish(unanswered_periodic, 0, 1000);
    unanswered_periodic.tick(1002, 0);
    require(unanswered_periodic.connected(), "Sending periodic Start alone preserves the prior lease");
    unanswered_periodic.tick(4002, 0);
    unanswered_periodic.tick(7002, 0);
    wait_for(unanswered_periodic.tick(10002, 0), RecoveryReason::NoServerResponse,
             "A wholly unanswered periodic Start cycle becomes a no-server wait");
    require(!unanswered_periodic.connected() && !unanswered_periodic.reauth_pending(),
            "No-server timeout cannot leave a stale confirmed lease active forever");

    RecoveryController duplicate_at_deadline;
    establish(duplicate_at_deadline);
    duplicate_at_deadline.request(100, true);
    wait_for(duplicate_at_deadline.request(9100, true), RecoveryReason::TransientFailure,
             "Duplicate packet processing also enforces the deadline before tick");
}

void test_link_debounce_and_reopen_handshake() {
    RecoveryController controller;
    wait_for(controller.start(0, false), RecoveryReason::LinkDown, "Missing selected link waits without packets");
    empty(controller.tick(100000, 0), "Link-down wait has no auto-retry timer");
    wait_for(controller.link_changed(100001, true), RecoveryReason::LinkDebounce, "Link restoration is debounced");
    deadline(controller, 103001, "Link up waits three seconds");
    empty(controller.link_changed(102999, true), "Repeated up notification does not postpone readiness");
    deadline(controller, 103001, "Debounce deadline is stable");
    empty(controller.tick(103000, 0), "No early transport reopen");
    one(controller.tick(103001, 0), RecoveryActionKind::ReopenTransport, "Reopen selected transport before sending Start");
    require(controller.start_attempts() == 0, "No authentication packet before transport-ready callback");
    one(controller.transport_ready(103002), RecoveryActionKind::BeginExchange, "Successful reopen continues with Start");
    empty(controller.transport_ready(103003), "Repeated reopen completion must not resend Start");
    wait_for(controller.link_changed(103004, false), RecoveryReason::LinkDown, "Link loss cancels exchange");
    empty(controller.success(103005, 0), "Queued packet on a lost link cannot reconnect");
    empty(controller.transport_ready(103006), "Stale open completion cannot revive a lost link");
    wait_for(controller.link_changed(103007, true), RecoveryReason::LinkDebounce, "A new real up transition starts a new debounce");
    one(controller.tick(106007, 0), RecoveryActionKind::ReopenTransport, "Second link restoration reopens once");
    controller.link_changed(106008, false);
    empty(controller.transport_ready(106009), "Link loss during open prevents sending Start");
    require(controller.state() == RecoveryState::WaitingForLink && !controller.connected(), "Selected link remains the gate");
}

void test_suspend_resume_gates() {
    RecoveryController controller;
    establish(controller, 0, 10000);
    wait_for(controller.suspend(100), RecoveryReason::Suspended, "Suspend pauses all exchange timers");
    require(!controller.connected() && !controller.next_deadline_ms(), "Suspend clears the old authenticated session");
    empty(controller.suspend(200), "Repeated suspend is idempotent");
    empty(controller.tick(8 * 60 * 60 * 1000ULL, 0), "Hours suspended cannot trigger authentication");
    const Time wake = 8 * 60 * 60 * 1000ULL + 1;
    wait_for(controller.resume(wake), RecoveryReason::ResumeDelay, "Resume waits at least five seconds");
    deadline(controller, wake + 5000, "Resume delay is five seconds after actual wake event");
    empty(controller.resume(wake + 4999), "Duplicate resume does not postpone or bypass recovery");
    empty(controller.tick(wake + 4999, 0), "No early action on resume");
    one(controller.tick(wake + 5000, 0), RecoveryActionKind::ReopenTransport, "Resume reopens selected adapter after delay");
    one(controller.transport_ready(wake + 5001), RecoveryActionKind::BeginExchange, "Resume begins authentication only after reopen");

    RecoveryController no_link;
    establish(no_link);
    no_link.suspend(100);
    empty(no_link.link_changed(200, false), "Link event during suspend cannot wake authentication");
    wait_for(no_link.resume(1000), RecoveryReason::LinkDown, "Resume without ready link keeps waiting");
    empty(no_link.resume(2000), "Repeated resume while waiting for link is ignored");
    wait_for(no_link.link_changed(2001, true), RecoveryReason::LinkDebounce, "Link ready during resume still debounces");
    deadline(no_link, 6000, "Both the five-second wake gate and three-second link gate apply");
    empty(no_link.transport_error(5000), "Transport error must not bypass wake/link gates");
    one(no_link.tick(6000, 0), RecoveryActionKind::ReopenTransport, "Both gates allow exactly one reopen");

    RecoveryController suspended_up;
    suspended_up.start(0, false);
    suspended_up.suspend(100);
    suspended_up.link_changed(1000, true);
    suspended_up.resume(1100);
    deadline(suspended_up, 6100, "Up during sleep cannot skip resume settling delay");
}

void test_transport_backoff_and_missing_callback() {
    RecoveryController controller;
    controller.start(0, true);
    wait_for(controller.transport_error(1), RecoveryReason::TransportRetry, "Transport fault schedules a limited reopen");
    deadline(controller, 1001, "First transport retry waits one second");
    for (Time now = 2; now < 1001; ++now)
        empty(controller.transport_error(now), "Repeated read failures during wait must not spin or reset its clock");
    deadline(controller, 1001, "Transport error flood cannot delay a scheduled reopen");
    require(controller.transport_failures() == 1, "Error flood consumes only one retry step");
    one(controller.tick(1001, 0), RecoveryActionKind::ReopenTransport, "Fault retry emits one reopen action");
    empty(controller.tick(1001, 0), "Same-time tick cannot reopen repeatedly");
    empty(controller.tick(6000, 0), "Open callback gets a bounded response window");
    wait_for(controller.tick(6001, 0), RecoveryReason::TransportRetry, "Missing open callback schedules another limited attempt");
    deadline(controller, 8001, "Second transport retry waits two seconds");
    empty(controller.transport_ready(6002), "Late callback after timeout cannot skip backoff");

    Time now = 8001;
    Time expected_delay = 4000;
    for (unsigned iteration = 0; iteration < 8; ++iteration) {
        one(controller.tick(now, 0), RecoveryActionKind::ReopenTransport, "Each transport cycle reopens once");
        wait_for(controller.transport_error(now + 1), RecoveryReason::TransportRetry, "Synchronous reopen failure is rate limited");
        deadline(controller, now + 1 + expected_delay, "Transport backoff grows to thirty seconds and stays bounded");
        now += 1 + expected_delay;
        expected_delay = std::min<Time>(expected_delay * 2, 30000);
    }
    one(controller.tick(now, 0), RecoveryActionKind::ReopenTransport, "Transport may eventually recover");
    one(controller.transport_ready(now + 1), RecoveryActionKind::BeginExchange, "Open success emits one new exchange");
    require(controller.transport_failures() > 1, "Merely opening the handle must not reset a flapping transport budget");
    controller.request(now + 2, true);
    controller.success(now + 3, 0);
    require(controller.transport_failures() == 0, "Authenticated success resets transport backoff");
    controller.transport_error(now + 4);
    deadline(controller, now + 1004, "A new independent fault starts at one second again");

    RecoveryController late_callback;
    late_callback.start(0, true);
    late_callback.transport_error(1);
    late_callback.tick(1001, 0);
    wait_for(late_callback.transport_ready(6001), RecoveryReason::TransportRetry,
             "Late callback cannot beat the open deadline even if tick was delayed");
}

void test_late_scheduler_and_time_edges() {
    RecoveryController controller;
    controller.start(0, true);
    one(controller.tick(1000000, 0), RecoveryActionKind::RetryStart, "Delayed loop sends one retry, not a catch-up burst");
    require(controller.start_attempts() == 2, "Delayed tick increments count only once");
    deadline(controller, 1003000, "Next retry is anchored to its actual send time");
    empty(controller.tick(1000000, 0), "Repeated same-time tick is quiet");
    empty(controller.tick(900000, 0), "Backward clock input cannot cause early retries");
    controller.request(1000001, true);
    deadline(controller, 1009001, "Response phase replaces Start timer");
    empty(controller.tick(1003000, 0), "Obsolete Start deadline cannot emit RetryStart after a response");

    RecoveryController near_limit;
    const auto almost_max = std::numeric_limits<Time>::max() - 1000;
    near_limit.start(almost_max, true);
    require(!near_limit.next_deadline_ms(), "Unrepresentable deadline must not wrap into the past");
    empty(near_limit.tick(std::numeric_limits<Time>::max(), 19), "Time overflow cannot produce a busy retry loop");
    near_limit.request(almost_max, true);
    require(!near_limit.next_deadline_ms(), "Authentication deadline also avoids overflow");
}

void assert_stays_stopped(RecoveryController& controller, Time now) {
    one(controller.stop(now), RecoveryActionKind::Stopped, "Explicit stop emits its terminal action once");
    const auto generation = controller.exchange_generation();
    empty(controller.start(now + 1, true), "Start cannot revive a stopped instance");
    empty(controller.link_changed(now + 2, false), "Link down cannot revive stop");
    empty(controller.link_changed(now + 3, true), "Link up cannot revive stop");
    empty(controller.suspend(now + 4), "Suspend cannot hide stop");
    empty(controller.resume(now + 5), "Resume cannot revive stop");
    empty(controller.request(now + 6, false), "Identity cannot revive stop");
    empty(controller.request(now + 7, true), "MD5 cannot revive stop");
    empty(controller.success(now + 8, 1), "Success cannot revive stop");
    empty(controller.failure(now + 9, false), "Transient failure cannot revive stop");
    empty(controller.failure(now + 10, true), "Explicit rejection cannot replace stop");
    empty(controller.transport_error(now + 11), "Transport failure cannot revive stop");
    empty(controller.transport_ready(now + 12), "Open completion cannot revive stop");
    empty(controller.tick(now + 8 * 60 * 60 * 1000ULL, 19), "Hours of tick cannot revive stop");
    empty(controller.stop(now + 13), "Stop is idempotent");
    require(controller.state() == RecoveryState::Stopped && !controller.connected() &&
            !controller.next_deadline_ms() && controller.exchange_generation() == generation,
            "Stop must remain authoritative over every event source");
}

void test_stop_priority() {
    RecoveryController idle;
    assert_stays_stopped(idle, 0);
    RecoveryController connecting;
    connecting.start(0, true);
    assert_stays_stopped(connecting, 1);
    RecoveryController authenticated;
    establish(authenticated, 0, 1000);
    assert_stays_stopped(authenticated, 3);
    RecoveryController waiting;
    waiting.start(0, false);
    assert_stays_stopped(waiting, 1);
    RecoveryController suspended;
    establish(suspended);
    suspended.suspend(3);
    assert_stays_stopped(suspended, 4);
    RecoveryController opening;
    opening.start(0, true);
    opening.transport_error(1);
    opening.tick(1001, 0);
    assert_stays_stopped(opening, 1002);
    RecoveryController rejected;
    rejected.start(0, true);
    rejected.failure(1, true);
    assert_stays_stopped(rejected, 2);
}

void test_eight_hours_and_observation_does_not_stop_recovery() {
    RecoveryController stable;
    establish(stable);
    ObservationWindow stable_observation(1800);
    unsigned stable_reports = 0;
    for (unsigned second = 0; second <= 8 * 60 * 60; ++second) {
        empty(stable.tick(Time{second} * 1000, second % 20), "Zero periodic interval stays connected for eight hours");
        const auto result = stable_observation.advance(std::chrono::seconds(second));
        stable_reports += result.report_result ? 1 : 0;
        require(!result.disconnect && stable.connected() && !stable.stopped(),
                "Observation reporting cannot become a session lifetime limit");
    }
    require(stable_reports == 1 && stable.successful_exchanges() == 1, "Stable observation reports once without duplicate Success");

    RecoveryController reconnecting;
    establish(reconnecting);
    ObservationWindow observation(1800);
    unsigned reports = 0;
    unsigned reopen_count = 0;
    constexpr unsigned last_second = 8 * 60 * 60;
    for (unsigned second = 0; second <= last_second; ++second) {
        const auto now = Time{second} * 1000;
        if (second && second < last_second && second % 600 == 0)
            wait_for(reconnecting.link_changed(now, false), RecoveryReason::LinkDown, "Repeated long-run link loss waits");
        if (second > 1 && second % 600 == 1)
            wait_for(reconnecting.link_changed(now, true), RecoveryReason::LinkDebounce, "Repeated long-run link restoration debounces");
        const auto actions = reconnecting.tick(now, second % 20);
        if (!actions.empty()) {
            one(actions, RecoveryActionKind::ReopenTransport, "Long-run restoration must reopen once per loss");
            ++reopen_count;
            one(reconnecting.transport_ready(now), RecoveryActionKind::BeginExchange, "Reopen completion starts a new exchange");
            reconnecting.request(now, true);
            one(reconnecting.success(now + 1, 0), RecoveryActionKind::Connected, "Reauthentication continues after observation completion");
        }
        const auto result = observation.advance(std::chrono::seconds(second));
        reports += result.report_result ? 1 : 0;
        require(!result.disconnect && !reconnecting.stopped(), "Completed observation must not stop subsequent reconnects");
    }
    require(reports == 1 && reopen_count == 47 && reconnecting.successful_exchanges() == 48 && reconnecting.connected(),
            "Eight hours and forty-seven reconnects must finish with an active confirmed lease");

    RecoveryController no_server;
    no_server.start(0, true);
    for (unsigned second = 1; second <= last_second; ++second) {
        const auto actions = no_server.tick(Time{second} * 1000, second % 20);
        for (const auto& action : actions)
            require(action.kind == RecoveryActionKind::RetryStart || action.kind == RecoveryActionKind::BeginExchange ||
                    (action.kind == RecoveryActionKind::Waiting && action.reason == RecoveryReason::NoServerResponse),
                    "No-server cycles never manufacture Connected or consume transient failure policy");
        require(!no_server.stopped() && no_server.backoff_attempts() == 0 && no_server.start_attempts() <= 3,
                "No-server retry survives eight hours with bounded per-cycle Starts");
    }
    require(no_server.exchange_generation() > 700 && no_server.no_server_waits() > 700,
            "No hidden overall timeout may stop sustained no-server retries");

    RecoveryController periodic;
    establish(periodic, 0, 60000);
    for (unsigned second = 1; second <= last_second; ++second) {
        const auto now = Time{second} * 1000;
        const auto actions = periodic.tick(now, 0);
        if (!actions.empty()) {
            one(actions, RecoveryActionKind::BeginExchange, "Long-running periodic reauth begins one exchange");
            require(periodic.connected(), "Periodic Start must not reset continuous observation lease");
            periodic.request(now, true);
            require(periodic.connected(), "Periodic MD5 must not reset continuous observation lease");
            periodic.success(now + 1, 60000);
        }
        require(periodic.connected() && !periodic.stopped(), "Eight hours of periodic reauth remains online");
    }
    require(periodic.successful_exchanges() > 400, "Periodic reauth does not stop at observation duration");
}

}

int main() {
    try {
        test_start_period_and_no_server();
        test_response_deadline_and_backoff_limit();
        test_identity_and_md5_have_bounded_separate_windows();
        test_explicit_rejection();
        test_success_resets_and_duplicate_success();
        test_periodic_and_requested_reauth_keep_lease();
        test_link_debounce_and_reopen_handshake();
        test_suspend_resume_gates();
        test_transport_backoff_and_missing_callback();
        test_late_scheduler_and_time_edges();
        test_stop_priority();
        for(unsigned scenario=0;scenario<6;++scenario) {
            RecoveryController terminated;
            establish(terminated,0,60000);
            switch(scenario) {
            case 0:break;
            case 1:terminated.link_changed(100,false);break;
            case 2:terminated.suspend(100);break;
            case 3:terminated.transport_error(100);break;
            case 4:terminated.suspend(100);terminated.resume(200);break;
            case 5:terminated.request(100,true);break;
            }
            one(terminated.server_terminated(300),RecoveryActionKind::Rejected,
                "Authenticated SAM termination must survive link, power, transport and reauth transitions");
            require(!terminated.connected() && terminated.state()==RecoveryState::Rejected &&
                    terminated.reason()==RecoveryReason::ServerRejected && terminated.tick(100000,0).empty(),
                "A confirmed server termination must never schedule automatic login");
        }
        RecoveryController manually_stopped;
        establish(manually_stopped,0,0);manually_stopped.stop(100);
        require(manually_stopped.server_terminated(200).empty() && manually_stopped.stopped(),
            "Manual stop must retain priority over a late SAM termination");
        test_eight_hours_and_observation_does_not_stop_recovery();
        std::cout << "PASS: recovery fake-clock policies; bounded rejection retries; link/power/transport gates; "
                     "fixed reauth deadline; permanent stop; eight-hour retained sessions and reconnects\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
