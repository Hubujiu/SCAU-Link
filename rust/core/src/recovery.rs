#[repr(u8)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum State {
    #[default]
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
    Stopped,
}

#[repr(u8)]
#[derive(Clone, Copy, Default)]
enum Reason {
    #[default]
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
    PeriodicReauth,
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum Action {
    None,
    BeginExchange,
    RetryStart,
    ReopenTransport,
    Connected,
    Rejected,
    Waiting,
    Stopped,
}

#[derive(Default)]
pub struct Recovery {
    state: State,
    reason: Reason,
    deadline: Option<u64>,
    link_ready_at: Option<u64>,
    resume_not_before: Option<u64>,
    last_now: u64,
    generation: u64,
    no_server_waits: u64,
    successful_exchanges: u64,
    reauth_interval: u64,
    start_attempts: u32,
    backoff_attempts: u32,
    transport_failures: u32,
    started: bool,
    link_up: bool,
    connected: bool,
    reauth_pending: bool,
    md5_seen: bool,
    reopen_needed: bool,
}

const START_PERIOD: u64 = 3000;
const RESPONSE_TIMEOUT: u64 = 9000;

impl Recovery {
    fn observe_time(&mut self, now: u64) -> u64 {
        self.last_now = self.last_now.max(now);
        self.last_now
    }

    fn terminal(&self) -> bool {
        matches!(self.state, State::Stopped | State::Rejected)
    }

    fn accepts_packet(&self) -> bool {
        matches!(
            self.state,
            State::Connecting | State::Authenticating | State::Connected | State::NoServerWait
        )
    }

    fn clear_session(&mut self) {
        self.connected = false;
        self.reauth_pending = false;
        self.reauth_interval = 0;
        self.md5_seen = false;
        self.start_attempts = 0;
        self.deadline = None;
    }

    fn wait(&mut self, state: State, reason: Reason, deadline: Option<u64>) -> Action {
        self.state = state;
        self.reason = reason;
        self.deadline = deadline;
        Action::Waiting
    }

    fn begin_exchange(&mut self, now: u64, reason: Reason) -> Action {
        let existing_lease = self.connected;
        self.clear_session();
        self.connected = existing_lease;
        self.reauth_pending = existing_lease || matches!(reason, Reason::PeriodicReauth);
        self.state = State::Connecting;
        self.reason = reason;
        self.start_attempts = 1;
        self.deadline = now.checked_add(START_PERIOD);
        self.generation = self.generation.saturating_add(1);
        Action::BeginExchange
    }

    fn reopen_transport(&mut self, now: u64) -> Action {
        self.clear_session();
        self.state = State::ReopeningTransport;
        self.reason = Reason::TransportPending;
        self.deadline = now.checked_add(5000);
        Action::ReopenTransport
    }

    fn reject(&mut self, reason: Reason) -> Action {
        self.clear_session();
        self.state = State::Rejected;
        self.reason = reason;
        Action::Rejected
    }

    fn transient_failure(&mut self, now: u64) -> Action {
        self.clear_session();
        if self.backoff_attempts >= 3 {
            return self.reject(Reason::RetryExhausted);
        }
        let delay = 1000 << self.backoff_attempts;
        self.backoff_attempts += 1;
        self.wait(
            State::TransientBackoff,
            Reason::TransientFailure,
            now.checked_add(delay),
        )
    }

    fn schedule_transport_retry(&mut self, now: u64) -> Action {
        self.clear_session();
        self.reopen_needed = true;
        let delay = (1000_u64 << self.transport_failures.min(5)).min(30000);
        self.transport_failures = self.transport_failures.saturating_add(1);
        self.wait(
            State::TransportBackoff,
            Reason::TransportRetry,
            now.checked_add(delay),
        )
    }

    fn start(&mut self, now: u64, up: bool) -> Action {
        if self.state == State::Stopped {
            return Action::None;
        }
        let now = self.observe_time(now);
        if self.started && self.state != State::Rejected {
            return Action::None;
        }
        self.started = true;
        self.link_up = up;
        self.backoff_attempts = 0;
        self.transport_failures = 0;
        self.resume_not_before = None;
        self.link_ready_at = None;
        self.reopen_needed = !up;
        self.clear_session();
        if up {
            self.begin_exchange(now, Reason::None)
        } else {
            self.wait(State::WaitingForLink, Reason::LinkDown, None)
        }
    }

    fn link_changed(&mut self, now: u64, up: bool) -> Action {
        if self.state == State::Stopped {
            return Action::None;
        }
        let now = self.observe_time(now);
        if self.link_up == up {
            return Action::None;
        }
        self.link_up = up;
        if !self.started || self.terminal() {
            return Action::None;
        }
        self.reopen_needed = true;
        if !up {
            self.link_ready_at = None;
            self.clear_session();
            return if self.state == State::Suspended {
                Action::None
            } else {
                self.wait(State::WaitingForLink, Reason::LinkDown, None)
            };
        }
        self.link_ready_at = now.checked_add(3000);
        if self.state == State::Suspended {
            return Action::None;
        }
        let ready = delay_gate(self.link_ready_at, self.resume_not_before);
        self.wait(State::LinkDebounce, Reason::LinkDebounce, ready)
    }

    fn suspend(&mut self, now: u64) -> Action {
        if !self.started || self.terminal() || self.state == State::Suspended {
            return Action::None;
        }
        self.observe_time(now);
        self.clear_session();
        self.reopen_needed = true;
        self.resume_not_before = None;
        self.wait(State::Suspended, Reason::Suspended, None)
    }

    fn resume(&mut self, now: u64) -> Action {
        if self.state != State::Suspended {
            return Action::None;
        }
        let now = self.observe_time(now);
        self.resume_not_before = now.checked_add(5000);
        if !self.link_up {
            return self.wait(State::WaitingForLink, Reason::LinkDown, None);
        }
        let ready = delay_gate(self.resume_not_before, self.link_ready_at);
        self.wait(State::ResumeDelay, Reason::ResumeDelay, ready)
    }

    fn request(&mut self, now: u64, md5: bool) -> Action {
        if !self.accepts_packet() || !self.link_up {
            return Action::None;
        }
        let now = self.observe_time(now);
        if self.state == State::Authenticating {
            if self.deadline.is_some_and(|deadline| now >= deadline) {
                return self.transient_failure(now);
            }
            // Only the first forward transition from Identity to MD5 gets a new deadline.
            if md5 && !self.md5_seen {
                self.md5_seen = true;
                self.deadline = now.checked_add(RESPONSE_TIMEOUT);
            }
            return Action::None;
        }
        self.md5_seen = md5;
        self.reauth_pending |= self.connected;
        self.state = State::Authenticating;
        self.reason = Reason::None;
        self.deadline = now.checked_add(RESPONSE_TIMEOUT);
        Action::None
    }

    fn success(&mut self, now: u64, reauth_interval: u64) -> Action {
        if !self.accepts_packet() || self.state == State::Connected || !self.link_up {
            return Action::None;
        }
        let now = self.observe_time(now);
        if self.state == State::Authenticating
            && self.deadline.is_some_and(|deadline| now >= deadline)
        {
            return self.transient_failure(now);
        }
        self.state = State::Connected;
        self.reason = Reason::None;
        self.connected = true;
        self.reauth_pending = false;
        self.backoff_attempts = 0;
        self.transport_failures = 0;
        self.reauth_interval = reauth_interval;
        self.deadline = (reauth_interval != 0)
            .then(|| now.checked_add(reauth_interval))
            .flatten();
        self.resume_not_before = None;
        self.link_ready_at = None;
        self.successful_exchanges = self.successful_exchanges.saturating_add(1);
        Action::Connected
    }

    fn failure(&mut self, now: u64, has_reason: bool) -> Action {
        // A validated late rejection can cancel a queued retry.
        if !self.link_up
            || !(self.accepts_packet() || has_reason && self.state == State::TransientBackoff)
        {
            return Action::None;
        }
        let now = self.observe_time(now);
        if has_reason {
            self.reject(Reason::ServerRejected)
        } else {
            self.transient_failure(now)
        }
    }

    fn server_terminated(&mut self, now: u64) -> Action {
        if !self.started || self.terminal() {
            return Action::None;
        }
        self.observe_time(now);
        self.reject(Reason::ServerRejected)
    }

    fn transport_error(&mut self, now: u64) -> Action {
        if !self.started || self.terminal() || self.state == State::Suspended {
            return Action::None;
        }
        let now = self.observe_time(now);
        self.reopen_needed = true;
        if !self.link_up
            || matches!(
                self.state,
                State::WaitingForLink
                    | State::LinkDebounce
                    | State::ResumeDelay
                    | State::TransportBackoff
            )
        {
            return Action::None;
        }
        self.schedule_transport_retry(now)
    }

    fn transport_ready(&mut self, now: u64) -> Action {
        if self.state != State::ReopeningTransport || !self.link_up {
            return Action::None;
        }
        let now = self.observe_time(now);
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            return self.schedule_transport_retry(now);
        }
        self.reopen_needed = false;
        self.begin_exchange(now, Reason::None)
    }

    fn tick(&mut self, now: u64, jitter: u64) -> Action {
        if !self.started || self.terminal() || self.state == State::Suspended {
            return Action::None;
        }
        let now = self.observe_time(now);
        if self.deadline.is_none_or(|deadline| now < deadline) {
            return Action::None;
        }
        // Produce at most one transition even if the scheduler missed several deadlines.
        match self.state {
            State::Connecting if self.start_attempts < 3 => {
                self.start_attempts += 1;
                self.deadline = now.checked_add(START_PERIOD);
                Action::RetryStart
            }
            State::Connecting => {
                self.connected = false;
                self.reauth_pending = false;
                self.reauth_interval = 0;
                self.no_server_waits = self.no_server_waits.saturating_add(1);
                let delay = 10000 + 1000 * jitter.min(19);
                self.wait(
                    State::NoServerWait,
                    Reason::NoServerResponse,
                    now.checked_add(delay),
                )
            }
            State::Authenticating => self.transient_failure(now),
            State::Connected => self.begin_exchange(now, Reason::PeriodicReauth),
            State::NoServerWait | State::TransientBackoff => self.begin_exchange(now, Reason::None),
            State::LinkDebounce | State::ResumeDelay => {
                if !self.link_up {
                    return self.wait(State::WaitingForLink, Reason::LinkDown, None);
                }
                self.resume_not_before = None;
                self.link_ready_at = None;
                if self.reopen_needed {
                    self.reopen_transport(now)
                } else {
                    self.begin_exchange(now, Reason::None)
                }
            }
            State::TransportBackoff => self.reopen_transport(now),
            State::ReopeningTransport => self.schedule_transport_retry(now),
            _ => Action::None,
        }
    }

    fn stop(&mut self, now: u64) -> Action {
        if self.state == State::Stopped {
            return Action::None;
        }
        self.observe_time(now);
        self.clear_session();
        self.state = State::Stopped;
        self.reason = Reason::None;
        self.link_ready_at = None;
        self.resume_not_before = None;
        Action::Stopped
    }
}

// A required delay that overflows waits for an external event.
fn delay_gate(required: Option<u64>, other: Option<u64>) -> Option<u64> {
    required.map(|deadline| deadline.max(other.unwrap_or(deadline)))
}

#[repr(C)]
pub struct Snapshot {
    deadline: u64,
    generation: u64,
    no_server_waits: u64,
    successful_exchanges: u64,
    reauth_interval: u64,
    start_attempts: u32,
    backoff_attempts: u32,
    transport_failures: u32,
    state: State,
    reason: Reason,
    action: Action,
    has_deadline: bool,
    link_up: bool,
    connected: bool,
    reauth_pending: bool,
    md5_seen: bool,
}

#[unsafe(no_mangle)]
pub extern "C" fn scau_recovery_create() -> *mut Recovery {
    Box::into_raw(Box::new(Recovery::default()))
}

// The C++ owner passes the live handle once, after its last step.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scau_recovery_destroy(handle: *mut Recovery) {
    unsafe { drop(Box::from_raw(handle)) };
}

// The owner serializes steps and supplies a valid result pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scau_recovery_step(
    handle: *mut Recovery,
    operation: u8,
    now: u64,
    argument: u64,
    result: *mut Snapshot,
) {
    let recovery = unsafe { &mut *handle };
    let action = match operation {
        0 => recovery.start(now, argument != 0),
        1 => recovery.link_changed(now, argument != 0),
        2 => recovery.suspend(now),
        3 => recovery.resume(now),
        4 => recovery.request(now, argument != 0),
        5 => recovery.success(now, argument),
        6 => recovery.failure(now, argument != 0),
        7 => recovery.server_terminated(now),
        8 => recovery.transport_error(now),
        9 => recovery.transport_ready(now),
        10 => recovery.tick(now, argument),
        11 => recovery.stop(now),
        _ => Action::None,
    };
    unsafe {
        result.write(Snapshot {
            deadline: recovery.deadline.unwrap_or_default(),
            generation: recovery.generation,
            no_server_waits: recovery.no_server_waits,
            successful_exchanges: recovery.successful_exchanges,
            reauth_interval: recovery.reauth_interval,
            start_attempts: recovery.start_attempts,
            backoff_attempts: recovery.backoff_attempts,
            transport_failures: recovery.transport_failures,
            state: recovery.state,
            reason: recovery.reason,
            action,
            has_deadline: recovery.deadline.is_some(),
            link_up: recovery.link_up,
            connected: recovery.connected,
            reauth_pending: recovery.reauth_pending,
            md5_seen: recovery.md5_seen,
        })
    };
}
