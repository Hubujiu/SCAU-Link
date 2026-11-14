#include "sam_runtime.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace scau;

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
SamConfig config() {
    SamConfig c;
    c.local = {{192, 0, 2, 10}, 80};
    c.server = {{192, 0, 2, 20}, 3848};
    c.local_mac = {2, 0x11, 0x22, 0x33, 0x44, 0x55};
    c.username = "student";
    c.key = {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1};
    c.iv = {1, 2, 3, 4, 5, 6, 7, 8};
    c.server_utc = 1000;
    return c;
}
void put(Bytes& bytes, std::size_t at, std::uint64_t value, std::size_t size) {
    for (std::size_t i = 0; i < size; ++i) {
        bytes[at + size - i - 1] = Byte(value);
        value >>= 8;
    }
}
SamDatagram message(const SamConfig& c, std::span<const Byte> body, std::uint32_t id,
                    std::uint64_t counter) {
    const auto encrypted = sam_encrypt_body(c.key, c.iv, body);
    Bytes payload(42 + encrypted.size());
    payload[0] = c.version;
    payload[1] = 1;
    put(payload, 2, 1, 4);
    put(payload, 6, payload.size(), 2);
    put(payload, 24, id, 4);
    put(payload, 28, counter, 8);
    payload[36] = payload[37] = 1;
    put(payload, 38, encrypted.size(), 4);
    std::copy(encrypted.begin(), encrypted.end(), payload.begin() + 42);
    const auto auth = sam_packet_authenticator(c.key, c.iv, payload);
    std::copy(auth.begin(), auth.end(), payload.begin() + 8);
    return {c.server, c.local, std::move(payload)};
}
bool notice(const SamRuntimeOutput& output, SamRuntimeNoticeKind kind, Byte command = 0) {
    return std::any_of(output.notices.begin(), output.notices.end(), [&](const SamRuntimeNotice& n) {
        return n.kind == kind && n.command == command;
    });
}
const Bytes info{1, 1, 1, 2, 3, 'i', 'n', 'f'};
const Bytes kick{1, 1, 5, 8, 3, 'b', 'y', 'e'};

void test_initial_hello() {
    auto c = config();
    c.hello_interval_seconds = 10;
    SamRuntime runtime;
    runtime.configure(c, {100, 5000});
    require(runtime.active() && runtime.configured() && runtime.next_deadline_ms() == 100,
            "Initial HELLO was not retained for poll");
    std::vector<SamDatagram> sent;
    const auto output = runtime.poll({100, 5000}, [&](const SamDatagram& d) {
        sent.push_back(d);
        return SamSendResult::sent;
    });
    require(sent.size() == 1 && sent[0].source == c.local && sent[0].destination == c.server &&
            sent[0].payload[1] == 1 && output.notices.empty() && !output.server_termination,
            "HELLO datagram forwarding failed");
    const auto plain = sam_decrypt_body(c.key, c.iv, std::span<const Byte>(sent[0].payload).subspan(42));
    require(plain[0] == 1 && plain[1] == 1 && plain[2] == 2, "Initial data is not HELLO");
    require(runtime.next_deadline_ms() == 10100, "Ordinary HELLO acquired ACK timeout");
}

void test_zero_interval_listens_and_validates() {
    const auto c = config();
    SamRuntime runtime;
    runtime.configure(c, {0, 5000});
    std::vector<SamDatagram> sent;
    const SamRuntime::Sender sender = [&](const SamDatagram& d) {
        sent.push_back(d);
        return SamSendResult::sent;
    };
    runtime.poll({0, 5000}, sender);
    require(runtime.active() && runtime.configured() && sent.empty(), "HELLO zero disabled listener or emitted packet");
    auto datagram = message(c, info, 1, 2001);
    auto wrong = datagram;
    ++wrong.source.port;
    require(runtime.receive(wrong, {0, 5000}, sender).notices.empty() && sent.empty(), "Wrong source tuple passed through");
    wrong = datagram;
    ++wrong.destination.address[3];
    require(runtime.receive(wrong, {0, 5000}, sender).notices.empty() && sent.empty(), "Wrong destination tuple passed through");
    wrong = datagram;
    wrong.payload.back() ^= 1;
    require(runtime.receive(wrong, {0, 5000}, sender).notices.empty() && sent.empty(), "Unauthenticated message passed through");
    const auto output = runtime.receive(datagram, {0, 5000}, sender);
    require(sent.size() == 1 && sent[0].payload.size() == 42 && sent[0].payload[1] == 2 &&
            notice(output, SamRuntimeNoticeKind::server_message, 1) && output.notices.size() == 1,
            "HELLO zero did not ACK message with safe notice");
}

void test_kick_ack_before_terminal() {
    const auto c = config();
    SamRuntime runtime;
    runtime.configure(c, {0, 5000});
    unsigned calls = 0;
    bool ack_before_terminal = true;
    const auto output = runtime.receive(message(c, kick, 1, 2001), {0, 5000}, [&](const SamDatagram& d) {
        ++calls;
        ack_before_terminal &= runtime.configured() && d.payload[1] == 2;
        return SamSendResult::sent;
    });
    require(calls == 1 && ack_before_terminal && output.server_termination && !output.cancelled &&
            notice(output, SamRuntimeNoticeKind::server_termination, 5) &&
            !runtime.configured() && !runtime.active(), "Kick did not finish after ACK");
    bool sent_after_stop = false;
    runtime.poll({99999, 5099}, [&](const SamDatagram&) {
        sent_after_stop = true;
        return SamSendResult::sent;
    });
    require(!sent_after_stop, "Stopped runtime tried to send");
}

void test_blocked_kick_is_bounded() {
    auto c = config();
    c.hello_interval_seconds = 10;
    SamRuntime runtime;
    runtime.configure(c, {0, 5000});
    unsigned calls = 0;
    bool only_ack_sent = true;
    const SamRuntime::Sender blocked = [&](const SamDatagram& d) {
        ++calls;
        only_ack_sent &= d.payload[1] == 2;
        return SamSendResult::would_block;
    };
    const auto first = runtime.receive(message(c, kick, 1, 2001), {100, 5000}, blocked);
    require(calls == 1 && only_ack_sent && !first.server_termination && runtime.configured() && !runtime.active(),
            "Blocked ACK prematurely reported termination");
    require(runtime.next_deadline_ms() == 110, "Would-block retry time incorrect");
    require(!runtime.poll({109, 5000}, blocked).server_termination && calls == 1, "Blocked sender retried too early");
    require(!runtime.poll({5099, 5005}, blocked).server_termination && calls == 2, "ACK did not retain bounded retry window");
    const auto expired = runtime.poll({5100, 5005}, blocked);
    require(calls == 2 && only_ack_sent && expired.server_termination &&
            notice(expired, SamRuntimeNoticeKind::packet_expired) && !runtime.configured(),
            "Unsendable ACK hung termination beyond five seconds");
}

void test_blocked_send_recovers_and_expires() {
    auto c = config();
    c.hello_interval_seconds = 10;
    SamRuntime runtime;
    runtime.configure(c, {0, 5000});
    unsigned calls = 0;
    Bytes first;
    const auto blocked = runtime.poll({0, 5000}, [&](const SamDatagram& d) {
        ++calls;
        first = d.payload;
        return SamSendResult::would_block;
    });
    require(blocked.notices.empty() && calls == 1, "Would-block treated as send failure");
    bool same_payload = true;
    runtime.poll({10, 5000}, [&](const SamDatagram& d) {
        ++calls;
        same_payload &= d.payload == first;
        return SamSendResult::sent;
    });
    require(calls == 2 && same_payload && runtime.active(), "Would-block did not recover with original datagram");
    runtime.configure(c, {0, 5000});
    const auto expired = runtime.poll({5000, 5005}, [&](const SamDatagram&) {
        ++calls;
        return SamSendResult::sent;
    });
    require(calls == 2 && notice(expired, SamRuntimeNoticeKind::packet_expired) && runtime.active() &&
            !expired.server_termination, "Stale ordinary datagram was sent or triggered termination");
}

void test_cancellation_never_retries() {
    auto c = config();
    c.hello_interval_seconds = 10;
    SamRuntime runtime;
    runtime.configure(c, {0, 5000});
    unsigned calls = 0;
    const SamRuntime::Sender cancel = [&](const SamDatagram&) {
        ++calls;
        return SamSendResult::cancelled;
    };
    require(runtime.poll({0, 5000}, cancel).cancelled && calls == 1 && !runtime.configured(),
            "Stop request was treated as temporary send failure");
    runtime.poll({10, 5000}, cancel);
    runtime.poll({10000, 5010}, cancel);
    require(calls == 1, "Cancelled packet or HELLO retried");
    runtime.configure(c, {0, 5000});
    const auto kick_output = runtime.receive(message(c, kick, 1, 2001), {0, 5000}, cancel);
    require(kick_output.cancelled && !kick_output.server_termination && calls == 2 && !runtime.configured(),
            "Cancelled terminal ACK reported terminal or retried");
}

void test_exception_drops_without_retry() {
    auto c = config();
    c.hello_interval_seconds = 10;
    SamRuntime runtime;
    runtime.configure(c, {0, 5000});
    unsigned calls = 0;
    const SamRuntime::Sender failure = [&](const SamDatagram&) -> SamSendResult {
        ++calls;
        throw std::runtime_error("Synthetic sensitive failure text must not escape");
    };
    const auto output = runtime.poll({0, 5000}, failure);
    require(calls == 1 && notice(output, SamRuntimeNoticeKind::send_failed) && runtime.active() &&
            !output.cancelled && !output.server_termination, "Ordinary send failure caused protocol failure");
    runtime.poll({1000, 5001}, failure);
    require(calls == 1, "Uncertain send outcome was retransmitted");
}

void test_queue_bound_and_refresh() {
    auto c = config();
    SamRuntime runtime;
    runtime.configure(c, {0, 5000});
    const SamRuntime::Sender blocked = [](const SamDatagram&) { return SamSendResult::would_block; };
    bool overflow = false;
    for (unsigned i = 1; i <= 70; ++i) {
        const auto output = runtime.receive(message(c, info, i, 2000 + i), {0, 5000}, blocked);
        overflow |= notice(output, SamRuntimeNoticeKind::queue_full);
    }
    require(overflow, "Queue cap not enforced");
    unsigned sent = 0;
    runtime.poll({10, 5000}, [&](const SamDatagram&) { ++sent; return SamSendResult::sent; });
    require(sent == 64, "Queue retained more than 64 datagrams");
    c.hello_interval_seconds = 10;
    runtime.configure(c, {100, 5000});
    runtime.poll({100, 5000}, blocked);
    const auto old = message(c, kick, 1, 4001);
    auto fresh = c;
    fresh.key[0] ^= 0x80;
    runtime.configure(fresh, {200, 5000});
    std::vector<SamDatagram> output;
    const SamRuntime::Sender sender = [&](const SamDatagram& d) {
        output.push_back(d);
        return SamSendResult::sent;
    };
    require(!runtime.receive(old, {200, 5000}, sender).server_termination && output.size() == 1 &&
            sam_verify_packet_authenticator(fresh.key, fresh.iv, output[0].payload) &&
            !sam_verify_packet_authenticator(c.key, c.iv, output[0].payload),
            "Old queued packet or old-key kick survived refresh");
    runtime.stop();
    require(!runtime.configured() && !runtime.next_deadline_ms(), "Stop retained queue/deadlines");
}
} // namespace

int main() {
    try {
        test_initial_hello();
        test_zero_interval_listens_and_validates();
        test_kick_ack_before_terminal();
        test_blocked_kick_is_bounded();
        test_blocked_send_recovers_and_expires();
        test_cancellation_never_retries();
        test_exception_drops_without_retry();
        test_queue_bound_and_refresh();
        std::cout << "SAM runtime offline tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
