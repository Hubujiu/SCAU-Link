#include "sam.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string_view>

using namespace scau;

namespace {
void require(bool value, const char* description) {
    if (!value) throw std::runtime_error(description);
}
Bytes hex(std::string_view value) {
    const auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return unsigned(c - '0');
        if (c >= 'a' && c <= 'f') return unsigned(c - 'a' + 10);
        throw std::runtime_error("Invalid test hex");
    };
    Bytes result;
    for (std::size_t i = 0; i < value.size(); i += 2)
        result.push_back(Byte(digit(value[i]) * 16 + digit(value[i + 1])));
    return result;
}
void put(Bytes& bytes, std::size_t at, std::uint64_t value, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        bytes[at + count - i - 1] = Byte(value);
        value >>= 8;
    }
}
std::uint64_t number(std::span<const Byte> bytes, std::size_t at, std::size_t count) {
    std::uint64_t result{};
    for (std::size_t i = 0; i < count; ++i) result = result * 256 + bytes[at + i];
    return result;
}
SamConfig config() {
    SamConfig c;
    c.local = {{192, 0, 2, 1}, 80};
    c.server = {{192, 0, 2, 2}, 3848};
    c.local_mac = {2, 0x11, 0x22, 0x33, 0x44, 0x55};
    c.username = "student";
    const auto key = hex("133457799bbcdff1"), iv = hex("0102030405060708");
    std::copy(key.begin(), key.end(), c.key.begin());
    std::copy(iv.begin(), iv.end(), c.iv.begin());
    c.server_utc = 1000;
    return c;
}
void authenticate(const SamConfig& c, Bytes& packet) {
    const auto auth = sam_packet_authenticator(c.key, c.iv, packet);
    std::copy(auth.begin(), auth.end(), packet.begin() + 8);
}
Bytes packet(const SamConfig& c, Byte type, std::uint32_t id, std::uint32_t session,
             std::uint64_t stamp, Byte fragment, std::uint32_t total,
             std::span<const Byte> ciphertext = {}) {
    Bytes result(42 + ciphertext.size());
    result[0] = c.version;
    result[1] = type;
    put(result, 2, id, 4);
    put(result, 6, result.size(), 2);
    put(result, 24, session, 4);
    put(result, 28, stamp, 8);
    result[36] = 1;
    result[37] = fragment;
    put(result, 38, total, 4);
    std::copy(ciphertext.begin(), ciphertext.end(), result.begin() + 42);
    authenticate(c, result);
    return result;
}
Bytes server_message(const SamConfig& c, std::span<const Byte> body,
                     std::uint32_t session, std::uint64_t stamp) {
    const auto ciphertext = sam_encrypt_body(c.key, c.iv, body);
    return packet(c, 1, 1, session, stamp, 1,
                  static_cast<std::uint32_t>(ciphertext.size()), ciphertext);
}
SamOutput receive(SamSession& session, const SamConfig& c, const Bytes& bytes,
                  SamTime now = {0, 5000}) {
    return session.receive(c.server, c.local, bytes, now);
}
bool empty(const SamOutput& output) {
    return output.datagrams.empty() && output.events.empty();
}

void test_hello_vector_and_period() {
    auto c = config();
    c.hello_interval_seconds = 10;
    SamSession session;
    const auto output = session.configure(c, {0, 5000});
    require(session.active() && output.datagrams.size() == 1 && output.events.empty(), "Immediate HELLO missing");
    // Independently produced using Python struct + PyCryptodome DES + hashlib.
    const auto expected = hex("020100000001004ae8505e98183966e33c5bd2368cadc5b10000000100000000000003e9010100000020a6259a190aa86e707c7aa5935f9c367d2602ded2fd7825e3d3ec4ab073595b86");
    require(output.datagrams[0].payload == expected, "Full synthetic HELLO wire vector mismatch");
    require(output.datagrams[0].source == c.local && output.datagrams[0].destination == c.server,
            "HELLO endpoints reversed");
    require(session.next_deadline_ms() == 10000, "HELLO deadline mismatch");
    require(empty(session.tick({9999, 5009})), "HELLO sent early");
    const auto second = session.tick({10000, 5010});
    require(second.datagrams.size() == 1 && second.events.empty(), "Unconfirmed HELLO blocked next interval");
    require(number(second.datagrams[0].payload, 2, 4) == 1 &&
            number(second.datagrams[0].payload, 24, 4) == 2 &&
            number(second.datagrams[0].payload, 28, 8) == 1002, "HELLO IDs or v2 counter mismatch");
    const auto late = session.tick({45000, 5045});
    require(late.datagrams.size() == 1 && session.next_deadline_ms() == 55000, "Late tick caused HELLO burst");
}

void test_reliable_retry_and_ack() {
    const auto c = config();
    SamSession session;
    require(empty(session.configure(c, {0, 5000})), "Disabled HELLO emitted initial packet");
    const auto first = session.send_message(Bytes{1, 1, 2}, true, {0, 5000});
    require(first.datagrams.size() == 1 && session.next_deadline_ms() == 2000, "Reliable first send missing");
    require(empty(session.tick({1999, 5001})), "Retry sent early");
    const auto retry = session.tick({2000, 5002});
    require(retry.datagrams.size() == 1 && number(retry.datagrams[0].payload, 2, 4) == 1 &&
            number(retry.datagrams[0].payload, 24, 4) == 1 &&
            number(retry.datagrams[0].payload, 28, 8) == 1002, "Retry changed message or packet ID");
    require(std::equal(first.datagrams[0].payload.begin() + 42, first.datagrams[0].payload.end(),
                       retry.datagrams[0].payload.begin() + 42), "Retry changed ciphertext");
    require(empty(receive(session, c, packet(c, 2, 2, 1, 2001, 1, 0), {2000, 5002})), "Wrong packet ACK accepted");
    require(empty(receive(session, c, packet(c, 2, 1, 2, 2001, 1, 0), {2000, 5002})), "Wrong session ACK accepted");
    const auto ack = packet(c, 2, 1, 1, 2001, 1, 0);
    auto wrong = c.server;
    ++wrong.port;
    require(empty(session.receive(wrong, c.local, ack, {2000, 5002})), "Wrong-source ACK accepted");
    const auto done = receive(session, c, ack, {2000, 5002});
    require(done.events.size() == 1 && done.events[0].kind == SamEventKind::send_confirmed &&
            done.events[0].session_id == 1 && !session.next_deadline_ms(), "Valid ACK did not finish send");
    require(empty(receive(session, c, ack, {2001, 5002})), "Duplicate ACK changed state");
    require(empty(session.tick({4000, 5004})), "ACKed message retried");
}

void test_retry_exhaustion_and_queue() {
    const auto c = config();
    SamSession session;
    session.configure(c, {0, 5000});
    session.send_message(Bytes{1, 1, 2}, true, {0, 5000});
    require(empty(session.send_message(Bytes{1, 1, 2}, true, {1, 5000})), "Reliable queue sent before prior ACK");
    require(session.tick({2000, 5002}).datagrams.size() == 1, "First retry absent");
    require(empty(receive(session, c, packet(c, 2, 1, 1, 2001, 1, 0), {4000, 5004})),
            "Late ACK revived an exhausted send before caller tick");
    const auto timeout = session.tick({4000, 5004});
    require(timeout.events.size() == 1 && timeout.events[0].kind == SamEventKind::send_failed &&
            timeout.events[0].session_id == 1 && timeout.datagrams.size() == 1 && session.active(),
            "Retry limit failed to finish only failed transport message");
    require(number(timeout.datagrams[0].payload, 24, 4) == 2, "Queued session ID mismatch");
    const auto done = receive(session, c, packet(c, 2, 1, 2, 2001, 1, 0), {4001, 5004});
    require(done.events.size() == 1 && done.events[0].kind == SamEventKind::send_confirmed, "Queued message ACK failed");
}

void test_fragmented_reliable() {
    const auto c = config();
    SamSession session;
    session.configure(c, {0, 5000});
    const auto first = session.send_message(Bytes(2000, 0x5a), true, {0, 5000});
    require(first.datagrams.size() == 1 && first.datagrams[0].payload.size() == 1400 &&
            first.datagrams[0].payload[37] == 2, "First fragment boundary incorrect");
    const auto next = receive(session, c, packet(c, 2, 1, 1, 2001, 1, 0));
    require(next.events.empty() && next.datagrams.size() == 1 && next.datagrams[0].payload.size() == 684 &&
            next.datagrams[0].payload[37] == 4 && number(next.datagrams[0].payload, 2, 4) == 2,
            "ACK did not advance to final fragment");
    require(empty(receive(session, c, packet(c, 2, 1, 1, 2002, 1, 0))), "Old fragment ACK advanced state");
    const auto done = receive(session, c, packet(c, 2, 2, 1, 2002, 1, 0));
    require(done.events.size() == 1 && done.events[0].kind == SamEventKind::send_confirmed, "Final fragment ACK failed");
}

void test_server_data_and_replay() {
    const auto c = config();
    SamSession session;
    session.configure(c, {0, 5000});
    const Bytes body{1, 1, 1, 2, 3, 'i', 'n', 'f'};
    const auto bytes = server_message(c, body, 3, 2001);
    auto wrong = c.server;
    wrong.address[3] = 3;
    require(empty(session.receive(wrong, c.local, bytes, {0, 5000})), "Wrong server address accepted");
    auto corrupt = bytes;
    corrupt.back() ^= 1;
    require(empty(receive(session, c, corrupt)), "Corrupt authenticator accepted");
    const auto output = receive(session, c, bytes);
    require(output.datagrams.size() == 1 && output.datagrams[0].payload[1] == 2 &&
            output.datagrams[0].payload.size() == 42 && output.events.size() == 1 &&
            output.events[0].command == 1 && output.events[0].attributes[0].value == Bytes({'i', 'n', 'f'}),
            "Server data did not produce message and authenticated ACK");
    const auto duplicate = receive(session, c, bytes);
    require(duplicate.datagrams.size() == 1 && duplicate.events.empty(), "Duplicate data executed command again or omitted ACK");
    // The duplicate above consumes the first nonincreasing allowance. UDP
    // messages can arrive across logical sessions in a different order.
    for (std::uint32_t id = 4; id <= 7; ++id) {
        const auto reordered = receive(session, c, server_message(c, body, id, 2001 - (id - 3)));
        require(reordered.datagrams.size() == 1 && reordered.events.size() == 1,
                "One of the five nonincreasing packets was rejected");
    }
    require(empty(receive(session, c, server_message(c, body, 8, 2000))), "Sixth nonincreasing data packet accepted");
    require(empty(receive(session, c, bytes)), "Sixth nonincreasing duplicate was ACKed");
    require(receive(session, c, server_message(c, body, 8, 2002)).events.size() == 1,
            "Higher counter did not reset exhausted tolerance");
    for (std::uint32_t id = 9; id <= 13; ++id)
        require(receive(session, c, server_message(c, body, id, 2002)).events.size() == 1,
                "Equal counter was not included in five-packet tolerance");
    require(empty(receive(session, c, server_message(c, body, 14, 2002))), "Sixth equal counter accepted");
    require(receive(session, c, server_message(c, body, 14, 2003)).events.size() == 1,
            "New high water did not reopen tolerance");
    const auto delayed_kick = receive(session, c, server_message(c, Bytes{1, 1, 5, 8, 0}, 15, 2001));
    require(delayed_kick.datagrams.size() == 1 && delayed_kick.events.size() == 1 &&
            delayed_kick.events[0].kind == SamEventKind::server_termination && !session.active(),
            "Reordered server termination was delayed or discarded");

    session.configure(c, {1, 5000});
    const auto reset_packet = server_message(c, body, 1, 1);
    require(receive(session, c, reset_packet, {1, 5000}).events.size() == 1,
            "New configuration retained old receive high water");
    for (unsigned i = 0; i < 5; ++i) {
        const auto repeated = receive(session, c, reset_packet, {1, 5000});
        require(repeated.datagrams.size() == 1 && repeated.events.empty(),
                "Reconfigured duplicate tolerance was not reset or command was dispatched again");
    }
    require(empty(receive(session, c, reset_packet, {1, 5000})), "Reconfigured sixth duplicate accepted");

    auto other_config = c;
    other_config.server.address[3] = 3;
    SamSession other_peer;
    other_peer.configure(other_config, {1, 5000});
    const auto other_packet = server_message(other_config, body, 1, 1);
    require(receive(other_peer, other_config, other_packet, {1, 5000}).events.size() == 1,
            "Another peer inherited receive high water");
    for (unsigned i = 0; i < 5; ++i)
        require(receive(other_peer, other_config, other_packet, {1, 5000}).datagrams.size() == 1,
                "Nonincreasing tolerance leaked between peers");
    require(empty(receive(other_peer, other_config, other_packet, {1, 5000})),
            "Another peer did not enforce its own sixth-packet bound");
}

void test_timestamp_window_shared_by_ack_and_data() {
    const auto c = config();
    const Bytes body{1, 1, 1, 2, 3, 'i', 'n', 'f'};
    SamSession session;
    session.configure(c, {0, 5000});
    require(receive(session, c, server_message(c, body, 50, 3000)).events.size() == 1,
            "Failed to establish peer receive high water");
    session.send_message(Bytes{1, 1, 2}, true, {0, 5000});
    const auto first_ack = receive(session, c, packet(c, 2, 1, 1, 2999, 1, 0));
    require(first_ack.events.size() == 1 && first_ack.events[0].kind == SamEventKind::send_confirmed,
            "Reordered matching ACK was rejected");
    const auto data = server_message(c, body, 51, 2998);
    require(receive(session, c, data).events.size() == 1, "Reordered data after ACK rejected");
    const auto duplicate = receive(session, c, data);
    require(duplicate.datagrams.size() == 1 && duplicate.events.empty(), "Duplicate data redispatched command");
    session.send_message(Bytes{1, 1, 2}, true, {0, 5000});
    require(receive(session, c, packet(c, 2, 1, 2, 2997, 1, 0)).events.size() == 1,
            "ACK did not share the nonincreasing window");
    require(receive(session, c, server_message(c, body, 52, 3000)).events.size() == 1,
            "Fifth mixed nonincreasing packet rejected");
    session.send_message(Bytes{1, 1, 2}, true, {0, 5000});
    require(empty(receive(session, c, packet(c, 2, 1, 3, 2996, 1, 0))),
            "Sixth mixed nonincreasing ACK accepted");
    const auto reset_ack = receive(session, c, packet(c, 2, 1, 3, 3001, 1, 0));
    require(reset_ack.events.size() == 1 && reset_ack.events[0].kind == SamEventKind::send_confirmed,
            "Higher matching ACK did not reset receive tolerance");
    const auto reset_data = server_message(c, body, 53, 0);
    require(receive(session, c, reset_data).events.size() == 1, "ACK reset did not admit reordered data");
    for (unsigned i = 0; i < 4; ++i) {
        const auto repeated = receive(session, c, reset_data);
        require(repeated.datagrams.size() == 1 && repeated.events.empty(),
                "Duplicate did not use remaining shared tolerance");
    }
    require(empty(receive(session, c, reset_data)), "Duplicate bypassed exhausted mixed tolerance");
}

void test_server_fragmentation() {
    const auto c = config();
    SamSession session;
    session.configure(c, {0, 5000});
    Bytes body{1, 1, 1};
    for (unsigned i = 0; i < 8; ++i) {
        body.insert(body.end(), {2, 255});
        body.insert(body.end(), 255, Byte('a' + i));
    }
    const auto ciphertext = sam_encrypt_body(c.key, c.iv, body);
    const auto first = packet(c, 1, 1, 7, 2001, 2, static_cast<std::uint32_t>(ciphertext.size()),
                              std::span<const Byte>(ciphertext).first(1358));
    const auto out = receive(session, c, first);
    require(out.datagrams.size() == 1 && out.events.empty(), "Partial message delivered before reassembly");
    require(receive(session, c, first).datagrams.size() == 1, "Duplicate partial fragment not ACKed");
    const auto remaining = std::span<const Byte>(ciphertext).subspan(1358);
    require(empty(receive(session, c, packet(c, 1, 3, 7, 2002, 4,
                          static_cast<std::uint32_t>(ciphertext.size()), remaining))), "Out-of-order fragment accepted");
    const auto last = packet(c, 1, 2, 7, 2002, 4, static_cast<std::uint32_t>(ciphertext.size()), remaining);
    const auto complete = receive(session, c, last);
    require(complete.datagrams.size() == 1 && complete.events.size() == 1 &&
            complete.events[0].attributes.size() == 8, "Reassembled encrypted message incorrect");
    require(receive(session, c, last).events.empty(), "Repeated final fragment executed message twice");
    require(empty(receive(session, c, first)), "Old first fragment replaced completed session");
}

void test_bounds_and_malformed_messages() {
    const auto c = config();
    const auto valid = server_message(c, Bytes{1, 1, 1, 2, 3, 'i', 'n', 'f'}, 1, 2001);
    for (std::size_t length = 0; length < valid.size(); ++length) {
        SamSession session;
        session.configure(c, {0, 5000});
        require(empty(receive(session, c, Bytes(valid.begin(), valid.begin() + static_cast<std::ptrdiff_t>(length)))),
                "Truncated packet accepted");
    }
    const std::array<std::pair<std::size_t, Byte>, 5> bad_fields{{
        {std::size_t{0}, Byte{3}}, {std::size_t{1}, Byte{3}}, {std::size_t{36}, Byte{0}},
        {std::size_t{37}, Byte{0}}, {std::size_t{41}, Byte{7}}}};
    for (const auto& [offset, value] : bad_fields) {
        SamSession session;
        session.configure(c, {0, 5000});
        auto bad = valid;
        bad[offset] = value;
        authenticate(c, bad);
        require(empty(receive(session, c, bad)), "Authenticated malformed header accepted");
        require(receive(session, c, valid).events.size() == 1, "Malformed header poisoned valid next packet");
    }
    for (const Bytes& bad_body : {Bytes{1, 1, 5, 8, 255}, Bytes{1, 1, 5},
                                  Bytes{1, 1, 9, 19, 2, 0, 0}, Bytes{1, 1, 1, 4, 3, 1, 2, 3},
                                  Bytes{1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}) {
        SamSession session;
        session.configure(c, {0, 5000});
        require(empty(receive(session, c, server_message(c, bad_body, 1, 2001))) && session.active(),
                "Malformed body was ACKed or changed active state");
    }
}

void test_server_termination_and_command9() {
    const auto c = config();
    SamSession session;
    session.configure(c, {0, 5000});
    const auto wireless = receive(session, c, server_message(c, Bytes{1, 1, 9, 19, 1, 0, 2, 0}, 1, 2001));
    require(wireless.events.size() == 1 && wireless.events[0].kind == SamEventKind::server_message && session.active(),
            "Wireless DHCP result incorrectly terminated session");
    const auto stop = receive(session, c, server_message(c, Bytes{1, 1, 5, 8, 0}, 2, 2002));
    require(stop.events.size() == 1 && stop.events[0].kind == SamEventKind::server_termination &&
            stop.datagrams.size() == 1 && !session.active() && !session.next_deadline_ms(),
            "Server termination not ACKed and stopped");
    require(empty(session.tick({999999, 5999})), "Stopped session emitted maintenance");
}

void test_large_server_message() {
    const auto c = config();
    SamSession session;
    session.configure(c, {0, 5000});
    Bytes body{1, 1, 11, 4, 4, 192, 0, 2, 2, 2, 44, 1};
    body.insert(body.end(), 300, 'x');
    const auto bytes = server_message(c, body, 1, 2001);
    const auto output = receive(session, c, bytes);
    require(output.datagrams.empty() && output.events.size() == 1 &&
            output.events[0].attributes[1].value.size() == 300,
            "Command 11 two-byte length or ACK suppression incorrect");
    require(empty(receive(session, c, bytes)), "Repeated command 11 acknowledged or delivered again");
}

void test_v1_time_window() {
    auto c = config();
    c.version = 1;
    c.hello_interval_seconds = 5;
    SamSession session;
    const auto initial = session.configure(c, {0, 5000});
    require(number(initial.datagrams[0].payload, 28, 8) == 1000, "V1 initial timestamp incorrect");
    const auto next = session.tick({5000, 5005});
    require(number(next.datagrams[0].payload, 28, 8) == 1005, "V1 timestamp did not follow server clock offset");
    const Bytes body{1, 1, 1, 2, 3, 'i', 'n', 'f'};
    require(empty(receive(session, c, server_message(c, body, 4, 1066), {5000, 5005})), "V1 future timestamp outside window accepted");
    require(receive(session, c, server_message(c, body, 4, 1065), {5000, 5005}).events.size() == 1,
            "V1 inclusive 60-second window rejected");
}

void test_refresh_stop_and_integrity() {
    auto c = config();
    SamSession session;
    session.configure(c, {0, 5000});
    session.send_message(Bytes{1, 1, 2}, true, {0, 5000});
    const auto old = server_message(c, Bytes{1, 1, 5, 8, 0}, 1, 2001);
    auto fresh = c;
    fresh.key[0] ^= 0x80;
    fresh.server_utc = 3000;
    require(empty(session.configure(fresh, {500, 5000})) && !session.next_deadline_ms(), "New Success retained old timers");
    require(empty(receive(session, fresh, old, {500, 5000})) && session.active(), "Old-key server message accepted after refresh");
    require(empty(session.tick({5000, 5005})), "Old queued message retried after refresh");
    session.stop();
    require(empty(session.tick({10000, 5010})) && !session.active(), "Stop emitted exit or logoff traffic");
    fresh.hello_interval_seconds = 10;
    fresh.append_integrity_attribute = true;
    for (std::size_t i = 0; i < fresh.integrity_seed.size(); ++i) fresh.integrity_seed[i] = Byte(i);
    const auto hello = session.configure(fresh, {0, 5000});
    const auto plain = sam_decrypt_body(fresh.key, fresh.iv,
                                       std::span<const Byte>(hello.datagrams[0].payload).subspan(42));
    const auto position = std::size_t{3 + 2 + fresh.username.size() + 6 + 8};
    require(plain[position] == 20 && plain[position + 1] == 128, "Integrity attribute type or length mismatch");
    const auto expected = sam_integrity_attribute(1, fresh.integrity_seed);
    require(std::equal(expected.begin(), expected.end(), plain.begin() + static_cast<std::ptrdiff_t>(position + 2)),
            "Integrity seed or message serial mismatch");
    fresh.version = 3;
    bool rejected = false;
    try { session.configure(fresh, {1, 5000}); } catch (const std::invalid_argument&) { rejected = true; }
    require(rejected && !session.active(), "Invalid new parameters retained old session");
}
} // namespace

int main() {
    try {
        test_hello_vector_and_period();
        test_reliable_retry_and_ack();
        test_retry_exhaustion_and_queue();
        test_fragmented_reliable();
        test_server_data_and_replay();
        test_timestamp_window_shared_by_ack_and_data();
        test_server_fragmentation();
        test_bounds_and_malformed_messages();
        test_server_termination_and_command9();
        test_large_server_message();
        test_v1_time_window();
        test_refresh_stop_and_integrity();
        std::cout << "SAM offline protocol tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
