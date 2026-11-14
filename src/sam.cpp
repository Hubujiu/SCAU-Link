#include "sam.hpp"

#include <algorithm>
#include <iterator>
#include <limits>
#include <stdexcept>

namespace scau {
namespace {
constexpr std::size_t header_size = 42;
constexpr std::size_t fragment_size = 1358;
constexpr std::size_t max_udp_payload = 65507;
constexpr std::size_t max_message_size = 65536;
constexpr std::size_t max_assemblies = 64;
constexpr std::size_t max_queue_size = 16;
constexpr std::uint64_t assembly_lifetime_ms = 180000;

template<class Range>
struct ScopedWipe {
    Range& bytes;
    explicit ScopedWipe(Range& value) : bytes(value) {}
    ~ScopedWipe() { sam_clear_secret(bytes); }
    ScopedWipe(const ScopedWipe&) = delete;
    ScopedWipe& operator=(const ScopedWipe&) = delete;
};
void clear_attributes(SamEvent& event) noexcept {
    for (auto& attribute : event.attributes) sam_clear_secret(attribute.value);
}
struct EventWipe {
    SamEvent& event;
    ~EventWipe() { clear_attributes(event); }
};
struct EventsWipe {
    std::vector<SamEvent>& events;
    ~EventsWipe() { for (auto& event : events) clear_attributes(event); }
};

std::uint16_t be16(std::span<const Byte> bytes, std::size_t at) {
    return static_cast<std::uint16_t>((std::uint16_t{bytes[at]} << 8) | bytes[at + 1]);
}
std::uint32_t be32(std::span<const Byte> bytes, std::size_t at) {
    std::uint32_t value{};
    for (std::size_t i = 0; i < 4; ++i) value = (value << 8) | bytes[at + i];
    return value;
}
std::uint64_t be64(std::span<const Byte> bytes, std::size_t at) {
    std::uint64_t value{};
    for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | bytes[at + i];
    return value;
}
void write_be(std::span<Byte> bytes, std::size_t at, std::uint64_t value, std::size_t size) {
    for (std::size_t i = 0; i < size; ++i) {
        bytes[at + size - i - 1] = static_cast<Byte>(value);
        value >>= 8;
    }
}
std::uint64_t deadline(std::uint64_t now, std::uint64_t delay) {
    if (delay > std::numeric_limits<std::uint64_t>::max() - now)
        return std::numeric_limits<std::uint64_t>::max();
    return now + delay;
}
Byte fragment_kind(std::size_t offset, std::size_t size, std::size_t total) {
    if (size == total) return 1;
    if (offset == 0) return 2;
    return offset + size == total ? 4 : 3;
}
void append_attribute(Bytes& bytes, Byte type, std::span<const Byte> value) {
    if (value.size() > 255) throw std::invalid_argument("SAM attribute exceeds byte length");
    bytes.push_back(type);
    bytes.push_back(static_cast<Byte>(value.size()));
    bytes.insert(bytes.end(), value.begin(), value.end());
}

// Length bytes describe values only. Command 11's text field is the one
// documented exception: its length is two bytes, least significant first.
bool parse_messages(std::span<const Byte> body, std::uint32_t session,
                    std::vector<SamEvent>& events) {
    std::size_t at = 0;
    std::size_t count = 0;
    while (at < body.size()) {
        const auto rest = body.subspan(at);
        if (rest.size() <= 7 && std::all_of(rest.begin(), rest.end(), [](Byte x) { return x == 0; }))
            break;
        if (rest.size() < 3 || rest[0] != 1 || rest[1] != 1 || ++count > 64) return false;
        SamEvent event{SamEventKind::server_message, session, rest[2], {}};
        EventWipe wipe_event{event};
        at += 3;
        while (at < body.size()) {
            const auto tail = body.subspan(at);
            if (tail.size() <= 7 && std::all_of(tail.begin(), tail.end(), [](Byte x) { return x == 0; })) {
                at = body.size();
                break;
            }
            if (tail.size() < 2 || tail[0] == 0) return false;
            if (tail[0] == 1) break;
            const Byte type = tail[0];
            std::size_t length = tail[1];
            std::size_t prefix = 2;
            if (event.command == 11 && type == 2) {
                if (tail.size() < 3) return false;
                length |= std::size_t{tail[2]} << 8;
                prefix = 3;
            }
            if (length > tail.size() - prefix || event.attributes.size() >= 256) return false;
            if ((type == 4 && length != 4) || (type == 5 && length != 6) ||
                (type == 19 && length != 1)) return false;
            event.attributes.push_back({type, Bytes(tail.begin() + static_cast<std::ptrdiff_t>(prefix),
                                                    tail.begin() + static_cast<std::ptrdiff_t>(prefix + length))});
            at += prefix + length;
        }
        const auto has = [&](Byte type) {
            return std::any_of(event.attributes.begin(), event.attributes.end(),
                               [type](const SamAttribute& a) { return a.type == type; });
        };
        if ((event.command == 1 || event.command == 10 || event.command == 11) && !has(2)) return false;
        if (event.command == 7 && !has(10)) return false;
        if (event.command == 5) {
            if (!has(8)) return false;
            event.kind = SamEventKind::server_termination;
        }
        if (event.command == 9) {
            for (const auto& attr : event.attributes)
                if (attr.type == 19 && attr.value.size() != 1) return false;
        }
        events.push_back(std::move(event));
    }
    return !events.empty();
}
} // namespace

SamSession::~SamSession() { stop(); }

void SamSession::stop() noexcept {
    active_ = false;
    sam_clear_secret(config_.key);
    sam_clear_secret(config_.iv);
    sam_clear_secret(config_.integrity_seed);
    sam_clear_secret({reinterpret_cast<Byte*>(config_.username.data()), config_.username.size()});
    config_ = SamConfig{};
    pending_.reset();
    queued_.clear();
    assemblies_.clear();
    send_stamp_ = receive_stamp_ = hello_deadline_ = 0;
    receive_nonincreasing_ = 0;
    configured_at_ = {};
    next_session_id_ = 1;
}

SamOutput SamSession::configure(const SamConfig& config, SamTime now) {
    stop();
    if ((config.version != 1 && config.version != 2) || config.local.port == 0 ||
        config.server.port == 0 || config.username.empty() || config.username.size() > 255 ||
        config.username.find('\0') != std::string::npos || config.retry_timeout_ms == 0 ||
        config.max_attempts == 0 || config.max_attempts > 16 ||
        config.server_utc == std::numeric_limits<std::uint64_t>::max())
        throw std::invalid_argument("Invalid SAM configuration");
    try {
        config_ = config;
        configured_at_ = now;
        send_stamp_ = config.server_utc;
        active_ = true;
        if (config_.hello_interval_seconds == 0) return {};
        hello_deadline_ = deadline(now.monotonic_ms, std::uint64_t{config_.hello_interval_seconds} * 1000);
        return hello(now);
    } catch (...) {
        stop();
        throw;
    }
}

std::uint64_t SamSession::timestamp(SamTime now) {
    if (config_.version == 2) {
        if (send_stamp_ == std::numeric_limits<std::uint64_t>::max())
            throw std::overflow_error("SAM counter exhausted");
        return ++send_stamp_;
    }
    if (now.unix_seconds >= configured_at_.unix_seconds) {
        const auto delta = now.unix_seconds - configured_at_.unix_seconds;
        if (delta > std::numeric_limits<std::uint64_t>::max() - config_.server_utc)
            throw std::overflow_error("SAM time exhausted");
        return config_.server_utc + delta;
    }
    const auto delta = configured_at_.unix_seconds - now.unix_seconds;
    if (delta > config_.server_utc) throw std::overflow_error("SAM time precedes epoch");
    return config_.server_utc - delta;
}

Bytes SamSession::packet(Byte type, std::uint32_t packet_id, std::uint32_t session_id,
                         Byte fragment, std::uint32_t total,
                         std::span<const Byte> ciphertext, SamTime now) {
    Bytes result(header_size + ciphertext.size());
    result[0] = config_.version;
    result[1] = type;
    write_be(result, 2, packet_id, 4);
    write_be(result, 6, result.size(), 2);
    write_be(result, 24, session_id, 4);
    write_be(result, 28, timestamp(now), 8);
    result[36] = 1;
    result[37] = fragment;
    write_be(result, 38, total, 4);
    std::copy(ciphertext.begin(), ciphertext.end(), result.begin() + header_size);
    const auto auth = sam_packet_authenticator(config_.key, config_.iv, result);
    std::copy(auth.begin(), auth.end(), result.begin() + 8);
    return result;
}

SamDatagram SamSession::datagram(Bytes payload) const {
    return {config_.local, config_.server, std::move(payload)};
}

SamOutput SamSession::hello(SamTime now) {
    Bytes body{1, 1, 2};
    body.reserve(19 + config_.username.size() + (config_.append_integrity_attribute ? 130 : 0));
    ScopedWipe wipe_body(body);
    const auto* name = reinterpret_cast<const Byte*>(config_.username.data());
    append_attribute(body, 3, {name, config_.username.size()});
    append_attribute(body, 4, config_.local.address);
    append_attribute(body, 5, config_.local_mac);
    if (config_.append_integrity_attribute) {
        auto value = sam_integrity_attribute(next_session_id_, config_.integrity_seed);
        ScopedWipe wipe_value(value);
        append_attribute(body, 20, value);
    }
    return send_message(body, false, now);
}

SamOutput SamSession::send_message(std::span<const Byte> body, bool reliable, SamTime now) {
    SamOutput result;
    if (!active_ || now.monotonic_ms < configured_at_.monotonic_ms) return result;
    if (body.empty() || body.size() > max_message_size || next_session_id_ == 0)
        throw std::invalid_argument("Invalid SAM message length or exhausted session ID");
    if (reliable && pending_ && queued_.size() >= max_queue_size)
        throw std::length_error("SAM reliable queue is full");
    Pending next;
    next.session_id = next_session_id_++;
    next.packet_id = 1;
    next.ciphertext = sam_encrypt_body(config_.key, config_.iv, body);
    if (reliable) {
        if (pending_) queued_.push_back(std::move(next));
        else {
            pending_ = std::move(next);
            send_fragment(result, now);
        }
    } else {
        for (std::size_t at = 0; at < next.ciphertext.size(); at += fragment_size) {
            const auto count = std::min(fragment_size, next.ciphertext.size() - at);
            const auto fragment = fragment_kind(at, count, next.ciphertext.size());
            result.datagrams.push_back(datagram(packet(1, next.packet_id++, next.session_id, fragment,
                static_cast<std::uint32_t>(next.ciphertext.size()),
                std::span<const Byte>(next.ciphertext).subspan(at, count), now)));
        }
    }
    return result;
}

void SamSession::send_fragment(SamOutput& output, SamTime now) {
    auto& p = *pending_;
    const auto count = std::min(fragment_size, p.ciphertext.size() - p.offset);
    output.datagrams.push_back(datagram(packet(1, p.packet_id, p.session_id,
        fragment_kind(p.offset, count, p.ciphertext.size()),
        static_cast<std::uint32_t>(p.ciphertext.size()),
        std::span<const Byte>(p.ciphertext).subspan(p.offset, count), now)));
    ++p.attempts;
    p.deadline = deadline(now.monotonic_ms, config_.retry_timeout_ms);
}

void SamSession::advance_queue(SamOutput& output, SamTime now) {
    if (!queued_.empty()) {
        pending_ = std::move(queued_.front());
        queued_.erase(queued_.begin());
        send_fragment(output, now);
    }
}

SamOutput SamSession::tick(SamTime now) {
    SamOutput result;
    if (!active_ || now.monotonic_ms < configured_at_.monotonic_ms) return result;
    std::erase_if(assemblies_, [&](const Assembly& a) {
        return now.monotonic_ms >= deadline(a.touched, assembly_lifetime_ms);
    });
    if (pending_ && now.monotonic_ms >= pending_->deadline) {
        if (pending_->attempts >= config_.max_attempts) {
            result.events.push_back({SamEventKind::send_failed, pending_->session_id, 0, {}});
            pending_.reset();
            advance_queue(result, now);
        } else send_fragment(result, now);
    }
    if (config_.hello_interval_seconds != 0 && now.monotonic_ms >= hello_deadline_) {
        auto output = hello(now);
        result.datagrams.insert(result.datagrams.end(),
                                std::make_move_iterator(output.datagrams.begin()),
                                std::make_move_iterator(output.datagrams.end()));
        hello_deadline_ = deadline(now.monotonic_ms, std::uint64_t{config_.hello_interval_seconds} * 1000);
    }
    return result;
}

SamOutput SamSession::receive(const SamEndpoint& source, const SamEndpoint& destination,
                              std::span<const Byte> payload, SamTime now) {
    SamOutput result;
    if (!active_ || now.monotonic_ms < configured_at_.monotonic_ms || source != config_.server ||
        destination != config_.local || payload.size() < header_size ||
        payload.size() > max_udp_payload || payload[0] != config_.version ||
        be16(payload, 6) != payload.size() || payload[36] != 1 ||
        (payload[1] != 1 && payload[1] != 2)) return result;
    const auto id = be32(payload, 2);
    const auto session = be32(payload, 24);
    const auto stamp = be64(payload, 28);
    const auto fragment = payload[37];
    const auto total = be32(payload, 38);
    const auto part = payload.subspan(header_size);
    if (id == 0 || session == 0 || fragment < 1 || fragment > 4 ||
        !sam_verify_packet_authenticator(config_.key, config_.iv, payload)) return result;
    if (config_.version == 1) {
        const auto expected = timestamp(now);
        if ((stamp >= expected ? stamp - expected : expected - stamp) > 60) return result;
    } else if (stamp <= receive_stamp_ && receive_nonincreasing_ >= 5) return result;
    const auto accept_receive_stamp = [&] {
        if (config_.version != 2) return;
        if (stamp > receive_stamp_) {
            receive_stamp_ = stamp;
            receive_nonincreasing_ = 0;
        } else ++receive_nonincreasing_;
    };
    if (payload[1] == 2) {
        if (!part.empty() || total != 0 || fragment != 1 || !pending_ ||
            id != pending_->packet_id || session != pending_->session_id ||
            (pending_->attempts >= config_.max_attempts && now.monotonic_ms >= pending_->deadline)) return result;
        accept_receive_stamp();
        const auto count = std::min(fragment_size, pending_->ciphertext.size() - pending_->offset);
        pending_->offset += count;
        if (pending_->offset == pending_->ciphertext.size()) {
            result.events.push_back({SamEventKind::send_confirmed, session, 0, {}});
            pending_.reset();
            advance_queue(result, now);
        } else {
            ++pending_->packet_id;
            pending_->attempts = 0;
            send_fragment(result, now);
        }
        return result;
    }
    if (part.empty() || total == 0 || total > max_message_size || total % 8 != 0 ||
        part.size() > total) return result;
    auto found = std::find_if(assemblies_.begin(), assemblies_.end(),
                             [session](const Assembly& a) { return a.session_id == session; });
    const bool duplicate = found != assemblies_.end() && found->last_packet_id == id &&
        found->total == total && found->last_fragment == fragment && found->last_size == part.size() &&
        std::equal(part.begin(), part.end(), found->ciphertext.begin() +
                   static_cast<std::ptrdiff_t>(found->last_offset));
    if (duplicate) {
        if (!found->suppress_ack)
            result.datagrams.push_back(datagram(packet(2, id, session, 1, 0, {}, now)));
        accept_receive_stamp();
        return result;
    }
    Assembly next;
    auto replace = assemblies_.end();
    if (found == assemblies_.end()) {
        if (fragment != 1 && fragment != 2) return result;
        if (assemblies_.size() >= max_assemblies) {
            for (auto i = assemblies_.begin(); i != assemblies_.end(); ++i)
                if (i->complete && (replace == assemblies_.end() || i->touched < replace->touched))
                    replace = i;
            if (replace == assemblies_.end()) return result;
        }
        next.session_id = session;
        next.total = total;
    } else {
        if (found->complete || found->total != total || id != found->last_packet_id + 1 ||
            found->last_packet_id == std::numeric_limits<std::uint32_t>::max() ||
            (fragment != 3 && fragment != 4)) return result;
        next = *found;
    }
    if (part.size() > total - next.ciphertext.size()) return result;
    const auto new_size = next.ciphertext.size() + part.size();
    if (((fragment == 1 || fragment == 4) && new_size != total) ||
        ((fragment == 2 || fragment == 3) && new_size >= total)) return result;
    next.last_offset = next.ciphertext.size();
    next.last_size = part.size();
    next.last_fragment = fragment;
    next.last_packet_id = id;
    next.touched = now.monotonic_ms;
    next.ciphertext.insert(next.ciphertext.end(), part.begin(), part.end());
    next.complete = new_size == total;
    std::vector<SamEvent> events;
    EventsWipe wipe_events{events};
    bool suppress_ack = false;
    if (next.complete) {
        auto plaintext = sam_decrypt_body(config_.key, config_.iv, next.ciphertext);
        ScopedWipe wipe_plaintext(plaintext);
        if (!parse_messages(plaintext, session, events)) return result;
        suppress_ack = plaintext.size() >= 3 && plaintext[0] == 1 && plaintext[1] == 1 && plaintext[2] == 11;
        next.suppress_ack = suppress_ack;
    }
    if (replace != assemblies_.end()) *replace = std::move(next);
    else if (found == assemblies_.end()) assemblies_.push_back(std::move(next));
    else *found = std::move(next);
    accept_receive_stamp();
    if (!suppress_ack) result.datagrams.push_back(datagram(packet(2, id, session, 1, 0, {}, now)));
    result.events = std::move(events);
    if (std::any_of(result.events.begin(), result.events.end(), [](const SamEvent& e) {
        return e.kind == SamEventKind::server_termination;
    })) stop();
    return result;
}

std::optional<std::uint64_t> SamSession::next_deadline_ms() const noexcept {
    if (!active_) return {};
    std::optional<std::uint64_t> result;
    if (config_.hello_interval_seconds != 0) result = hello_deadline_;
    if (pending_ && (!result || pending_->deadline < *result)) result = pending_->deadline;
    for (const auto& a : assemblies_) {
        const auto expiry = deadline(a.touched, assembly_lifetime_ms);
        if (!result || expiry < *result) result = expiry;
    }
    return result;
}

} // namespace scau
