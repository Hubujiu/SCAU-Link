#include "sam_runtime.hpp"

#include <algorithm>
#include <limits>

namespace scau {
namespace {
constexpr std::size_t max_queue = 64;
constexpr std::uint64_t packet_lifetime_ms = 5000;
constexpr std::uint64_t would_block_delay_ms = 10;

std::uint64_t after(std::uint64_t now, std::uint64_t delay) {
    return delay > std::numeric_limits<std::uint64_t>::max() - now
        ? std::numeric_limits<std::uint64_t>::max() : now + delay;
}
bool is_ack(const SamDatagram& datagram) {
    return datagram.payload.size() >= 2 && datagram.payload[1] == 2;
}
struct EventsWipe {
    std::vector<SamEvent>& events;
    ~EventsWipe() {
        for (auto& event : events)
            for (auto& attribute : event.attributes) sam_clear_secret(attribute.value);
    }
};
} // namespace

SamRuntime::~SamRuntime() { stop(); }

void SamRuntime::stop() noexcept {
    session_.stop();
    queue_.clear();
    notices_.clear();
    configured_ = termination_pending_ = false;
    generation_started_ = send_due_ = termination_deadline_ = 0;
}

void SamRuntime::configure(const SamConfig& config, SamTime now) {
    stop();
    auto output = session_.configure(config, now);
    configured_ = true;
    generation_started_ = send_due_ = now.monotonic_ms;
    accept(std::move(output), now);
}

void SamRuntime::accept(SamOutput output, SamTime now) {
    EventsWipe wipe_events{output.events};
    const bool termination = std::any_of(output.events.begin(), output.events.end(),
        [](const SamEvent& event) { return event.kind == SamEventKind::server_termination; });
    if (termination) {
        termination_pending_ = true;
        termination_deadline_ = after(now.monotonic_ms, packet_lifetime_ms);
        // A server termination stops proactive work immediately. Keep ACKs
        // until sent/expired; HELLOs queued before it no longer serve a purpose.
        std::erase_if(queue_, [](const Queued& item) { return !is_ack(item.datagram); });
    }
    for (auto& event : output.events) {
        if (event.kind == SamEventKind::server_message)
            notices_.push_back({SamRuntimeNoticeKind::server_message, event.command});
        else if (event.kind == SamEventKind::send_confirmed)
            notices_.push_back({SamRuntimeNoticeKind::send_confirmed, event.command});
        else if (event.kind == SamEventKind::send_failed)
            notices_.push_back({SamRuntimeNoticeKind::send_failed, event.command});
        // Server attributes are intentionally consumed here and never enter a
        // diagnostic result. Clear their backing storage before destruction.
    }
    for (auto& datagram : output.datagrams) {
        if (queue_.size() >= max_queue) {
            notices_.push_back({SamRuntimeNoticeKind::queue_full, 0});
            auto discard = std::find_if(queue_.begin(), queue_.end(),
                [](const Queued& item) { return !is_ack(item.datagram); });
            if (discard == queue_.end()) discard = queue_.begin();
            queue_.erase(discard);
        }
        Queued item{std::move(datagram), after(now.monotonic_ms, packet_lifetime_ms)};
        // Acknowledgements precede any ordinary send retained after would-block.
        if (is_ack(item.datagram)) {
            const auto position = std::find_if(queue_.begin(), queue_.end(),
                [](const Queued& existing) { return !is_ack(existing.datagram); });
            queue_.insert(position, std::move(item));
        } else queue_.push_back(std::move(item));
    }
}

SamRuntimeOutput SamRuntime::flush(SamTime now, const Sender& sender) {
    SamRuntimeOutput result;
    result.notices.swap(notices_);
    if (!configured_ || now.monotonic_ms < generation_started_) return result;
    std::erase_if(queue_, [&](const Queued& item) {
        if (now.monotonic_ms < item.expires) return false;
        result.notices.push_back({SamRuntimeNoticeKind::packet_expired, 0});
        return true;
    });
    if (now.monotonic_ms >= send_due_) {
        while (!queue_.empty()) {
            SamSendResult status;
            try {
                status = sender(queue_.front().datagram);
            } catch (...) {
                // An I/O exception has an uncertain transmission outcome.
                // Discard this datagram, exposing only a safe kind to logging.
                queue_.pop_front();
                result.notices.push_back({SamRuntimeNoticeKind::send_failed, 0});
                continue;
            }
            if (status == SamSendResult::cancelled) {
                stop();
                result.cancelled = true;
                return result;
            }
            if (status == SamSendResult::would_block) {
                send_due_ = after(now.monotonic_ms, would_block_delay_ms);
                break;
            }
            queue_.pop_front();
        }
    }
    if (termination_pending_ && (queue_.empty() || now.monotonic_ms >= termination_deadline_)) {
        result.notices.push_back({SamRuntimeNoticeKind::server_termination, 5});
        result.server_termination = true;
        stop();
    }
    return result;
}

SamRuntimeOutput SamRuntime::poll(SamTime now, const Sender& sender) {
    if (configured_ && now.monotonic_ms >= generation_started_ && session_.active())
        accept(session_.tick(now), now);
    return flush(now, sender);
}

SamRuntimeOutput SamRuntime::receive(const SamDatagram& datagram, SamTime now, const Sender& sender) {
    if (configured_ && now.monotonic_ms >= generation_started_ && session_.active())
        accept(session_.receive(datagram.source, datagram.destination, datagram.payload, now), now);
    return flush(now, sender);
}

std::optional<std::uint64_t> SamRuntime::next_deadline_ms() const noexcept {
    if (!configured_) return {};
    auto result = session_.next_deadline_ms();
    const auto include = [&](std::uint64_t value) {
        if (!result || value < *result) result = value;
    };
    if (!queue_.empty()) {
        include(send_due_);
        for (const auto& item : queue_) include(item.expires);
    }
    if (termination_pending_) include(termination_deadline_);
    return result;
}

} // namespace scau
