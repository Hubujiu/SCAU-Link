#pragma once

#include "sam.hpp"

#include <deque>
#include <functional>

namespace scau {

enum class SamSendResult { sent, would_block, cancelled };

enum class SamRuntimeNoticeKind {
    server_message,
    server_termination,
    send_confirmed,
    send_failed,
    packet_expired,
    queue_full,
};

struct SamRuntimeNotice {
    SamRuntimeNoticeKind kind{};
    Byte command{};
};

struct SamRuntimeOutput {
    std::vector<SamRuntimeNotice> notices;
    bool server_termination{};
    bool cancelled{};
};

// The only I/O capability is the caller's datagram sender. A stop request
// is represented explicitly by cancelled, never by a retryable error.
class SamRuntime {
public:
    using Sender = std::function<SamSendResult(const SamDatagram&)>;

    SamRuntime() = default;
    ~SamRuntime();
    SamRuntime(const SamRuntime&) = delete;
    SamRuntime& operator=(const SamRuntime&) = delete;

    // Starts a fresh generation and retains the initial HELLO for poll().
    // Only SamSession retains the configuration and session material.
    void configure(const SamConfig& config, SamTime now);
    SamRuntimeOutput receive(const SamDatagram& datagram, SamTime now, const Sender& sender);
    SamRuntimeOutput poll(SamTime now, const Sender& sender);
    void stop() noexcept;
    bool configured() const noexcept { return configured_; }
    bool active() const noexcept { return configured_ && session_.active(); }
    std::optional<std::uint64_t> next_deadline_ms() const noexcept;

private:
    struct Queued {
        SamDatagram datagram;
        std::uint64_t expires{};
    };
    SamSession session_;
    std::deque<Queued> queue_;
    std::vector<SamRuntimeNotice> notices_;
    bool configured_{}, termination_pending_{};
    std::uint64_t generation_started_{}, send_due_{}, termination_deadline_{};

    void accept(SamOutput output, SamTime now);
    SamRuntimeOutput flush(SamTime now, const Sender& sender);
};

} // namespace scau
