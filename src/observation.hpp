#pragma once
#include <chrono>

namespace scau {
struct ObservationDecision {
    bool report_result = false;
    bool disconnect = false;
};

// An observation deadline is not a session deadline. Keep the authenticated
// connection until a separate stop request unless explicitly configured otherwise.
class ObservationWindow {
    std::chrono::seconds duration_;
    bool disconnect_after_;
    bool reported_ = false;
public:
    explicit ObservationWindow(unsigned seconds, bool disconnect_after = false)
        : duration_(seconds), disconnect_after_(disconnect_after) {}

    ObservationDecision advance(std::chrono::seconds online_time) {
        if (reported_ || online_time < duration_) return {};
        reported_ = true;
        return {true, disconnect_after_};
    }
    bool reported() const { return reported_; }
};
}
