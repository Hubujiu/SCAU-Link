#pragma once
#include <algorithm>
#include <cmath>

namespace scau::desktop {
// Analytic underdamped spring. Retargeting preserves position and velocity;
// dt is wall time, not a frame count, so delayed frames cannot destabilize it.
class Spring {
    double position_ = 0, velocity_ = 0, target_ = 0;

  public:
    double value() const noexcept {
        return position_;
    }
    double velocity() const noexcept {
        return velocity_;
    }
    double target() const noexcept {
        return target_;
    }
    void snap(double value) noexcept {
        position_ = target_ = value;
        velocity_ = 0;
    }
    void move_to(double value) noexcept {
        target_ = value;
    }
    void enter(double from, double to = 0) noexcept {
        position_ = from;
        velocity_ = 0;
        target_ = to;
    }
    bool active() const noexcept {
        return std::abs(position_ - target_) > .08 || std::abs(velocity_) > .3;
    }
    // Critical damping keeps reading content from rebounding past its target.
    // Other UI transitions retain the underdamped step() below.
    void step_critical(double seconds) noexcept {
        if (!active()) {
            snap(target_);
            return;
        }
        const double dt = std::clamp(seconds, 0., .25), frequency = 24.;
        const double a = position_ - target_, b = velocity_ + frequency * a;
        const double decay = std::exp(-frequency * dt);
        position_ = target_ + (a + b * dt) * decay;
        velocity_ = (velocity_ - frequency * b * dt) * decay;
        if (!active())
            snap(target_);
    }
    void step(double seconds) noexcept {
        if (!active()) {
            snap(target_);
            return;
        }
        const auto dt = std::clamp(seconds, 0., .25);
        constexpr double damping = 12., frequency = 18.;
        const double a = position_ - target_, b = (velocity_ + damping * a) / frequency;
        const double c = std::cos(frequency * dt), s = std::sin(frequency * dt),
                     decay = std::exp(-damping * dt);
        position_ = target_ + decay * (a * c + b * s);
        velocity_ = decay * ((b * frequency - damping * a) * c - (a * frequency + damping * b) * s);
        if (!active())
            snap(target_);
    }
};
} // namespace scau::desktop
