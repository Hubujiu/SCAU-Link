#pragma once
#include "spring.hpp"
#include "visual.hpp"
#include <commctrl.h>
#include <chrono>
#include <functional>

namespace scau::desktop {
// Retains native selection/keyboard/accessibility, but presents a whole viewport
// from a reusable buffer. The scrollbar is a sibling, outside LISTBOX scrolling.
class ListScrollbar {
    HWND list_{}, window_{};
    UINT dpi_ = 96;
    bool animations_ = true, dragging_ = false, syncing_ = false, redraw_ = true;
    bool timer_running_ = false, native_update_ = false, publishing_ = false;
    bool reset_pending_ = false, selecting_ = false, clock_checked_ = false;
    int top_{}, count_{}, row_height_ = 1;
    double extent_{}, grab_offset_{};
    int viewport_width_ = -1, viewport_height_ = -1;
    POINT viewport_origin_{-1, -1};
    HDC buffer_dc_{};
    HBITMAP buffer_bitmap_{};
    HGDIOBJ buffer_original_{};
    SIZE buffer_size_{};
    std::function<void(HDC, RECT, double)> paint_viewport_;
    float track_height_{}, thumb_height_{};
    Spring scroll_, hover_;
    HANDLE frame_timer_{};
    PTP_WAIT frame_wait_{};
    UINT_PTR frame_generation_{};
    std::chrono::steady_clock::time_point frame_{}, next_frame_{};
    visual::Renderer renderer_;
    int px(int value) const { return MulDiv(value, int(dpi_), 96); }
    void animate();
    void schedule_frame();
    void stop_frames();
    void close_clock();
    static void CALLBACK frame_ready(PTP_CALLBACK_INSTANCE, void *, PTP_WAIT, TP_WAIT_RESULT);
    void tick();
    void paint();
    void paint_list(HDC);
    void release_buffer();
    void scroll_to(double, bool immediate = false);
    void publish_position();
    int hit_test(POINT) const;
    void select_at(POINT);
    static LRESULT CALLBACK proc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK list_proc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);

  public:
    ~ListScrollbar();
    void attach(HWND list, UINT dpi, bool animations, std::function<void(HDC, RECT, double)> paint_viewport);
    void configure(UINT dpi, bool animations);
    void sync(bool immediate = false);
    bool animating() const noexcept { return timer_running_; }
    double offset() const noexcept { return std::clamp(scroll_.value(), 0., extent_); }
    double target_offset() const noexcept { return scroll_.target(); }
    double scroll_range() const noexcept { return extent_; }
    double thumb_position() const noexcept;
};
} // namespace scau::desktop
