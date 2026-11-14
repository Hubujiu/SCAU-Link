#pragma once
#include <windows.h>
#include "spring.hpp"
#include <functional>
#include <vector>

namespace scau::desktop {
// Mouse capture is explicit, so a drag can start anywhere on a strip without
// the delay/gesture policy of the common-controls drag-list helper.
class AccountPointer {
    HWND list_{}, floating_{};
    UINT dpi_ = 96;
    int row_ = 84, gap_ = 12, radius_ = 9;
    int from_ = -1, target_ = -1;
    bool dragging_ = false, scrolling_ = false, settling_ = false, releasing_ = false, animations_ = true,
         pending_commit_ = false, drag_cursor_set_ = false;
    int slot_ = -1, floating_width_ = 0, floating_height_ = 0;
    POINT origin_{}, cursor_{}, grab_{};
    Spring lift_, landing_x_, landing_y_;
    std::vector<Spring> offsets_;
    ULONGLONG frame_ = 0;
    std::function<void(int)> selected_;
    std::function<void(int, int)> moved_;
    std::function<void(HDC, RECT, int)> paint_floating_;
    static LRESULT CALLBACK proc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
    static LRESULT CALLBACK floating_proc(HWND, UINT, WPARAM, LPARAM);
    void begin(POINT point);
    void lift();
    void preview(int slot);
    void place_floating();
    void animate();
    void tick();
    void release();
    void set_drag_cursor();
    void update(POINT point, bool scroll);
    void finish(bool commit);
    void complete(bool commit);
    int destination(POINT point) const;

  public:
    ~AccountPointer();
    void attach(HWND list, std::function<void(int)> selected, std::function<void(int, int)> moved,
                std::function<void(HDC, RECT, int)> paint_floating = {});
    void geometry(UINT dpi, int row, int gap, int radius, bool animations = true);
    int hit_test(POINT point) const;
    void clear_selection();
    void cancel() { complete(false); }
    bool active() const { return from_ >= 0; }
    bool dragging() const { return dragging_; }
    bool settling() const { return settling_; }
    bool lifted() const { return dragging_ || settling_; }
    int from() const { return from_; }
    int target() const { return target_; }
    int slot() const { return slot_; }
    double row_offset(int index) const;
    RECT floating_rect() const;
};
} // namespace scau::desktop
