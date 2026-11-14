#include "list_scrollbar.hpp"
#include <stdexcept>
#include <windowsx.h>

namespace scau::desktop {
namespace {
constexpr wchar_t scrollbar_class[] = L"ScauLink.Native.ListScrollbar";
constexpr UINT frame_message = WM_APP + 117;
constexpr auto frame_interval = std::chrono::nanoseconds(16'666'667);
}
ListScrollbar::~ListScrollbar() {
    close_clock();
    if (list_ && IsWindow(list_))
        RemoveWindowSubclass(list_, list_proc, 0);
    if (window_ && IsWindow(window_))
        DestroyWindow(window_);
    release_buffer();
}
void ListScrollbar::attach(HWND list, UINT dpi, bool animations,
                           std::function<void(HDC, RECT, double)> paint_viewport) {
    list_ = list;
    dpi_ = dpi;
    animations_ = animations;
    paint_viewport_ = std::move(paint_viewport);
    WNDCLASSEXW wc{sizeof(wc)};
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpfnWndProc = proc;
    wc.lpszClassName = scrollbar_class;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);
    SetWindowLongPtrW(list_, GWL_STYLE, (GetWindowLongPtrW(list_, GWL_STYLE) | WS_CLIPSIBLINGS) & ~WS_VSCROLL);
    window_ = CreateWindowExW(0, scrollbar_class, L"滚动条", WS_CHILD | WS_CLIPSIBLINGS, 0, 0, 1, 1,
                              GetParent(list_), nullptr, wc.hInstance, this);
    if (!window_)
        throw std::runtime_error("Cannot create list scrollbar");
    SetWindowSubclass(list_, list_proc, 0, reinterpret_cast<DWORD_PTR>(this));
    sync(true);
}
void ListScrollbar::configure(UINT dpi, bool animations) {
    dpi_ = dpi;
    animations_ = animations;
    renderer_.reset();
    if (!animations_) {
        stop_frames();
        hover_.snap(hover_.target());
        scroll_.snap(scroll_.target());
    }
    viewport_width_ = viewport_height_ = -1;
    sync(true);
}
double ListScrollbar::thumb_position() const noexcept {
    return extent_ > 0 ? (track_height_ - thumb_height_) * offset() / extent_ : 0;
}
void ListScrollbar::publish_position() {
    if (!list_ || publishing_)
        return;
    const int index = int(std::round(offset())) / row_height_;
    if (index == top_)
        return;
    publishing_ = true;
    SendMessageW(list_, LB_SETTOPINDEX, index, 0);
    top_ = int(SendMessageW(list_, LB_GETTOPINDEX, 0, 0));
    publishing_ = false;
}
void ListScrollbar::sync(bool immediate) {
    if (!list_ || !window_ || syncing_ || native_update_ || publishing_)
        return;
    syncing_ = true;
    if (GetWindowLongPtrW(list_, GWL_STYLE) & WS_VSCROLL)
        ShowScrollBar(list_, SB_VERT, FALSE);
    RECT rect{};
    GetClientRect(list_, &rect);
    POINT origin{};
    MapWindowPoints(list_, GetParent(list_), &origin, 1);
    const int row = std::max(1, int(SendMessageW(list_, LB_GETITEMHEIGHT, 0, 0)));
    const int count = std::max(0, int(SendMessageW(list_, LB_GETCOUNT, 0, 0)));
    const int native_top = std::max(0, int(SendMessageW(list_, LB_GETTOPINDEX, 0, 0)));
    const bool metrics_changed = viewport_width_ != rect.right || viewport_height_ != rect.bottom ||
                                 count_ != count || row_height_ != row;
    const bool layout_changed = metrics_changed || viewport_origin_.x != origin.x || viewport_origin_.y != origin.y;
    const bool top_changed = native_top != top_;
    const bool reset = reset_pending_;
    const double previous = offset(), target = scroll_.target();
    const double scale = double(row) / row_height_;
    extent_ = std::max(0., double(count) * row - rect.bottom);
    count_ = count;
    row_height_ = row;
    top_ = native_top;
    viewport_width_ = rect.right;
    viewport_height_ = rect.bottom;
    viewport_origin_ = origin;
    if (reset) {
        scroll_.snap(std::clamp(double(native_top) * row, 0., extent_));
        reset_pending_ = false;
    } else if (metrics_changed) {
        scroll_.enter(std::clamp(previous * scale, 0., extent_), std::clamp(target * scale, 0., extent_));
        if (!animations_)
            scroll_.snap(scroll_.target());
    } else if (top_changed) {
        const double destination = std::clamp(double(native_top) * row, 0., extent_);
        if (immediate || !animations_)
            scroll_.snap(destination);
        else
            scroll_.move_to(destination);
    }
    const bool visible = extent_ > 0 && (GetWindowLongPtrW(list_, GWL_STYLE) & WS_VISIBLE);
    if (visible != bool(GetWindowLongPtrW(window_, GWL_STYLE) & WS_VISIBLE))
        ShowWindow(window_, visible ? SW_SHOWNA : SW_HIDE);
    // Content scrolling never moves HWNDs. Only viewport layout does.
    if (layout_changed)
        SetWindowPos(window_, HWND_TOP, origin.x + std::max(0L, rect.right - px(14)), origin.y + px(4),
                     px(14), std::max(1L, rect.bottom - px(8)), SWP_NOACTIVATE);
    track_height_ = float(std::max(1L, rect.bottom - px(8))) * 96 / dpi_;
    thumb_height_ = std::min(track_height_, std::max(28.f, track_height_ *
                                  float(rect.bottom) / float(std::max(1, count * row))));
    publish_position();
    if (metrics_changed || reset || offset() != previous)
        InvalidateRect(list_, nullptr, FALSE);
    if (layout_changed || top_changed || reset)
        InvalidateRect(window_, nullptr, FALSE);
    syncing_ = false;
    if (animations_ && (scroll_.active() || hover_.active()))
        animate();
}
void CALLBACK ListScrollbar::frame_ready(PTP_CALLBACK_INSTANCE, void *data, PTP_WAIT, TP_WAIT_RESULT) {
    auto &self = *static_cast<ListScrollbar *>(data);
    // No drawing or state mutation on the pool thread; at most one pulse is armed.
    PostMessageW(self.window_, frame_message, self.frame_generation_, 0);
}
void ListScrollbar::animate() {
    if (timer_running_ || !window_ || (!scroll_.active() && !hover_.active()))
        return;
    if (!clock_checked_) {
        clock_checked_ = true;
        frame_timer_ = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                              TIMER_MODIFY_STATE | SYNCHRONIZE);
        if (frame_timer_)
            frame_wait_ = CreateThreadpoolWait(frame_ready, this, nullptr);
        if (frame_timer_ && !frame_wait_) {
            CloseHandle(frame_timer_);
            frame_timer_ = nullptr;
        }
    }
    frame_ = std::chrono::steady_clock::now();
    next_frame_ = frame_ + frame_interval;
    ++frame_generation_;
    timer_running_ = true;
    schedule_frame();
}
void ListScrollbar::schedule_frame() {
    if (frame_timer_) {
        const auto delay = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               next_frame_ - std::chrono::steady_clock::now()).count();
        LARGE_INTEGER due{};
        due.QuadPart = -std::max(1LL, delay / 100);
        SetThreadpoolWait(frame_wait_, frame_timer_, nullptr);
        if (SetWaitableTimer(frame_timer_, &due, 0, nullptr, nullptr, FALSE))
            return;
        SetThreadpoolWait(frame_wait_, nullptr, nullptr);
        WaitForThreadpoolWaitCallbacks(frame_wait_, TRUE);
        CloseThreadpoolWait(frame_wait_);
        CloseHandle(frame_timer_);
        frame_wait_ = nullptr;
        frame_timer_ = nullptr;
    }
    // Older Windows builds keep a bounded native message-timer fallback.
    SetTimer(window_, 1, USER_TIMER_MINIMUM, nullptr);
}
void ListScrollbar::stop_frames() {
    if (window_)
        KillTimer(window_, 1);
    if (frame_timer_)
        CancelWaitableTimer(frame_timer_);
    if (frame_wait_) {
        SetThreadpoolWait(frame_wait_, nullptr, nullptr);
        WaitForThreadpoolWaitCallbacks(frame_wait_, TRUE);
    }
    timer_running_ = false;
    ++frame_generation_;
}
void ListScrollbar::close_clock() {
    stop_frames();
    if (frame_wait_)
        CloseThreadpoolWait(frame_wait_);
    if (frame_timer_)
        CloseHandle(frame_timer_);
    frame_wait_ = nullptr;
    frame_timer_ = nullptr;
}
void ListScrollbar::tick() {
    if (!timer_running_)
        return;
    const auto now = std::chrono::steady_clock::now();
    const double seconds = std::chrono::duration<double>(now - frame_).count();
    frame_ = now;
    const double previous = offset();
    scroll_.step_critical(seconds);
    hover_.step(seconds);
    if (offset() != previous) {
        publish_position();
        InvalidateRect(list_, nullptr, FALSE);
    }
    InvalidateRect(window_, nullptr, FALSE);
    if (!scroll_.active() && !hover_.active())
        stop_frames();
    else if (frame_timer_) {
        next_frame_ += frame_interval;
        if (next_frame_ <= now)
            next_frame_ = now + frame_interval;
        schedule_frame();
    }
}
void ListScrollbar::scroll_to(double value, bool immediate) {
    value = std::clamp(value, 0., extent_);
    if (immediate || !animations_)
        scroll_.snap(value);
    else if ((value - offset()) * scroll_.velocity() < 0)
        scroll_.enter(offset(), value);
    else
        scroll_.move_to(value);
    publish_position();
    InvalidateRect(list_, nullptr, FALSE);
    InvalidateRect(window_, nullptr, FALSE);
    if (animations_ && (scroll_.active() || hover_.active()))
        animate();
}
int ListScrollbar::hit_test(POINT point) const {
    RECT bounds{};
    GetClientRect(list_, &bounds);
    if (!PtInRect(&bounds, point))
        return -1;
    const int index = int(std::floor((point.y + std::round(offset())) / row_height_));
    return index >= 0 && index < count_ ? index : -1;
}
void ListScrollbar::select_at(POINT point) {
    const int index = hit_test(point);
    const int previous = int(SendMessageW(list_, LB_GETCURSEL, 0, 0));
    // Selecting a partly visible row must not invoke the native row-aligned
    // ensure-visible scroll or displace the continuous content under the pointer.
    publishing_ = true;
    SetFocus(list_);
    SendMessageW(list_, LB_SETCURSEL, index, 0);
    const int native_top = int(std::round(offset())) / row_height_;
    SendMessageW(list_, LB_SETTOPINDEX, native_top, 0);
    top_ = int(SendMessageW(list_, LB_GETTOPINDEX, 0, 0));
    publishing_ = false;
    InvalidateRect(list_, nullptr, FALSE);
    if (index != previous && (GetWindowLongPtrW(list_, GWL_STYLE) & LBS_NOTIFY))
        SendMessageW(GetParent(list_), WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(list_), LBN_SELCHANGE),
                     reinterpret_cast<LPARAM>(list_));
}
void ListScrollbar::release_buffer() {
    if (buffer_dc_ && buffer_original_)
        SelectObject(buffer_dc_, buffer_original_);
    if (buffer_bitmap_)
        DeleteObject(buffer_bitmap_);
    if (buffer_dc_)
        DeleteDC(buffer_dc_);
    buffer_dc_ = nullptr;
    buffer_bitmap_ = nullptr;
    buffer_original_ = nullptr;
    buffer_size_ = {};
}
void ListScrollbar::paint_list(HDC dc) {
    RECT rect{};
    GetClientRect(list_, &rect);
    if (!dc || !paint_viewport_ || rect.right <= 0 || rect.bottom <= 0)
        return;
    if (buffer_size_.cx != rect.right || buffer_size_.cy != rect.bottom) {
        release_buffer();
        buffer_dc_ = CreateCompatibleDC(dc);
        buffer_bitmap_ = CreateCompatibleBitmap(dc, rect.right, rect.bottom);
        if (buffer_dc_ && buffer_bitmap_) {
            buffer_original_ = SelectObject(buffer_dc_, buffer_bitmap_);
            buffer_size_ = {rect.right, rect.bottom};
        } else
            release_buffer();
    }
    paint_viewport_(buffer_dc_ ? buffer_dc_ : dc, rect, offset());
    if (buffer_dc_)
        BitBlt(dc, 0, 0, rect.right, rect.bottom, buffer_dc_, 0, 0, SRCCOPY);
}
void ListScrollbar::paint() {
    PAINTSTRUCT ps{};
    const auto dc = BeginPaint(window_, &ps);
    RECT rect{};
    GetClientRect(window_, &rect);
    if (renderer_.begin(dc, rect, dpi_, visual::White)) {
        const float width = float(rect.right) * 96 / dpi_, height = float(rect.bottom) * 96 / dpi_;
        const double hot = std::clamp(hover_.value(), 0., 1.);
        if (hot > .001)
            renderer_.fill({2, 0, width - 4, height}, visual::mix(visual::White, visual::Soft, hot), 5);
        const float side = dragging_ ? 7.f : float(4 + 2 * hot);
        const float y = std::clamp(float(thumb_position()), 0.f, std::max(0.f, height - thumb_height_));
        renderer_.fill({(width - side) / 2, y, side, thumb_height_},
                       visual::mix(RGB(184, 202, 188), visual::Pine, dragging_ ? .8 : hot * .6), side / 2);
        renderer_.end();
    }
    EndPaint(window_, &ps);
}
LRESULT CALLBACK ListScrollbar::list_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR data) {
    auto &self = *reinterpret_cast<ListScrollbar *>(data);
    if (m == WM_ERASEBKGND)
        return TRUE;
    if (m == WM_PAINT || m == WM_PRINTCLIENT) {
        PAINTSTRUCT ps{};
        const auto dc = m == WM_PAINT ? BeginPaint(h, &ps) : reinterpret_cast<HDC>(w);
        if (self.redraw_)
            self.paint_list(dc);
        if (m == WM_PAINT)
            EndPaint(h, &ps);
        return 0;
    }
    if (m == WM_MOUSEWHEEL) {
        UINT lines = 3;
        SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &lines, 0);
        const double distance = lines == WHEEL_PAGESCROLL ? self.viewport_height_ :
                                  double(std::min(lines, 1000U)) * self.row_height_;
        if (distance)
            self.scroll_to(self.scroll_.target() - double(GET_WHEEL_DELTA_WPARAM(w)) / WHEEL_DELTA * distance);
        return 0;
    }
    if (m == WM_LBUTTONDOWN || m == WM_LBUTTONDBLCLK) {
        self.scroll_.snap(self.offset());
        self.selecting_ = true;
        self.select_at({GET_X_LPARAM(l), GET_Y_LPARAM(l)});
        SetCapture(h);
        if (m == WM_LBUTTONDBLCLK && (GetWindowLongPtrW(h, GWL_STYLE) & LBS_NOTIFY))
            SendMessageW(GetParent(h), WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(h), LBN_DBLCLK), reinterpret_cast<LPARAM>(h));
        return 0;
    }
    if (m == WM_MOUSEMOVE && self.selecting_) {
        self.select_at({GET_X_LPARAM(l), GET_Y_LPARAM(l)});
        return 0;
    }
    if (m == WM_LBUTTONUP && self.selecting_) {
        self.selecting_ = false;
        if (GetCapture() == h)
            ReleaseCapture();
        return 0;
    }
    if (m == WM_CAPTURECHANGED || m == WM_CANCELMODE)
        self.selecting_ = false;
    if (m == LB_ITEMFROMPOINT) {
        const int index = self.hit_test({GET_X_LPARAM(l), GET_Y_LPARAM(l)});
        if (index >= 0)
            return MAKELRESULT(index, 0);
    }
    if (m == LB_RESETCONTENT)
        self.reset_pending_ = true;
    // Only the full buffered WM_PAINT can present changes to the viewport.
    const bool changes_display =
        m == LB_ADDSTRING || m == LB_INSERTSTRING || m == LB_DELETESTRING || m == LB_RESETCONTENT ||
        m == LB_SETTOPINDEX || m == LB_SETCURSEL || m == LB_SETSEL || m == LB_SETCARETINDEX ||
        m == LB_SELECTSTRING || m == LB_SELITEMRANGE || m == LB_SELITEMRANGEEX ||
        m == WM_VSCROLL || m == WM_KEYDOWN || m == WM_CHAR || m == WM_TIMER ||
        m == WM_SETFOCUS || m == WM_KILLFOCUS || m == WM_UPDATEUISTATE;
    const bool update = changes_display && self.redraw_ && !self.native_update_ &&
                        (GetWindowLongPtrW(h, GWL_STYLE) & WS_VISIBLE);
    if (update) {
        self.native_update_ = true;
        DefSubclassProc(h, WM_SETREDRAW, FALSE, 0);
    }
    const auto result = DefSubclassProc(h, m, w, l);
    const bool explicit_top = m == LB_SETTOPINDEX && !self.publishing_ && self.redraw_;
    const int requested_top = explicit_top ? int(SendMessageW(h, LB_GETTOPINDEX, 0, 0)) : 0;
    if (update) {
        DefSubclassProc(h, WM_SETREDRAW, TRUE, 0);
        self.native_update_ = false;
        if (!explicit_top)
            self.sync();
        InvalidateRect(h, nullptr, FALSE);
    }
    if (explicit_top) {
        self.top_ = requested_top;
        self.scroll_to(double(requested_top) * self.row_height_);
    }
    if (m == WM_KEYDOWN && (w == VK_HOME || w == VK_END))
        self.scroll_to(w == VK_HOME ? 0 : self.extent_);
    if (m == LB_GETITEMRECT && result != LB_ERR && l)
        OffsetRect(reinterpret_cast<RECT *>(l), 0, int(self.top_ * self.row_height_ - std::round(self.offset())));
    switch (m) {
    case WM_SETREDRAW:
        self.redraw_ = w != 0;
        if (self.redraw_)
            self.sync(true);
        break;
    case WM_SIZE:
    case WM_WINDOWPOSCHANGED:
    case LB_SETITEMHEIGHT:
    case LB_RESETCONTENT:
        if (self.redraw_)
            self.sync(true);
        break;
    case LB_ADDSTRING:
    case LB_DELETESTRING:
    case LB_SETTOPINDEX:
    case WM_VSCROLL:
    case WM_KEYDOWN:
    case WM_TIMER:
        if (self.redraw_)
            self.sync();
        break;
    case WM_NCDESTROY:
        RemoveWindowSubclass(h, list_proc, 0);
        self.close_clock();
        self.list_ = nullptr;
        if (self.window_)
            DestroyWindow(self.window_);
        break;
    }
    return result;
}
LRESULT CALLBACK ListScrollbar::proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    auto *self = reinterpret_cast<ListScrollbar *>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        self = static_cast<ListScrollbar *>(reinterpret_cast<CREATESTRUCTW *>(l)->lpCreateParams);
        self->window_ = h;
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    if (!self)
        return DefWindowProcW(h, m, w, l);
    if (m == frame_message) {
        if (w == self->frame_generation_)
            self->tick();
        return 0;
    }
    switch (m) {
    case WM_MOUSEMOVE: {
        TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE, h, 0};
        TrackMouseEvent(&track);
        if (self->animations_)
            self->hover_.move_to(1);
        else
            self->hover_.snap(1);
        if (self->dragging_) {
            const double y = double(GET_Y_LPARAM(l)) * 96 / self->dpi_ - self->grab_offset_;
            const double travel = self->track_height_ - self->thumb_height_;
            self->scroll_to(travel > 0 ? y / travel * self->extent_ : 0, true);
        }
        if (self->animations_)
            self->animate();
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    }
    case WM_MOUSELEAVE:
        if (!self->dragging_) {
            if (self->animations_)
                self->hover_.move_to(0);
            else
                self->hover_.snap(0);
            if (self->animations_)
                self->animate();
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN: {
        // Taking the thumb interrupts momentum at its displayed pixel position.
        self->scroll_.snap(self->offset());
        self->publishing_ = true;
        SetFocus(self->list_);
        self->publishing_ = false;
        self->top_ = int(SendMessageW(self->list_, LB_GETTOPINDEX, 0, 0));
        self->publish_position();
        const double y = double(GET_Y_LPARAM(l)) * 96 / self->dpi_;
        const double top = self->thumb_position();
        if (y >= top && y <= top + self->thumb_height_) {
            self->dragging_ = true;
            self->grab_offset_ = y - top;
            SetCapture(h);
            InvalidateRect(h, nullptr, FALSE);
        } else
            self->scroll_to(self->offset() + (y < top ? -self->viewport_height_ : self->viewport_height_));
        return 0;
    }
    case WM_LBUTTONUP:
        if (GetCapture() == h)
            ReleaseCapture();
        return 0;
    case WM_CAPTURECHANGED:
    case WM_CANCELMODE:
        self->dragging_ = false;
        if (self->animations_) {
            self->hover_.move_to(0);
            self->animate();
        } else
            self->hover_.snap(0);
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    case WM_MOUSEWHEEL:
        return SendMessageW(self->list_, m, w, l);
    case WM_PAINT:
        self->paint();
        return 0;
    case WM_ERASEBKGND:
        return TRUE;
    case WM_TIMER:
        self->tick();
        return 0;
    case WM_NCDESTROY:
        self->close_clock();
        self->window_ = nullptr;
        break;
    }
    return DefWindowProcW(h, m, w, l);
}
} // namespace scau::desktop
