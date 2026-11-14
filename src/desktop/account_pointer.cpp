#include "account_pointer.hpp"
#include <algorithm>
#include <commctrl.h>
#include <cstdlib>
#include <dwmapi.h>
#include <stdexcept>
#include <utility>
#include <windowsx.h>

namespace scau::desktop {
namespace {
constexpr UINT_PTR scroll_timer = 0x5343;
constexpr UINT_PTR hold_timer = 0x5344, motion_timer = 0x5345;
constexpr wchar_t floating_class[] = L"ScauLink.Native.FloatingAccount";
} // namespace
AccountPointer::~AccountPointer() {
    if (list_ && IsWindow(list_)) {
        cancel();
        RemoveWindowSubclass(list_, proc, 0);
    }
    if (floating_ && IsWindow(floating_))
        DestroyWindow(floating_);
}
void AccountPointer::attach(HWND list, std::function<void(int)> selected, std::function<void(int, int)> moved,
                            std::function<void(HDC, RECT, int)> paint_floating) {
    if (list_ || !list || !SetWindowSubclass(list, proc, 0, reinterpret_cast<DWORD_PTR>(this)))
        throw std::runtime_error("Cannot attach account pointer interaction");
    list_ = list;
    selected_ = std::move(selected);
    moved_ = std::move(moved);
    paint_floating_ = std::move(paint_floating);
}
void AccountPointer::geometry(UINT dpi, int row, int gap, int radius, bool animations) {
    if (dpi_ != dpi || row_ != row || gap_ != gap || radius_ != radius || animations_ != animations)
        cancel();
    dpi_ = dpi;
    row_ = row;
    gap_ = gap;
    radius_ = radius;
    animations_ = animations;
}
int AccountPointer::hit_test(POINT point) const {
    if (!list_)
        return -1;
    RECT client{};
    GetClientRect(list_, &client);
    if (!PtInRect(&client, point))
        return -1;
    const int count = int(SendMessageW(list_, LB_GETCOUNT, 0, 0));
    const int index = int(SendMessageW(list_, LB_GETTOPINDEX, 0, 0)) + point.y / row_;
    if (index < 0 || index >= count)
        return -1;
    RECT item{};
    SendMessageW(list_, LB_GETITEMRECT, index, reinterpret_cast<LPARAM>(&item));
    item.bottom -= gap_;
    if (!PtInRect(&item, point))
        return -1;
    const int x = point.x - item.left, y = point.y - item.top;
    const int dx = std::max({radius_ - x, 0, x - int(item.right - item.left - radius_)});
    const int dy = std::max({radius_ - y, 0, y - int(item.bottom - item.top - radius_)});
    return dx * dx + dy * dy <= radius_ * radius_ ? index : -1;
}
int AccountPointer::destination(POINT point) const {
    RECT client{};
    GetClientRect(list_, &client);
    if (point.x < client.left || point.x >= client.right)
        return -1;
    const int count = int(SendMessageW(list_, LB_GETCOUNT, 0, 0));
    if (count <= 0)
        return -1;
    // The lifted strip's center decides the slot, independent of the grab point.
    point.y += (row_ - gap_) / 2 - grab_.y;
    const int y = int(std::clamp(point.y, 0L, std::max(0L, client.bottom - 1)));
    const int index = int(SendMessageW(list_, LB_GETTOPINDEX, 0, 0)) + y / row_;
    if (index >= count)
        return count - 1;
    if (y % row_ >= row_ - gap_) {
        const int insertion = index + 1;
        return std::clamp(insertion - (from_ < insertion ? 1 : 0), 0, count - 1);
    }
    return index;
}
void AccountPointer::clear_selection() {
    if (!list_)
        return;
    cancel();
    SendMessageW(list_, LB_SETCURSEL, WPARAM(-1), 0);
    SetFocus(GetParent(list_));
    if (selected_)
        selected_(-1);
    InvalidateRect(list_, nullptr, FALSE);
}
void AccountPointer::begin(POINT point) {
    if (settling_)
        return;
    cancel();
    const int index = hit_test(point);
    if (index < 0) {
        clear_selection();
        return;
    }
    from_ = target_ = index;
    origin_ = cursor_ = point;
    RECT item{};
    SendMessageW(list_, LB_GETITEMRECT, index, reinterpret_cast<LPARAM>(&item));
    grab_ = {point.x, point.y - item.top};
    SendMessageW(list_, LB_SETCURSEL, index, 0);
    SetFocus(list_);
    if (selected_)
        selected_(index);
    SetCapture(list_);
    SetTimer(list_, hold_timer, 220, nullptr);
    InvalidateRect(list_, nullptr, FALSE);
}
double AccountPointer::row_offset(int index) const {
    return index >= 0 && std::size_t(index) < offsets_.size() ? offsets_[std::size_t(index)].value() : 0.;
}
RECT AccountPointer::floating_rect() const {
    RECT client{};
    GetClientRect(list_, &client);
    const int expansion = int(std::round(MulDiv(4, int(dpi_), 96) * lift_.value()));
    const int elevation = int(std::round(MulDiv(6, int(dpi_), 96) * lift_.value()));
    const int x = settling_ ? int(std::round(landing_x_.value())) : cursor_.x - grab_.x;
    const int y = settling_ ? int(std::round(landing_y_.value())) : cursor_.y - grab_.y;
    return {x - expansion, y - elevation, x + client.right + expansion,
            y - elevation + row_ - gap_ + expansion};
}
void AccountPointer::lift() {
    if (!active() || dragging_ || settling_)
        return;
    KillTimer(list_, hold_timer);
    dragging_ = true;
    slot_ = from_;
    offsets_.resize(std::size_t(std::max<LRESULT>(0, SendMessageW(list_, LB_GETCOUNT, 0, 0))));
    for (auto &offset : offsets_)
        offset.snap(0);
    lift_.snap(1);
    if (animations_)
        lift_.enter(0, 1);
    if (paint_floating_ && IsWindowVisible(list_) && !floating_) {
        WNDCLASSEXW wc{sizeof(wc)};
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpfnWndProc = floating_proc;
        wc.lpszClassName = floating_class;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.style = CS_DROPSHADOW;
        RegisterClassExW(&wc);
        floating_ = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT, floating_class,
                                    L"拖动账号", WS_POPUP, 0, 0, 1, 1, GetAncestor(list_, GA_ROOT), nullptr,
                                    wc.hInstance, this);
        if (floating_) {
            const int corners = 2;
            DwmSetWindowAttribute(floating_, static_cast<DWMWINDOWATTRIBUTE>(33), &corners, sizeof(corners));
        }
    }
    place_floating();
    set_drag_cursor();
    if (floating_)
        InvalidateRect(floating_, nullptr, FALSE);
    InvalidateRect(list_, nullptr, FALSE);
    if (animations_)
        animate();
}
void AccountPointer::preview(int slot) {
    if (slot < 0 || slot == slot_)
        return;
    slot_ = slot;
    for (std::size_t i = 0; i < offsets_.size(); ++i) {
        const int index = int(i);
        int destination = index;
        if (index != from_) {
            if (from_ < slot_ && index > from_ && index <= slot_)
                --destination;
            if (from_ > slot_ && index >= slot_ && index < from_)
                ++destination;
        }
        const double offset = (destination - index) * row_;
        if (animations_)
            offsets_[i].move_to(offset);
        else
            offsets_[i].snap(offset);
    }
    if (animations_)
        animate();
}
void AccountPointer::place_floating() {
    if (!floating_ || !lifted() || !IsWindowVisible(list_))
        return;
    RECT rect = floating_rect();
    POINT origin{rect.left, rect.top};
    ClientToScreen(list_, &origin);
    const int width = rect.right - rect.left, height = rect.bottom - rect.top;
    const bool resized = width != floating_width_ || height != floating_height_;
    if (resized) {
        const int radius = radius_ * 2;
        const auto region = CreateRoundRectRgn(0, 0, width + 1, height + 1, radius, radius);
        if (region && !SetWindowRgn(floating_, region, FALSE))
            DeleteObject(region);
        floating_width_ = width;
        floating_height_ = height;
    }
    SetWindowPos(floating_, HWND_TOP, origin.x, origin.y, width, height,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOOWNERZORDER);
    if (resized)
        InvalidateRect(floating_, nullptr, FALSE);
}
void AccountPointer::animate() {
    if (!frame_) {
        frame_ = GetTickCount64();
        SetTimer(list_, motion_timer, 16, nullptr);
    }
}
void AccountPointer::tick() {
    if (!active() || !IsWindowVisible(list_)) {
        cancel();
        return;
    }
    const auto now = GetTickCount64();
    const double seconds = double(now - frame_) / 1000.;
    frame_ = now;
    lift_.step(seconds);
    bool moving = lift_.active();
    for (auto &offset : offsets_) {
        offset.step(seconds);
        moving |= offset.active();
    }
    if (settling_) {
        landing_x_.step(seconds);
        landing_y_.step(seconds);
        moving |= landing_x_.active() || landing_y_.active();
    }
    place_floating();
    InvalidateRect(list_, nullptr, FALSE);
    if (!moving) {
        KillTimer(list_, motion_timer);
        frame_ = 0;
        if (settling_)
            complete(pending_commit_);
    }
}
void AccountPointer::release() {
    const bool captured = GetCapture() == list_;
    const bool restore_cursor = drag_cursor_set_;
    drag_cursor_set_ = false;
    releasing_ = true;
    if (captured)
        ReleaseCapture();
    releasing_ = false;
    if (captured || restore_cursor)
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
}
void AccountPointer::set_drag_cursor() {
    // Shared system hand follows the user's current cursor scheme. Win32
    // defines no separate grab/grabbing cursor; never create or own a bitmap.
    SetCursor(LoadCursorW(nullptr, IDC_HAND));
    drag_cursor_set_ = true;
}
void AccountPointer::update(POINT point, bool scroll) {
    if (!active() || settling_)
        return;
    cursor_ = point;
    if (!dragging_) {
        const int dx = GetSystemMetricsForDpi(SM_CXDRAG, dpi_);
        const int dy = GetSystemMetricsForDpi(SM_CYDRAG, dpi_);
        if (std::abs(point.x - origin_.x) < dx && std::abs(point.y - origin_.y) < dy)
            return;
        lift();
    }
    RECT client{};
    GetClientRect(list_, &client);
    const int top = int(SendMessageW(list_, LB_GETTOPINDEX, 0, 0));
    const int count = int(SendMessageW(list_, LB_GETCOUNT, 0, 0));
    const int visible = std::max(1L, client.bottom / row_);
    const int edge = MulDiv(14, int(dpi_), 96);
    int step = 0;
    if (point.x >= 0 && point.x < client.right) {
        if (point.y < edge && top > 0)
            step = -1;
        else if (point.y > client.bottom - edge && top + visible < count)
            step = 1;
    }
    if (step && scroll)
        SendMessageW(list_, LB_SETTOPINDEX, top + step, 0);
    if (step && !scrolling_) {
        SetTimer(list_, scroll_timer, 70, nullptr);
        scrolling_ = true;
    }
    if (!step && scrolling_) {
        KillTimer(list_, scroll_timer);
        scrolling_ = false;
    }
    target_ = destination(point);
    preview(target_);
    place_floating();
    set_drag_cursor();
    InvalidateRect(list_, nullptr, FALSE);
}
void AccountPointer::finish(bool commit) {
    if (!active() || settling_)
        return;
    KillTimer(list_, hold_timer);
    KillTimer(list_, scroll_timer);
    scrolling_ = false;
    if (dragging_ && floating_ && IsWindowVisible(floating_) && animations_) {
        pending_commit_ = commit && target_ >= 0;
        const int destination = pending_commit_ ? target_ : from_;
        preview(destination);
        landing_x_.snap(cursor_.x - grab_.x);
        landing_y_.snap(cursor_.y - grab_.y);
        landing_x_.move_to(0);
        landing_y_.move_to((destination - int(SendMessageW(list_, LB_GETTOPINDEX, 0, 0))) * row_);
        lift_.move_to(0);
        dragging_ = false;
        settling_ = true;
        release();
        animate();
        return;
    }
    complete(commit);
}
void AccountPointer::complete(bool commit) {
    if (!list_)
        return;
    const int from = from_, target = target_;
    const bool move = commit && lifted() && from >= 0 && target >= 0 && from != target;
    // ReleaseCapture synchronously sends WM_CAPTURECHANGED. Clear first so
    // that cancellation cannot erase the valid drop or invoke it twice.
    from_ = target_ = slot_ = -1;
    dragging_ = settling_ = pending_commit_ = false;
    scrolling_ = false;
    frame_ = 0;
    offsets_.clear();
    lift_.snap(0);
    KillTimer(list_, scroll_timer);
    KillTimer(list_, hold_timer);
    KillTimer(list_, motion_timer);
    release();
    if (floating_)
        ShowWindow(floating_, SW_HIDE);
    InvalidateRect(list_, nullptr, FALSE);
    if (move && moved_)
        moved_(from, target);
}
LRESULT CALLBACK AccountPointer::floating_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    auto *self = reinterpret_cast<AccountPointer *>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        self = static_cast<AccountPointer *>(reinterpret_cast<CREATESTRUCTW *>(l)->lpCreateParams);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    if (!self)
        return DefWindowProcW(h, m, w, l);
    switch (m) {
    case WM_SETCURSOR:
        if (self->dragging_) {
            self->set_drag_cursor();
            return TRUE;
        }
        break;
    case WM_NCHITTEST:
        return HTTRANSPARENT;
    case WM_MOUSEACTIVATE:
        return MA_NOACTIVATE;
    case WM_ERASEBKGND:
        return TRUE;
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        const auto dc = BeginPaint(h, &ps);
        RECT client{};
        GetClientRect(h, &client);
        if (self->paint_floating_ && self->from_ >= 0)
            self->paint_floating_(dc, client, self->from_);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_NCDESTROY:
        self->floating_ = nullptr;
        break;
    }
    return DefWindowProcW(h, m, w, l);
}
LRESULT CALLBACK AccountPointer::proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR data) {
    auto &self = *reinterpret_cast<AccountPointer *>(data);
    switch (m) {
    case WM_LBUTTONDOWN:
    case WM_LBUTTONDBLCLK:
        self.begin({GET_X_LPARAM(l), GET_Y_LPARAM(l)});
        return 0;
    case WM_MOUSEMOVE:
        if (self.settling_)
            return 0;
        if (self.active()) {
            if (!(w & MK_LBUTTON))
                self.cancel();
            else
                self.update({GET_X_LPARAM(l), GET_Y_LPARAM(l)}, false);
            return 0;
        }
        break;
    case WM_LBUTTONUP:
        if (self.active()) {
            const POINT point{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
            if (self.dragging_)
                self.update(point, false);
            RECT client{};
            GetClientRect(h, &client);
            self.finish(PtInRect(&client, point) != FALSE);
            return 0;
        }
        break;
    case WM_SETCURSOR:
        if (self.dragging_) {
            self.set_drag_cursor();
            return TRUE;
        }
        break;
    case WM_TIMER:
        if (w == hold_timer) {
            KillTimer(h, hold_timer);
            if (GetCapture() == h)
                self.lift();
            return 0;
        }
        if (w == motion_timer) {
            self.tick();
            return 0;
        }
        if (w == scroll_timer) {
            if (!(GetKeyState(VK_LBUTTON) & 0x8000))
                self.cancel();
            else {
                POINT point{};
                GetCursorPos(&point);
                ScreenToClient(h, &point);
                self.update(point, true);
            }
            return 0;
        }
        break;
    case WM_CAPTURECHANGED:
        if (self.releasing_)
            return 0;
        [[fallthrough]];
    case WM_CANCELMODE:
        self.cancel();
        break;
    case WM_SHOWWINDOW:
        if (!w)
            self.cancel();
        break;
    case WM_MOUSEWHEEL:
    case WM_KEYDOWN:
        if (self.lifted())
            return 0;
        break;
    case WM_NCDESTROY:
        self.cancel();
        self.list_ = nullptr;
        RemoveWindowSubclass(h, proc, 0);
        break;
    }
    return DefSubclassProc(h, m, w, l);
}
} // namespace scau::desktop
