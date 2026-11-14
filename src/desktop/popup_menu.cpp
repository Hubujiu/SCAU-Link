#include "popup_menu.hpp"
#include <commctrl.h>
#include <dwmapi.h>
#include <stdexcept>
#include <utility>

namespace scau::desktop {
namespace {
constexpr wchar_t menu_class[] = L"ScauLink.Native.Menu";
constexpr UINT_PTR motion_timer = 1;
} // namespace
NativeMenu::~NativeMenu() {
    if (window_ && IsWindow(window_))
        DestroyWindow(window_);
}
NativeMenu::Row *NativeMenu::row(HWND button) {
    for (auto &item : rows_)
        if (item.button == button)
            return &item;
    return nullptr;
}
void NativeMenu::show(HWND owner, POINT anchor, std::vector<MenuEntry> entries,
                      std::function<void(int)> chosen, UINT dpi, bool animations, const wchar_t *title,
                      int width, std::function<void()> closed) {
    close();
    owner_ = owner;
    return_focus_ = GetFocus();
    dpi_ = dpi;
    animations_ = animations;
    keyboard_ = false;
    chosen_ = std::move(chosen);
    closed_ = std::move(closed);
    width_ = std::clamp(width, 140, 320);
    if (!window_) {
        WNDCLASSEXW wc{sizeof(wc)};
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpfnWndProc = proc;
        wc.lpszClassName = menu_class;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.style = CS_DROPSHADOW;
        RegisterClassExW(&wc);
        window_ = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_LAYERED, menu_class, title, WS_POPUP | WS_CLIPCHILDREN, 0, 0, 1, 1,
                                  owner, nullptr, wc.hInstance, this);
        if (!window_)
            throw std::runtime_error("Cannot create native menu");
        const int corners = 2;
        const COLORREF border = visual::Border;
        DwmSetWindowAttribute(window_, static_cast<DWMWINDOWATTRIBUTE>(33), &corners, sizeof(corners));
        DwmSetWindowAttribute(window_, static_cast<DWMWINDOWATTRIBUTE>(34), &border, sizeof(border));
    }
    SetWindowTextW(window_, title);
    for (const auto &item : rows_)
        if (item.button)
            DestroyWindow(item.button);
    rows_.clear();
    int y = 6;
    for (auto &entry : entries) {
        Row item{std::move(entry), nullptr, y, {}};
        if (item.entry.id) {
            item.button = CreateWindowExW(
                0, L"BUTTON", item.entry.label.c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                px(6), px(y), px(width_ - 12), px(38), window_,
                reinterpret_cast<HMENU>(INT_PTR(item.entry.id)), GetModuleHandleW(nullptr), nullptr);
            if (!item.button)
                throw std::runtime_error("Cannot create menu item");
            SetWindowSubclass(item.button, button_proc, 0, reinterpret_cast<DWORD_PTR>(this));
            EnableWindow(item.button, item.entry.enabled);
            y += 38;
        } else
            y += 9;
        rows_.push_back(std::move(item));
    }
    height_ = y + 6;
    MONITORINFO monitor{sizeof(monitor)};
    GetMonitorInfoW(MonitorFromPoint(anchor, MONITOR_DEFAULTTONEAREST), &monitor);
    destination_.x = std::clamp(anchor.x, monitor.rcWork.left + px(4),
                                std::max(monitor.rcWork.left + px(4), monitor.rcWork.right - px(width_ + 4)));
    destination_.y =
        std::clamp(anchor.y, monitor.rcWork.top + px(4),
                   std::max(monitor.rcWork.top + px(4), monitor.rcWork.bottom - px(height_ + 4)));
    const int radius = px(10);
    HRGN region = CreateRoundRectRgn(0, 0, px(width_) + 1, px(height_) + 1, radius * 2, radius * 2);
    if (region && !SetWindowRgn(window_, region, FALSE))
        DeleteObject(region);
    renderer_.reset();
    reveal_.snap(0);
    if (animations_)
        reveal_.enter(8);
    SetLayeredWindowAttributes(window_, 0, animations_ ? 170 : 255, LWA_ALPHA);
    visible_ = true;
    SetWindowPos(window_, HWND_TOP, destination_.x, destination_.y + px(int(reveal_.value())), px(width_),
                 px(height_), SWP_SHOWWINDOW);
    SetForegroundWindow(window_);
    focus_step(1, true);
    for (const auto &item : rows_)
        if (item.button && item.entry.checked && item.entry.enabled) {
            SetFocus(item.button);
            break;
        }
    InvalidateRect(window_, nullptr, FALSE);
    if (animations_)
        animate();
}
void NativeMenu::close(bool restore_focus) {
    if (!visible_)
        return;
    visible_ = false;
    KillTimer(window_, motion_timer);
    ShowWindow(window_, SW_HIDE);
    if (restore_focus && IsWindowVisible(owner_)) {
        SetForegroundWindow(owner_);
        if (IsWindow(return_focus_) && IsWindowVisible(return_focus_) && IsWindowEnabled(return_focus_))
            SetFocus(return_focus_);
    }
    if (auto closed = std::move(closed_))
        closed();
}
void NativeMenu::choose(int id) {
    const auto found =
        std::find_if(rows_.begin(), rows_.end(), [id](const Row &r) { return r.entry.id == id; });
    if (found == rows_.end() || !found->entry.enabled || !id)
        return;
    close(true);
    if (chosen_)
        chosen_(id);
}
void NativeMenu::focus_step(int direction, bool edge) {
    std::vector<HWND> enabled;
    for (const auto &item : rows_)
        if (item.button && item.entry.enabled)
            enabled.push_back(item.button);
    if (enabled.empty())
        return;
    const auto found = std::find(enabled.begin(), enabled.end(), GetFocus());
    int index = found == enabled.end() ? -1 : int(found - enabled.begin());
    if (edge || index < 0)
        index = direction > 0 ? 0 : int(enabled.size()) - 1;
    else
        index = (index + direction + int(enabled.size())) % int(enabled.size());
    SetFocus(enabled[std::size_t(index)]);
    for (const auto &item : rows_)
        if (item.button)
            InvalidateRect(item.button, nullptr, FALSE);
}
bool NativeMenu::filter(const MSG &message) {
    if (!visible_ || (message.hwnd != window_ && !IsChild(window_, message.hwnd)))
        return false;
    if (message.message != WM_KEYDOWN && message.message != WM_SYSKEYDOWN)
        return false;
    keyboard_ = true;
    switch (message.wParam) {
    case VK_ESCAPE:
    case VK_MENU:
    case VK_F10:
        close(true);
        return true;
    case VK_DOWN:
        focus_step(1);
        return true;
    case VK_UP:
        focus_step(-1);
        return true;
    case VK_HOME:
        focus_step(1, true);
        return true;
    case VK_END:
        focus_step(-1, true);
        return true;
    case VK_TAB:
        focus_step(GetKeyState(VK_SHIFT) & 0x8000 ? -1 : 1);
        return true;
    case VK_RETURN:
    case VK_SPACE:
        if (auto *item = row(GetFocus()))
            choose(item->entry.id);
        return true;
    }
    return false;
}
void NativeMenu::animate() {
    frame_ = GetTickCount64();
    SetTimer(window_, motion_timer, 16, nullptr);
}
void NativeMenu::hover(HWND button, bool hot) {
    if (auto *item = row(button)) {
        keyboard_ = false;
        if (animations_)
            item->hover.move_to(hot ? 1. : 0.);
        else
            item->hover.snap(hot ? 1. : 0.);
        InvalidateRect(button, nullptr, FALSE);
        if (animations_)
            animate();
    }
}
void NativeMenu::tick() {
    const auto now = GetTickCount64();
    const double seconds = double(now - frame_) / 1000.;
    frame_ = now;
    reveal_.step(seconds);
    SetLayeredWindowAttributes(window_, 0,
        BYTE(std::lround(255 - std::min(1., std::abs(reveal_.value()) / 8.) * 85)), LWA_ALPHA);
    SetWindowPos(window_, nullptr, destination_.x, destination_.y + px(int(std::round(reveal_.value()))), 0,
                 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    bool moving = reveal_.active();
    for (auto &item : rows_)
        if (item.button) {
            const bool active = item.hover.active();
            item.hover.step(seconds);
            moving |= item.hover.active();
            if (active)
                InvalidateRect(item.button, nullptr, FALSE);
        }
    if (!moving)
        KillTimer(window_, motion_timer);
}
void NativeMenu::paint() {
    PAINTSTRUCT ps{};
    const auto dc = BeginPaint(window_, &ps);
    RECT client{};
    GetClientRect(window_, &client);
    if (renderer_.begin(dc, client, dpi_, visual::White)) {
        renderer_.outline({.5f, .5f, float(width_ - 1), float(height_ - 1)}, visual::Line, 9.5f);
        for (const auto &item : rows_)
            if (!item.entry.id)
                renderer_.line(12, float(item.y) + 4.5f, float(width_ - 12), float(item.y) + 4.5f,
                               visual::Line);
        renderer_.end();
    }
    EndPaint(window_, &ps);
}
void NativeMenu::draw(const DRAWITEMSTRUCT &draw) {
    const auto *item = row(draw.hwndItem);
    if (!item || !renderer_.begin(draw.hDC, draw.rcItem, dpi_, visual::White))
        return;
    const bool focused = keyboard_ && GetFocus() == item->button;
    const bool pressed = (draw.itemState & ODS_SELECTED) != 0;
    const double hot = focused || pressed || item->entry.checked ? 1. : item->hover.value();
    const COLORREF hover = item->entry.destructive ? RGB(252, 240, 237) : visual::Soft;
    renderer_.fill({0, 0, float(width_ - 12), 38}, visual::mix(visual::White, hover, hot), 7);
    const COLORREF color = !item->entry.enabled      ? visual::Subtle
                           : item->entry.destructive ? visual::Error
                                                     : visual::Ink;
    const COLORREF icon = !item->entry.enabled      ? visual::Subtle
                          : item->entry.destructive ? visual::Error
                                                    : visual::Pine;
    const bool has_icon = item->entry.icon != visual::Icon::None;
    if (has_icon)
        renderer_.icon(item->entry.icon, {11, 11, 16, 16}, icon, 1.8f);
    const float left = has_icon ? 39.f : 12.f;
    renderer_.text(item->entry.label, {left, 0, float(width_ - 42) - left, 38},
                   item->entry.checked ? visual::Deep : color);
    if (item->entry.checked)
        renderer_.icon(visual::Icon::Check, {float(width_ - 38), 11, 16, 16}, visual::Pine, 1.8f);
    renderer_.end();
}
LRESULT CALLBACK NativeMenu::button_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR data) {
    auto &self = *reinterpret_cast<NativeMenu *>(data);
    if (m == WM_MOUSEMOVE) {
        TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE, h, 0};
        TrackMouseEvent(&track);
        if (auto *item = self.row(h); item && item->hover.target() != 1.)
            self.hover(h, true);
    } else if (m == WM_MOUSELEAVE)
        self.hover(h, false);
    else if (m == WM_SETFOCUS || m == WM_KILLFOCUS)
        InvalidateRect(h, nullptr, FALSE);
    else if (m == WM_RBUTTONUP) {
        self.choose(GetDlgCtrlID(h));
        return 0;
    } else if (m == WM_NCDESTROY)
        RemoveWindowSubclass(h, button_proc, 0);
    return DefSubclassProc(h, m, w, l);
}
LRESULT CALLBACK NativeMenu::proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    auto *self = reinterpret_cast<NativeMenu *>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        self = static_cast<NativeMenu *>(reinterpret_cast<CREATESTRUCTW *>(l)->lpCreateParams);
        self->window_ = h;
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    if (!self)
        return DefWindowProcW(h, m, w, l);
    switch (m) {
    case WM_ACTIVATE:
        if (LOWORD(w) == WA_INACTIVE)
            self->close();
        return 0;
    case WM_COMMAND:
        if (HIWORD(w) == BN_CLICKED)
            self->choose(LOWORD(w));
        return 0;
    case WM_DRAWITEM:
        self->draw(*reinterpret_cast<DRAWITEMSTRUCT *>(l));
        return TRUE;
    case WM_PAINT:
        self->paint();
        return 0;
    case WM_ERASEBKGND:
        return TRUE;
    case WM_TIMER:
        if (w == motion_timer)
            self->tick();
        return 0;
    case WM_CLOSE:
        self->close(true);
        return 0;
    case WM_NCDESTROY:
        self->window_ = nullptr;
        self->visible_ = false;
        break;
    }
    return DefWindowProcW(h, m, w, l);
}
} // namespace scau::desktop
