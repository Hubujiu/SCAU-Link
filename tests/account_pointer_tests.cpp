#include "desktop/account_pointer.hpp"
#include <commctrl.h>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>

using scau::desktop::AccountPointer;
namespace {
void require(bool value, const char *why) {
    if (!value)
        throw std::runtime_error(why);
}
struct Fixture {
    HWND parent{}, list{};
    int selected = -1;
    std::vector<std::pair<int, int>> moves;
    AccountPointer pointer;
    explicit Fixture(bool presentation = false) {
        parent = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, L"STATIC", L"Account pointer fixture",
                                 WS_POPUP, -30000, -30000, 400, 500, nullptr, nullptr,
                                 GetModuleHandleW(nullptr), nullptr);
        require(parent != nullptr, "Cannot create hidden fixture");
        list = CreateWindowExW(0, L"LISTBOX", L"Fixture accounts",
                               WS_CHILD | WS_VISIBLE | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS, 0, 0, 300, 420,
                               parent, nullptr, GetModuleHandleW(nullptr), nullptr);
        require(list != nullptr, "Cannot create native fixture list");
        for (auto name : {L"A", L"B", L"C"})
            SendMessageW(list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(name));
        SendMessageW(list, LB_SETITEMHEIGHT, 0, 84);
        pointer.attach(
            list, [this](int index) { selected = index; },
            [this](int from, int to) { moves.emplace_back(from, to); },
            presentation ? std::function<void(HDC, RECT, int)>([](HDC dc, RECT rect, int) {
                FillRect(dc, &rect, GetSysColorBrush(COLOR_WINDOW));
            })
                         : std::function<void(HDC, RECT, int)>{});
        pointer.geometry(96, 84, 12, 9);
        if (presentation)
            ShowWindow(parent, SW_SHOWNOACTIVATE);
    }
    ~Fixture() { DestroyWindow(parent); }
    void mouse(UINT message, int x, int y, WPARAM buttons = 0) {
        // Only messages to windows created in this fixture; no global input.
        SendMessageW(list, message, buttons, MAKELPARAM(x, y));
    }
    void down(int x, int y) { mouse(WM_LBUTTONDOWN, x, y, MK_LBUTTON); }
    void move(int x, int y) { mouse(WM_MOUSEMOVE, x, y, MK_LBUTTON); }
    void up(int x, int y) { mouse(WM_LBUTTONUP, x, y); }
    void click(int x, int y) {
        down(x, y);
        up(x, y);
    }
    void deselected(const char *why) {
        require(selected == -1 && SendMessageW(list, LB_GETCURSEL, 0, 0) == LB_ERR && GetFocus() != list &&
                    !pointer.active() && GetCapture() != list,
                why);
    }
    template <class F> void wait(F ready) {
        const auto deadline = GetTickCount64() + 1800;
        while (!ready() && GetTickCount64() < deadline) {
            MSG msg{};
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
                DispatchMessageW(&msg);
            Sleep(2);
        }
        require(ready(), "Timed out waiting for own offscreen drag fixture");
    }
};
} // namespace
int main() {
    try {
        INITCOMMONCONTROLSEX common{sizeof(common), ICC_STANDARD_CLASSES};
        InitCommonControlsEx(&common);
        {
            Fixture f;
            f.down(150, 36);
            require(f.pointer.active() && GetCapture() == f.list && f.selected == 0,
                    "Body press captures mouse");
            f.move(150, 66);
            f.move(150, 123);
            f.move(150, 210);
            require(f.pointer.dragging() && f.pointer.target() == 2 && f.moves.empty(),
                    "Held multi-move drag previews target without committing");
            f.up(150, 210);
            require(f.moves == std::vector<std::pair<int, int>>{{0, 2}} && !f.pointer.active() &&
                        GetCapture() != f.list,
                    "ReleaseCapture must commit exactly once");
            f.up(150, 210);
            require(f.moves.size() == 1, "Duplicate release must not repeat reorder");
        }
        {
            Fixture f;
            f.down(20, 210);
            f.move(20, 126);
            f.move(20, 36);
            f.up(20, 36);
            require(f.moves == std::vector<std::pair<int, int>>{{2, 0}}, "Grip drag supports upward reorder");
        }
        {
            Fixture f;
            f.down(150, 126);
            f.move(151, 127);
            f.up(151, 127);
            require(f.selected == 1 && f.moves.empty(), "Ordinary click and small jitter only select");
            f.click(150, 78);
            f.deselected("Inter-row gap clears selection, focus and capture");
            f.click(150, 126);
            f.click(150, 300);
            f.deselected("Empty list area clears selection and focus");
            f.click(150, 126);
            f.click(1, 1);
            f.deselected("Rounded corner outside strip clears selection");
            f.click(150, 36);
            f.pointer.clear_selection();
            f.deselected("Page blank callback clears selection");
        }
        for (UINT cancel : {UINT(WM_CANCELMODE), UINT(WM_CAPTURECHANGED)}) {
            Fixture f;
            f.down(150, 36);
            f.move(150, 210);
            SendMessageW(f.list, cancel, 0, 0);
            f.up(150, 210);
            require(f.moves.empty() && !f.pointer.active() && GetCapture() != f.list,
                    "Cancellation or capture loss must not commit");
        }
        {
            Fixture f;
            f.down(150, 36);
            f.move(350, 210);
            f.up(350, 210);
            require(f.moves.empty() && !f.pointer.active(), "Drop outside list cancels");
            f.down(150, 36);
            f.mouse(WM_MOUSEMOVE, 150, 210);
            f.up(150, 210);
            require(f.moves.empty() && !f.pointer.active(), "Missing left-button state cancels");
        }
        {
            Fixture f;
            f.down(150, 210);
            f.move(150, 78);
            f.up(150, 78);
            require(f.moves == std::vector<std::pair<int, int>>{{2, 1}}, "Gap drop uses insertion order");
        }
        {
            Fixture f;
            f.down(150, 36);
            f.move(150, 210);
            f.pointer.geometry(144, 126, 18, 14);
            f.up(150, 210);
            require(f.moves.empty(), "Changing geometry cancels an old-coordinate drag");
        }
        {
            Fixture f;
            f.pointer.geometry(96, 84, 12, 9, false);
            f.down(80, 204);
            f.move(137, 120);
            const auto first = f.pointer.floating_rect();
            require(f.pointer.lifted() && f.pointer.slot() == 1 && f.pointer.row_offset(1) == 84 &&
                        f.pointer.row_offset(0) == 0,
                    "A lifted strip leaves a destination hole and moves its neighbor");
            f.move(201, 102);
            const auto second = f.pointer.floating_rect();
            require(second.left - first.left == 64 && second.top - first.top == -18,
                    "Floating strip follows both axes and retains the grab offset");
            f.move(-70, 50);
            require(f.pointer.floating_rect().left < 0 && f.pointer.target() == -1 && f.moves.empty(),
                    "Strip moves freely outside viewport without committing order");
            f.pointer.cancel();
            require(!f.pointer.lifted() && f.pointer.row_offset(1) == 0 && f.moves.empty(),
                    "Cancel restores the list with no reorder");
        }
        {
            Fixture f;
            f.pointer.geometry(96, 84, 12, 9, false);
            f.down(150, 120);
            const auto deadline = GetTickCount64() + 700;
            while (!f.pointer.lifted() && GetTickCount64() < deadline) {
                MSG msg{};
                while (PeekMessageW(&msg, f.list, 0, 0, PM_REMOVE))
                    DispatchMessageW(&msg);
                Sleep(2);
            }
            require(f.pointer.lifted() && f.pointer.slot() == 1 && f.moves.empty(),
                    "Stationary press lifts the strip without changing order");
            f.up(150, 120);
            require(!f.pointer.active() && f.moves.empty(), "Stationary lift lands without reordering");
        }
        {
            Fixture f(true);
            f.down(150, 36);
            const auto active = GetActiveWindow();
            f.move(210, 210);
            require(GetActiveWindow() == active, "Floating strip must not activate or steal focus");
            f.up(210, 210);
            require(f.pointer.settling() && GetCapture() != f.list && f.moves.empty(),
                    "Release starts landing without committing before the strip arrives");
            f.wait([&] { return !f.pointer.active(); });
            require(f.moves == std::vector<std::pair<int, int>>{{0, 2}},
                    "Animated landing commits once after capture has been released");
        }
        {
            Fixture f(true);
            f.down(150, 36);
            f.move(230, 210);
            f.up(230, 210);
            require(f.pointer.settling(), "Expected a cancellable animated landing");
            f.pointer.cancel();
            require(!f.pointer.active() && f.moves.empty() && GetCapture() != f.list,
                    "Cancelling an in-flight landing cannot persist a pending reorder");
        }
        std::cout << "Native floating account gestures passed (hold, free movement, landing, cancellation, "
                     "focus).\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
