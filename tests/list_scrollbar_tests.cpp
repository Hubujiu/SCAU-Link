#include "desktop/list_scrollbar.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>
#include <filesystem>
#include <fstream>
#include <windowsx.h>

using scau::desktop::ListScrollbar;
namespace {
void require(bool value, const char *why) { if (!value) throw std::runtime_error(why); }
void pump(unsigned milliseconds) {
    const auto deadline = GetTickCount64() + milliseconds;
    do {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
            DispatchMessageW(&message);
        Sleep(1);
    } while (GetTickCount64() < deadline);
}
struct Fixture {
    HWND parent{}, list{}, bar{};
    ListScrollbar scrollbar;
    unsigned frames{}, bar_moves{}, immediate_draws{};
    HDC last_buffer{};
    HGDIOBJ last_bitmap{};
    double last_offset{};
    std::vector<double> offsets;
    std::vector<std::chrono::steady_clock::time_point> frame_times;
    bool buffered = true, complete_viewport = true;
    static COLORREF color(int index) { return RGB(24 + index, 80, 110); }
    static LRESULT CALLBACK bar_probe(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR data) {
        auto &self = *reinterpret_cast<Fixture *>(data);
        if (m == WM_WINDOWPOSCHANGING)
            ++self.bar_moves;
        return DefSubclassProc(h, m, w, l);
    }
    static LRESULT CALLBACK parent_probe(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR data) {
        if (m == WM_DRAWITEM) {
            ++reinterpret_cast<Fixture *>(data)->immediate_draws;
            // Match the app: native focus/selection notifications can only
            // queue a viewport frame, never render a row into the window DC.
            InvalidateRect(reinterpret_cast<DRAWITEMSTRUCT *>(l)->hwndItem, nullptr, FALSE);
            return TRUE;
        }
        return DefSubclassProc(h, m, w, l);
    }
    Fixture() {
        parent = CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, L"STATIC", L"Scrollbar fixture",
                                 WS_POPUP, -30000, -30000, 400, 400, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        require(parent != nullptr, "Cannot create own offscreen fixture");
        SetWindowSubclass(parent, parent_probe, 0, reinterpret_cast<DWORD_PTR>(this));
        list = CreateWindowExW(0, L"LISTBOX", L"Fixture records",
                               WS_CHILD | WS_VISIBLE | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS,
                               0, 0, 300, 180, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
        require(list != nullptr, "Cannot create fixture list");
        SendMessageW(list, LB_SETITEMHEIGHT, 0, 36);
        scrollbar.attach(list, 96, false, [this](HDC dc, RECT bounds, double offset) {
            ++frames;
            buffered = buffered && GetObjectType(dc) == OBJ_MEMDC;
            RECT client{}; GetClientRect(list, &client);
            complete_viewport = complete_viewport && EqualRect(&bounds, &client);
            last_buffer = dc;
            last_bitmap = GetCurrentObject(dc, OBJ_BITMAP);
            last_offset = offset;
            offsets.push_back(offset);
            frame_times.push_back(std::chrono::steady_clock::now());
            const int row = int(SendMessageW(list, LB_GETITEMHEIGHT, 0, 0));
            const int painted = int(std::round(offset));
            const int count = int(SendMessageW(list, LB_GETCOUNT, 0, 0));
            FillRect(dc, &bounds, static_cast<HBRUSH>(GetStockObject(WHITE_BRUSH)));
            for (int i = painted / row, y = i * row - painted; y < bounds.bottom && i < count; y += row, ++i) {
                RECT stripe{0, y, bounds.right, std::min(y + row, int(bounds.bottom))};
                SetDCBrushColor(dc, color(i));
                FillRect(dc, &stripe, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
            }
        });
        bar = FindWindowExW(parent, nullptr, L"ScauLink.Native.ListScrollbar", nullptr);
        require(bar != nullptr, "Custom scrollbar must be lazily attached");
        require(GetParent(bar) == GetParent(list), "Scrollbar must be outside the scrolling LISTBOX subtree");
        SetWindowSubclass(bar, bar_probe, 0, reinterpret_cast<DWORD_PTR>(this));
        ShowWindow(parent, SW_SHOWNOACTIVATE);
        SendMessageW(list, WM_SETREDRAW, FALSE, 0);
        for (int i = 0; i < 100; ++i)
            SendMessageW(list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Fixture record"));
        SendMessageW(list, WM_SETREDRAW, TRUE, 0);
    }
    ~Fixture() { DestroyWindow(parent); }
    int top() { return int(SendMessageW(list, LB_GETTOPINDEX, 0, 0)); }
    void wheel(int delta) { SendMessageW(list, WM_MOUSEWHEEL, MAKEWPARAM(0, short(delta)), 0); }
};
}
int wmain(int argc, wchar_t **argv) {
    try {
        INITCOMMONCONTROLSEX common{sizeof(common), ICC_STANDARD_CLASSES};
        InitCommonControlsEx(&common);
        Fixture fixture;
        require(!(GetWindowLongPtrW(fixture.list, GWL_STYLE) & WS_VSCROLL) && IsWindowVisible(fixture.bar),
                "Overflow uses the custom bar without exposing the stock scrollbar");
        UINT lines = 3; SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &lines, 0);
        RECT initial{}; GetClientRect(fixture.list, &initial);
        const double detent = lines == WHEEL_PAGESCROLL ? initial.bottom : double(std::min(lines, 1000U)) * 36;
        fixture.wheel(-60);
        require(std::abs(fixture.scrollbar.offset() - std::min(detent / 2, fixture.scrollbar.scroll_range())) < .001,
                "Half-detent input must move proportionally without waiting for a full detent");
        fixture.wheel(-60);
        require(std::abs(fixture.scrollbar.offset() - std::min(detent, fixture.scrollbar.scroll_range())) < .001,
                "A full wheel detent must honor the user's line/page distance");
        RECT anchored{};
        GetWindowRect(fixture.bar, &anchored);
        MapWindowPoints(HWND_DESKTOP, fixture.list, reinterpret_cast<POINT *>(&anchored), 2);
        require(anchored.top == 4, "Native list scrolling must not carry the scrollbar child out of its viewport");
        fixture.wheel(120);
        require(fixture.scrollbar.offset() == 0, "Reverse wheel motion must return to the top");
        fixture.wheel(-1);
        require(std::abs(fixture.scrollbar.offset() - std::min(detent / 120, fixture.scrollbar.scroll_range())) < .001,
                "High-resolution wheel input must retain fractional pixel distance");
        fixture.wheel(1);
        fixture.scrollbar.configure(96, true);
        fixture.offsets.clear(); fixture.frame_times.clear();
        SendMessageW(fixture.list, LB_SETTOPINDEX, 3, 0);
        require(fixture.scrollbar.offset() == 0 && fixture.scrollbar.target_offset() == 108,
                "Animated navigation must retarget content without jumping immediately by rows");
        const auto deadline = GetTickCount64() + 1800;
        do {
            MSG message{};
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
                DispatchMessageW(&message);
            Sleep(2);
        } while (fixture.scrollbar.animating() && GetTickCount64() < deadline);
        require(!fixture.scrollbar.animating() && fixture.scrollbar.offset() == 108 && fixture.scrollbar.thumb_position() > 0,
                "Content and thumb must reach the target and stop their shared frame clock");
        unsigned subrow_frames = 0;
        double last = -1;
        for (const double value : fixture.offsets) {
            require(value >= last && value <= 108, "Reading content must progress without spring overshoot or rebound");
            if (value > 0 && value < 108 && std::fmod(value, 36.) > .1)
                ++subrow_frames;
            last = value;
        }
        require(subrow_frames >= 6, "The HWND animation must render multiple sub-row positions, not just animate the thumb");
        std::cout << "Animated content frames: " << fixture.offsets.size() << ", sub-row frames: " << subrow_frames << '\n';
        if (argc == 2) {
            std::ofstream trace{std::filesystem::path(argv[1])};
            require(bool(trace), "Cannot write requested motion trace");
            trace << "{\n  \"scope\": \"Own native HWND fixture; actual buffered viewport paint callbacks\",\n"
                     "  \"rowHeightPixels\": 36,\n  \"targetPixels\": 108,\n  \"subRowFrames\": " << subrow_frames << ",\n  \"frames\": [\n";
            for (std::size_t i = 0; i < fixture.offsets.size(); ++i) {
                const auto ms = std::chrono::duration<double, std::milli>(fixture.frame_times[i] - fixture.frame_times.front()).count();
                trace << "    {\"milliseconds\": " << ms << ", \"offsetPixels\": " << fixture.offsets[i] << "}"
                      << (i + 1 < fixture.offsets.size() ? ",\n" : "\n");
            }
            trace << "  ]\n}\n";
        }
        if (lines) {
            const double start = fixture.scrollbar.offset();
            fixture.wheel(-60);
            require(fixture.scrollbar.offset() == start &&
                    fixture.scrollbar.target_offset() == std::min(start + detent / 2, fixture.scrollbar.scroll_range()),
                    "Animated precision wheel input must retarget without jumping the content");
            fixture.wheel(-60);
            const double destination = std::min(std::min(start + detent / 2, fixture.scrollbar.scroll_range()) +
                                                   detent / 2, fixture.scrollbar.scroll_range());
            require(fixture.scrollbar.target_offset() == destination, "Rapid wheel input must accumulate on its target");
            pump(60);
            const double interrupted = fixture.scrollbar.offset();
            require(interrupted > start && interrupted < destination, "Content must move through intermediate wheel positions");
            fixture.wheel(60);
            require(fixture.scrollbar.offset() == interrupted &&
                    fixture.scrollbar.target_offset() == std::max(0., destination - detent / 2),
                    "Reversing the wheel must preserve the current pixel position and respond to the new target");
            pump(900);
            require(!fixture.scrollbar.animating() && fixture.scrollbar.offset() == fixture.scrollbar.target_offset(),
                    "Interrupted wheel animation must settle and release its clock");
        }
        fixture.scrollbar.configure(96, false);
        SendMessageW(fixture.list, LB_SETTOPINDEX, 0, 0);
        RECT bounds{}, viewport{};
        GetClientRect(fixture.bar, &bounds);
        GetClientRect(fixture.list, &viewport);
        const int maximum = int(fixture.scrollbar.scroll_range()) /
                                int(SendMessageW(fixture.list, LB_GETITEMHEIGHT, 0, 0));
        // All input messages address only windows created in this test process.
        SendMessageW(fixture.bar, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(bounds.right / 2, 8));
        SendMessageW(fixture.bar, WM_MOUSEMOVE, MK_LBUTTON, MAKELPARAM(bounds.right / 2, bounds.bottom - 1));
        SendMessageW(fixture.bar, WM_LBUTTONUP, 0, MAKELPARAM(bounds.right / 2, bounds.bottom - 1));
        require(fixture.top() == maximum && fixture.scrollbar.offset() == fixture.scrollbar.scroll_range() && GetCapture() != fixture.bar,
                "Dragging the thumb must scroll near the end, clamp and release capture");
        SendMessageW(fixture.list, WM_KEYDOWN, VK_HOME, 0);
        require(fixture.top() == 0, "Native Home navigation must synchronize the custom bar");
        SendMessageW(fixture.list, WM_KEYDOWN, VK_END, 0);
        require(fixture.top() == maximum, "Native End navigation must remain available");
        SendMessageW(fixture.list, LB_SETTOPINDEX, 0, 0);
        SendMessageW(fixture.bar, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(bounds.right / 2, 8));
        SendMessageW(fixture.bar, WM_MOUSEMOVE, MK_LBUTTON, MAKELPARAM(bounds.right / 2, 9));
        SendMessageW(fixture.bar, WM_LBUTTONUP, 0, MAKELPARAM(bounds.right / 2, 9));
        const double fractional = fixture.scrollbar.offset();
        require(fractional > 0 && std::fmod(fractional, 36.) > .1,
                "A one-pixel thumb move must retain its proportional content offset instead of snapping to a row");
        const int click_y = viewport.bottom - 2;
        const int clicked = int((click_y + std::round(fractional)) / 36);
        require(LOWORD(SendMessageW(fixture.list, LB_ITEMFROMPOINT, 0, MAKELPARAM(20, click_y))) == clicked,
                "Native hit queries must account for the partly visible first row");
        SendMessageW(fixture.list, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(20, click_y));
        SendMessageW(fixture.list, WM_LBUTTONUP, 0, MAKELPARAM(20, click_y));
        require(SendMessageW(fixture.list, LB_GETCURSEL, 0, 0) == clicked && fixture.scrollbar.offset() == fractional,
                "Clicking the last partial row must select the visible record without row-snapping the viewport");
        RECT selected{};
        SendMessageW(fixture.list, LB_GETITEMRECT, clicked, reinterpret_cast<LPARAM>(&selected));
        require(selected.top <= click_y && selected.bottom > click_y,
                "Native accessible row rectangles must follow the rendered pixel offset");
        SendMessageW(fixture.list, WM_KEYDOWN, VK_HOME, 0);
        require(fixture.scrollbar.offset() == 0, "Home must remove fractional offsets even when the native top row is already zero");
        SendMessageW(fixture.list, LB_SETTOPINDEX, 0, 0);
        require(fixture.scrollbar.offset() == 0,
                "An explicit top-row request must remove a fractional offset even when its native top index is unchanged");
        UpdateWindow(fixture.list);
        const auto buffer = fixture.last_buffer;
        const auto bitmap = fixture.last_bitmap;
        fixture.bar_moves = fixture.immediate_draws = 0;
        unsigned drag_frames = 0;
        SendMessageW(fixture.bar, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(bounds.right / 2, 8));
        // Exercise intermediate held positions in both directions, not only
        // the final screenshot after release. Every frame must remain complete.
        for (int i = 0; i < 120; ++i) {
            const int step = i < 60 ? i : 119 - i;
            const int y = 8 + step * (bounds.bottom - 12) / 59;
            const auto before = fixture.frames;
            SendMessageW(fixture.bar, WM_MOUSEMOVE, MK_LBUTTON, MAKELPARAM(bounds.right / 2, y));
            require(fixture.frames == before, "Input must queue painting rather than present partial rows synchronously");
            UpdateWindow(fixture.list);
            UpdateWindow(fixture.bar);
            drag_frames += fixture.frames - before;
            require(fixture.buffered && fixture.complete_viewport,
                    "Each drag frame must be a complete offscreen viewport");
            require(fixture.last_buffer == buffer && fixture.last_bitmap == bitmap,
                    "Dragging must reuse its bitmap instead of allocating per move");
            require(GetPixel(fixture.last_buffer, 4, 4) == Fixture::color((int(std::round(fixture.last_offset)) + 4) / 36) &&
                    GetPixel(fixture.last_buffer, 4, 40) == Fixture::color((int(std::round(fixture.last_offset)) + 40) / 36),
                    "Intermediate frames must contain the current rows with no cleared gaps or stale strips");
            require((GetWindowLongPtrW(fixture.list, GWL_STYLE) & WS_VISIBLE) && IsWindowVisible(fixture.bar),
                    "Neither viewport nor scrollbar may disappear during capture");
        }
        SendMessageW(fixture.bar, WM_LBUTTONUP, 0, MAKELPARAM(bounds.right / 2, 8));
        std::cout << "Intermediate drag frames: " << drag_frames << ", scrollbar window moves: "
                  << fixture.bar_moves << ", native draw notifications: " << fixture.immediate_draws << '\n';
        require(drag_frames >= 100, "Continuous dragging must paint intermediate positions in both directions");
        require(fixture.bar_moves == 0, "Scrolling must not move or re-anchor the scrollbar window");
        const auto stable = fixture.frames;
        UpdateWindow(fixture.list);
        require(fixture.frames == stable, "A settled viewport must not invalidate itself while painting");
        MoveWindow(fixture.list, 19, 23, 300, 180, FALSE);
        GetWindowRect(fixture.bar, &anchored);
        MapWindowPoints(HWND_DESKTOP, fixture.list, reinterpret_cast<POINT *>(&anchored), 2);
        require(anchored.top == 4 && anchored.right == 300,
                "Sibling scrollbar must follow layout transitions as well as resizing");
        ShowWindow(fixture.list, SW_HIDE);
        require(!IsWindowVisible(fixture.bar), "An empty or hidden viewport must hide its sibling scrollbar");
        ShowWindow(fixture.list, SW_SHOWNA);
        require(IsWindowVisible(fixture.bar), "Showing a populated viewport must restore the scrollbar");
        fixture.scrollbar.configure(144, false);
        MoveWindow(fixture.list, 0, 0, 450, 270, FALSE);
        SendMessageW(fixture.list, LB_SETITEMHEIGHT, 0, 54);
        GetWindowRect(fixture.bar, &bounds);
        require(bounds.right - bounds.left == 21, "Scrollbar hit target must scale with DPI");
        SendMessageW(fixture.list, LB_RESETCONTENT, 0, 0);
        SendMessageW(fixture.list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"One row"));
        require(!IsWindowVisible(fixture.bar), "A short filtered result must hide the scrollbar");
        {
            Fixture filtered;
            filtered.scrollbar.configure(96, true);
            SendMessageW(filtered.list, LB_SETTOPINDEX, 8, 0);
            pump(30);
            SendMessageW(filtered.list, WM_SETREDRAW, FALSE, 0);
            SendMessageW(filtered.list, LB_RESETCONTENT, 0, 0);
            SendMessageW(filtered.list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Short result"));
            SendMessageW(filtered.list, WM_SETREDRAW, TRUE, 0);
            pump(40);
            require(filtered.scrollbar.offset() == 0 && filtered.scrollbar.target_offset() == 0 &&
                    !IsWindowVisible(filtered.bar) && !filtered.scrollbar.animating(),
                    "A short filtered result must cancel in-flight motion without reviving a stale offset");
        }
        for (int i = 0; i < 4; ++i) {
            Fixture closing;
            closing.scrollbar.configure(96, true);
            SendMessageW(closing.list, LB_SETTOPINDEX, 8, 0);
            require(closing.scrollbar.animating(), "Lifecycle fixture must start an active clock");
        }
        MSG remaining{};
        while (PeekMessageW(&remaining, nullptr, 0, 0, PM_REMOVE))
            DispatchMessageW(&remaining);
        std::cout << "PASS: continuous pixel content/dragging, fractional wheel input, partial-row selection/accessibility, "
                     "complete buffered frames, clock shutdown/destruction, stable HWND/bitmap, keyboard and DPI\n";
        return 0;
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
