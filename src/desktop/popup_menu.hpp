#pragma once
#include "spring.hpp"
#include "visual.hpp"
#include <functional>
#include <string>
#include <vector>

namespace scau::desktop {
struct MenuEntry {
    int id;
    std::wstring label;
    visual::Icon icon = visual::Icon::None;
    bool enabled = true;
    bool destructive = false;
    bool checked = false;
};

// A lazy owned Win32 popup. Native buttons retain their accessibility names;
// outside clicks reach the original target instead of being swallowed.
class NativeMenu {
    struct Row {
        MenuEntry entry;
        HWND button{};
        int y{};
        Spring hover;
    };
    HWND window_{}, owner_{}, return_focus_{};
    UINT dpi_ = 96;
    bool visible_ = false, animations_ = true, keyboard_ = false;
    int width_ = 184, height_ = 0;
    POINT destination_{};
    ULONGLONG frame_{};
    Spring reveal_;
    std::vector<Row> rows_;
    std::function<void(int)> chosen_;
    std::function<void()> closed_;
    visual::Renderer renderer_;
    static LRESULT CALLBACK proc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK button_proc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
    int px(int dip) const { return MulDiv(dip, int(dpi_), 96); }
    Row *row(HWND);
    void hover(HWND, bool);
    void animate();
    void tick();
    void paint();
    void draw(const DRAWITEMSTRUCT &);
    void choose(int);
    void focus_step(int direction, bool edge = false);

  public:
    ~NativeMenu();
    void show(HWND owner, POINT anchor, std::vector<MenuEntry> entries, std::function<void(int)> chosen,
              UINT dpi, bool animations, const wchar_t *title, int width = 184,
              std::function<void()> closed = {});
    void close(bool restore_focus = false);
    bool filter(const MSG &);
};
} // namespace scau::desktop
