#include "backend.hpp"
#include "account_pointer.hpp"
#include "popup_menu.hpp"
#include "list_scrollbar.hpp"
#include "spring.hpp"
#include "visual.hpp"
#include "updates.hpp"
#include "release_config.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <commctrl.h>
#include <d2d1.h>
#include <dwmapi.h>
#include <memory>
#include <shellapi.h>
#include <stdexcept>
#include <string>
#include <uxtheme.h>
#include <vector>
#include <windowsx.h>
#include <wrl/client.h>

using Microsoft::WRL::ComPtr;
namespace scau::desktop {
namespace {
constexpr wchar_t root_class[] = L"ScauLink.Native.Window", page_class[] = L"ScauLink.Native.Page";
constexpr UINT tray_message = WM_APP + 21, show_message = WM_APP + 22;
constexpr UINT_PTR animation_timer = 1, uptime_timer = 2, exit_timer = 3, progress_timer = 4, search_timer = 5,
                   package_timer = 6, update_timer = 7;
constexpr int account_row_height = 84, account_row_gap = 12;
constexpr float account_row_radius = 9.f;
enum PageId { Home, Account, Preferences, Logs, PageCount };
enum Id {
    NavHome = 10,
    NavAccount,
    NavPreferences,
    NavLogs,
    Brand = 20,
    MiniBack,
    MiniSettings,
    WindowMinimize,
    WindowMaximize,
    WindowClose,
    Heading = 100,
    StateText,
    StateMessage,
    AccountValue,
    Action,
    Login,
    Duration,
    AdapterValue,
    Details,
    HomeBalance = 110,
    HomeExpiry,
    PackageStatus,
    HomeDevices,
    ConnectionModePicker,
    PortalAccept,
    UserLabel = 130,
    UserInput,
    PasswordLabel,
    PasswordInput,
    PasswordEye,
    SaveCredential,
    FormMessage,
    AccountList = 140,
    AddAccount,
    AccountBack,
    ManageAccount,
    DeleteAccount,
    PinAccount,
    AccountsEmpty,
    CampusAccount,
    ChangePasswordMenu,
    MiniToggle = 160,
    StartupHeading,
    AutoStartToggle,
    SilentToggle,
    ExitMini,
    SettingsMessage,
    StartupMode1,
    StartupMode2,
    StartupMode3,
    CheckUpdate,
    UpdateStatus,
    LogList = 180,
    RefreshLogs,
    LogsMessage,
    LogSearch,
    ClearLogSearch,
    LogStateFilter,
    LogTimeFilter,
    LogSort,
    LogCount,
    ResetLogFilters,
    LogSearchLabel,
    LogListLabel,
    Progress = 200,
    CampusUser = 220,
    CampusStateValue,
    CampusDevices,
    CampusActionButton,
    CampusRefresh,
    CampusCancel,
    CampusMessage,
    CampusConfirmation,
    PasswordAccount = 240,
    OldPasswordLabel,
    OldPasswordInput,
    NewPasswordLabel,
    NewPasswordInput,
    ConfirmPasswordLabel,
    ConfirmPasswordInput,
    SubmitPasswordChange,
    PortalPasswordLink,
    OfficialPasswordLink
};
constexpr COLORREF paper = visual::Paper, pine = visual::Pine, ink = visual::Ink, muted = visual::Muted,
                   sage = visual::Soft, nav_bg = visual::Sidebar, line_color = visual::Line;
enum Font { Body, Small, Medium, Title, Large, FontCount };
struct Box {
    int x, y, w, h;
};
struct Control {
    HWND handle{};
    int id{};
    Font font = Body;
    Spring hover, thumb;
};
class App;
struct Page {
    App *app{};
    PageId id{};
    HWND window{};
    std::vector<Control> controls;
};
std::wstring status_text(Status status, bool credentials) {
    switch (status) {
    case Status::Loading:
        return L"正在加载";
    case Status::Offline:
        return credentials ? L"未连接" : L"未登录";
    case Status::Connecting:
        return L"正在登录";
    case Status::Online:
        return L"已连接";
    case Status::Recovering:
        return L"正在重连";
    case Status::Waiting:
        return L"等待网络";
    case Status::Stopping:
        return L"正在断开";
    default:
        return L"连接失败";
    }
}
bool connected_or_busy(Status status) {
    return status == Status::Online || status == Status::Connecting || status == Status::Recovering ||
           status == Status::Waiting;
}
std::wstring masked(std::wstring_view value) {
    if (value.size() < 5)
        return value.empty() ? L"未登录" : std::wstring(1, value.front()) + L"•••";
    return std::wstring(value.substr(0, 4)) + L"••••" + std::wstring(value.substr(value.size() - 2));
}
class App {
  public:
    HINSTANCE instance{};
    HWND window{};
    BackendOptions options;
    ConnectionMode active_mode = ConnectionMode::Wired;
    bool force_silent = false;
    std::unique_ptr<Backend> backend;
    std::unique_ptr<updates::Manager> updater;
    updates::Snapshot update_snapshot;
    bool update_confirming=false,update_waiting_disconnect=false;
    bool demo_update_available = false, demo_update_ready = false, demo_update_live = false;
    Settings settings{};
    Status status = Status::Loading;
    bool initialized = false, credentials = false, quiet = true, exiting = false,
         pending_settings = false, pending_credential = false, logs_loading = false, show_details = false;
    std::wstring username, active_username, adapter = L"以太网", message;
    AccountCatalog account_catalog;
    std::map<std::string, std::pair<std::string, PackageInfo>> packages;
    std::string form_account_id, active_account_id, package_account_id;
    bool account_editor = false, login_after_save = false;
    bool account_service = false, campus_busy = false, campus_confirming = false;
    bool password_view = false, password_busy = false, password_confirming = false,
         password_submitted = false, password_official = false;
    std::string password_account_id, password_secret, portal_ticket;
    unsigned password_request = 0;
    std::wstring password_message;
    bool portal_approving = false;
    CampusView campus_view;
    std::string campus_account_id, campus_secret, campus_ticket;
    unsigned campus_request = 0;
    std::wstring campus_message;
    AccountPointer account_pointer;
    NativeMenu popup;
    ListScrollbar log_scrollbar;
    LogQuery log_query;
    LogResult log_result;
    unsigned log_request = 0;
    std::wstring log_error;
    PageId current = Home;
    std::array<Page, PageCount> pages;
    std::vector<Control> chrome;
    std::array<HFONT, FontCount> fonts{};
    UINT dpi = 96, taskbar_created{};
    bool tray_added = false, animations = true;
    HICON green{}, gray{}, amber{};
    HWND hovered{};
    visual::Renderer renderer;
    Spring page_spring, nav_spring, window_spring, log_results_spring;
    ULONGLONG last_frame = 0, online_since = 0;
    POINT window_destination{};
    RECT full_bounds{};
    bool full_bounds_saved = false;
    bool update_installing() const {
        return update_waiting_disconnect || update_snapshot.phase == updates::Phase::Starting || update_snapshot.phase == updates::Phase::InstallQueued;
    }
    bool update_interaction_busy() const {
        return account_editor || account_service || password_view || campus_busy || password_busy ||
            campus_confirming || pending_credential || pending_settings || account_pointer.active() || popup.visible() || exiting || update_confirming;
    }
    bool update_can_install(bool idle) const {
        const bool running = backend && (backend->running() || status==Status::Online);
        const bool authenticating = !initialized || !backend || status==Status::Loading || status==Status::Connecting ||
            status==Status::Recovering || status==Status::Waiting || status==Status::Stopping;
        return updates::can_install(update_snapshot.impact,running,authenticating,update_interaction_busy(),idle);
    }
    void refresh_update_controls() {
        using updates::Phase;
        std::wstring caption=L"检查更新", state=updates::current_version;
        bool enabled=initialized && (updater || options.demo);
        switch(update_snapshot.phase) {
        case Phase::Checking: caption=L"检查中";state+=L" · 正在检查";enabled=false;break;
        case Phase::Current: state+=L" · 已是最新版";break;
        case Phase::Available: caption=L"下载更新";state=L"可更新至 "+update_snapshot.version;break;
        case Phase::Downloading:
            caption=L"下载 "+std::to_wstring(update_snapshot.progress)+L"%";
            state=L"正在下载 "+update_snapshot.version;enabled=false;break;
        case Phase::Ready:
            caption=update_snapshot.impact==updates::Impact::PreserveConnection?L"安装更新":L"安装并重启";
            state=L"已下载 "+update_snapshot.version;
            enabled=!demo_update_live&&!update_interaction_busy()&&
                (update_can_install(true)||(update_snapshot.impact==updates::Impact::MayDisconnect&&initialized&&backend));
            break;
        case Phase::Applied: caption=L"已更新";state=update_snapshot.version+L" · 下次启动生效";enabled=false;break;
        case Phase::Starting: case Phase::InstallQueued: caption=L"准备安装";enabled=false;break;
        case Phase::Failed: state+=L" · 更新失败（"+std::to_wstring(update_snapshot.error)+L"）";break;
        default:break;
        }
        if(update_snapshot.phase==Phase::Available||update_snapshot.phase==Phase::Downloading||update_snapshot.phase==Phase::Ready)
            state+=update_snapshot.impact==updates::Impact::PreserveConnection?L" · 无需断网":L" · 更新时可能断网";
        if(update_waiting_disconnect){caption=L"准备安装";state=L"正在断开连接";enabled=false;}
        text(Preferences,CheckUpdate,caption);text(Preferences,UpdateStatus,state);
        if(auto button=ctrl(Preferences,CheckUpdate))EnableWindow(button,enabled);
        if(pages[Preferences].window)InvalidateRect(pages[Preferences].window,nullptr,FALSE);
    }
    void update_changed() {
        if(updater)update_snapshot=updater->snapshot();
        refresh_update_controls();
        if(update_snapshot.phase==updates::Phase::InstallQueued && !exiting)exit();
    }
    void update_tick() {
        if(!updater||!initialized||exiting||options.demo)return;
        if(update_waiting_disconnect) {
            if(update_can_install(true)) {
                update_waiting_disconnect=false;
                if(updater->install_now())update_changed();
            }
            return;
        }
        const bool idle=updates::system_idle();
        updater->tick(idle);
        if(update_snapshot.phase==updates::Phase::Ready && update_can_install(idle)) {
            if(updater->install_now())update_changed();
        }
    }
    void update_clicked() {
        using updates::Phase;
        if(options.demo && !demo_update_live) {
            if(update_snapshot.phase==Phase::Available)update_snapshot={Phase::Ready,L"0.14.0",100,0};
            else if(update_snapshot.phase!=Phase::Ready)
                update_snapshot=demo_update_available ? updates::Snapshot{Phase::Available,L"0.14.0",0,0} : updates::Snapshot{Phase::Current};
            refresh_update_controls();return;
        }
        if(!updater)return;
        if(update_snapshot.phase==Phase::Available)updater->download_now();
        else if(update_snapshot.phase==Phase::Ready) {
            if(options.demo||!initialized||!backend||update_interaction_busy())return;
            if(update_snapshot.impact==updates::Impact::MayDisconnect) {
                update_confirming=true;
                const int answer=MessageBoxW(window,L"更新时可能断网。\n继续更新？",L"安装更新",MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2);
                update_confirming=false;
                if(answer!=IDYES){refresh_update_controls();return;}
                // Automatic updates never request disconnection.
                if(backend->running()||connected_or_busy(status)||status==Status::Stopping) {
                    update_waiting_disconnect=true;backend->disconnect();refresh_update_controls();return;
                }
            }
            if(update_can_install(true))updater->install_now();
        } else updater->check_now();
        update_changed();
    }
    const PackageInfo& package_for(const std::string& id) const {
        static const PackageInfo missing;
        const auto* account = account_catalog.find(id);
        const auto found = packages.find(id);
        return account && found != packages.end() && found->second.first == account->secret_id
                   ? found->second.second : missing;
    }
    std::string home_package_account() const {
        if (account_catalog.find(active_account_id)) return active_account_id;
        return account_catalog.find(package_account_id) ? package_account_id : std::string{};
    }
    ConnectionMode display_mode() const {
        return connected_or_busy(status) ? active_mode : settings.mode;
    }
    void request_visible_packages() {
        if (!backend || !initialized || settings.mini || !IsWindowVisible(window) || IsIconic(window)) return;
        if (current == Account && !account_editor && !account_service) backend->request_packages();
        else if (current == Home && status == Status::Online) {
            const auto id = home_package_account();
            if (!id.empty()) backend->request_packages(id);
        }
    }
    Box page_box(int width, int height) const {
        const int content = settings.mini ? width - 48 : std::min(width - 248, 920);
        const int x = settings.mini ? 24 : 184 + (width - 184 - content) / 2, y = settings.mini ? 76 : 78;
        return {x, y, content, height - y - 24};
    }
    Box account_form(int width) const {
        if (settings.mini)
            return {0, 0, width, 293};
        const int field = std::min(width, 520);
        return {(width - field) / 2, 76, field, 342};
    }
    std::string first_account_id() const {
        const auto *first = account_catalog.first_account();
        return first ? first->id : std::string{};
    }
    bool connect_after_save() const {
        return settings.mini || (!credentials && !connected_or_busy(status));
    }
    int log_search_width(int width) const { return width - 390; }
    bool log_filters_active() const {
        return !log_query.search.empty() || log_query.level != LogLevel::All ||
               log_query.range != LogRange::All || log_query.order != LogOrder::Newest;
    }
    void update_log_controls() {
        if (!pages[Logs].window)
            return;
        constexpr const wchar_t *ranges[]{L"全部时间", L"最近1小时", L"最近24小时", L"今天", L"最近7天"};
        constexpr const wchar_t *orders[]{L"最新在前", L"最早在前", L"失败优先"};
        text(Logs, LogStateFilter, log_level_label(log_query.level));
        text(Logs, LogTimeFilter, ranges[int(log_query.range)]);
        text(Logs, LogSort, orders[int(log_query.order)]);
        std::wstring count = std::to_wstring(log_result.entries.size());
        if (log_result.matching_count > log_result.entries.size())
            count += L" / " + std::to_wstring(log_result.matching_count);
        text(Logs, LogCount, count + L" 条");
        text(Logs, LogsMessage,
             !log_error.empty() ? log_error
             : logs_loading ? L"正在加载"
             : log_filters_active() ? L"没有匹配的记录" : L"暂无记录");
        EnableWindow(ctrl(Logs, RefreshLogs), !logs_loading);
    }
    void request_logs(bool debounce = false) {
        if (!pages[Logs].window)
            return;
        KillTimer(window, search_timer);
        ++log_request;
        std::array<wchar_t, 257> search{};
        GetWindowTextW(ctrl(Logs, LogSearch), search.data(), int(search.size()));
        log_query.search = search.data();
        log_query.now_ms = 0;
        logs_loading = true;
        log_error.clear();
        update_log_controls();
        if (debounce)
            SetTimer(window, search_timer, 160, nullptr);
        else
            backend->load_logs(log_query, log_request);
        layout();
        timers();
    }
    void filter_open(int id, bool open) {
        if (auto *c = control(ctrl(id == ConnectionModePicker ? Home : Logs, id))) {
            if (animations)
                c->thumb.move_to(open ? 1. : 0.);
            else
                c->thumb.snap(open ? 1. : 0.);
            InvalidateRect(c->handle, nullptr, FALSE);
            if (animations)
                start_animation();
        }
    }
    void show_log_choices(int id) {
        std::vector<MenuEntry> choices;
        int selected = 0, width = 164;
        const wchar_t *name = L"状态筛选";
        if (id == LogStateFilter) {
            selected = int(log_query.level);
            for (auto level : {LogLevel::All, LogLevel::Success, LogLevel::Warning, LogLevel::Error, LogLevel::Info})
                choices.push_back({1000 + int(level), log_level_label(level), visual::Icon::None,
                                   true, false, int(level) == selected});
        } else if (id == LogTimeFilter) {
            selected = int(log_query.range);
            constexpr const wchar_t *labels[]{L"全部时间", L"最近1小时", L"最近24小时", L"今天", L"最近7天"};
            for (int i = 0; i < 5; ++i)
                choices.push_back({1000 + i, labels[i], visual::Icon::None, true, false, i == selected});
            name = L"时间范围";
            width = 176;
        } else {
            selected = int(log_query.order);
            constexpr const wchar_t *labels[]{L"最新在前", L"最早在前", L"失败优先"};
            for (int i = 0; i < 3; ++i)
                choices.push_back({1000 + i, labels[i], visual::Icon::None, true, false, i == selected});
            name = L"记录排序";
        }
        RECT bounds{};
        GetWindowRect(ctrl(Logs, id), &bounds);
        POINT anchor{id == LogSort ? bounds.right - px(width) : bounds.left, bounds.bottom + px(6)};
        popup.show(window, anchor, std::move(choices), [this, id](int choice) {
            const int index = choice - 1000;
            if (id == LogStateFilter)
                log_query.level = LogLevel(index);
            else if (id == LogTimeFilter)
                log_query.range = LogRange(index);
            else
                log_query.order = LogOrder(index);
            request_logs();
        }, dpi, animations, name, width, [this, id] { filter_open(id, false); });
        filter_open(id, true);
    }
    void show_connection_modes() {
        if (!initialized || connected_or_busy(status) || status == Status::Stopping || pending_settings) return;
        RECT bounds{}; GetWindowRect(ctrl(Home, ConnectionModePicker), &bounds);
        POINT anchor{bounds.right - px(184), bounds.bottom + px(6)};
        popup.show(window, anchor,
            {{1, L"有线 802.1X", visual::Icon::Ethernet, true, false, settings.mode == ConnectionMode::Wired},
             {2, L"无线 Web", visual::Icon::Wifi, true, false, settings.mode == ConnectionMode::WirelessWeb},
             {3, L"无线 802.1X", visual::Icon::Wifi, true, false, settings.mode == ConnectionMode::Wireless8021x}},
            [this](int choice) {
                auto next = settings;
                next.mode = choice == 3 ? ConnectionMode::Wireless8021x : choice == 2 ? ConnectionMode::WirelessWeb : ConnectionMode::Wired;
                if (next.mode == settings.mode) return;
                pending_settings = true;
                backend->save_preferences(next);
                refresh_visible();
            }, dpi, animations, L"上网模式", 184,
            [this] { filter_open(ConnectionModePicker, false); });
        filter_open(ConnectionModePicker, true);
    }
    void show_startup_modes(int id) {
        if (!initialized || pending_settings || settings.mini) return;
        const auto slot = std::size_t(id - StartupMode1);
        std::vector<MenuEntry> items;
        items.push_back({9, slot == 0 ? L"跟随上次选择" : L"不启用", visual::Icon::Network,
                         true, false, slot >= settings.startup_modes.size()});
        for (int mode = 0; mode != 3; ++mode)
            items.push_back({mode + 1, connection_mode_label(ConnectionMode(mode)),
                            mode == 0 ? visual::Icon::Ethernet : visual::Icon::Wifi,
                            slot < settings.startup_modes.size() ||
                                std::find(settings.startup_modes.begin(),settings.startup_modes.end(),ConnectionMode(mode))==settings.startup_modes.end(), false,
                            slot < settings.startup_modes.size() && settings.startup_modes[slot] == ConnectionMode(mode)});
        RECT bounds{}; GetWindowRect(ctrl(Preferences,id), &bounds);
        popup.show(window,{bounds.left,bounds.bottom+px(6)},std::move(items),[this,slot](int choice) {
            auto next = settings;
            if (choice == 9) next.startup_modes.resize(std::min(slot,next.startup_modes.size()));
            else {
                const auto mode = ConnectionMode(choice-1);
                auto& plan = next.startup_modes;
                const auto existing=std::find(plan.begin(),plan.end(),mode);
                if(existing!=plan.end()) {
                    if(slot<plan.size())std::iter_swap(plan.begin()+slot,existing);
                } else if(slot<plan.size())plan[slot]=mode;
                else plan.push_back(mode);
            }
            pending_settings = true; backend->save_preferences(next); refresh_visible();
        },dpi,animations,L"开机连接",240,[this,id]{ if(auto*c=control(ctrl(Preferences,id)))c->thumb.move_to(0); });
        if(auto*c=control(ctrl(Preferences,id)))c->thumb.move_to(1);
        start_animation();
    }
    int account_list_height(int height) const {
        const int visible = std::clamp((height - 116) / account_row_height, 3, 8);
        return std::min(visible, std::max(3, int(account_catalog.entries.size()))) * account_row_height;
    }
    Control *control(HWND handle) {
        for (auto &c : chrome)
            if (c.handle == handle)
                return &c;
        for (auto &p : pages)
            for (auto &c : p.controls)
                if (c.handle == handle)
                    return &c;
        return nullptr;
    }
    bool controls_moving() const {
        for (const auto &c : chrome)
            if (c.hover.active() || c.thumb.active())
                return true;
        for (const auto &p : pages)
            if (p.window && IsWindowVisible(p.window))
                for (const auto &c : p.controls)
                    if (c.hover.active() || c.thumb.active())
                        return true;
        return false;
    }
    void hover_control(HWND handle, bool hot) {
        if (auto *c = control(handle)) {
            if (animations)
                c->hover.move_to(hot ? 1. : 0.);
            else
                c->hover.snap(hot ? 1. : 0.);
            if (animations)
                start_animation();
            InvalidateRect(handle, nullptr, FALSE);
        }
    }
    visual::Type type(Font f) const {
        constexpr visual::Type types[]{visual::Text, visual::SmallText, visual::MediumText,
                                       visual::HeadingText, visual::StatusText};
        return types[f];
    }
    int px(int dip) const { return MulDiv(dip, int(dpi), 96); }
    HWND ctrl(PageId page, int id) const {
        for (const auto &c : pages[page].controls)
            if (c.id == id)
                return c.handle;
        return nullptr;
    }
    HWND chrome_ctrl(int id) const {
        for (const auto &c : chrome)
            if (c.id == id)
                return c.handle;
        return nullptr;
    }
    static LRESULT CALLBACK root_proc(HWND h, UINT m, WPARAM w, LPARAM l);
    static LRESULT CALLBACK page_proc(HWND h, UINT m, WPARAM w, LPARAM l);
    static LRESULT CALLBACK button_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR data);
    static LRESULT CALLBACK edit_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR data);
    static LRESULT CALLBACK label_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR data);
    static LRESULT CALLBACK account_list_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR data);
    void paint_log_list(HDC, RECT, double);
    HWND make_control(HWND parent, std::vector<Control> &controls, const wchar_t *cls, const wchar_t *text,
                      int id, DWORD style = 0, Font font = Body, DWORD ex = 0) {
        HWND h = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 1, 1, parent,
                                 reinterpret_cast<HMENU>(INT_PTR(id)), instance, nullptr);
        if (!h)
            throw std::runtime_error("Cannot create native control");
        controls.push_back({h, id, font});
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(fonts[font]), TRUE);
        if (std::wstring_view(cls) == L"BUTTON")
            SetWindowSubclass(h, button_proc, 0, reinterpret_cast<DWORD_PTR>(this));
        else if (std::wstring_view(cls) == L"EDIT")
            SetWindowSubclass(h, edit_proc, 0, reinterpret_cast<DWORD_PTR>(this));
        else if (std::wstring_view(cls) == L"STATIC")
            SetWindowSubclass(h, label_proc, 0, reinterpret_cast<DWORD_PTR>(this));
        return h;
    }
    HWND label(Page &p, const wchar_t *text, int id, Font font = Body) {
        return make_control(p.window, p.controls, L"STATIC", text, id, SS_LEFT | SS_CENTERIMAGE, font);
    }
    HWND button(Page &p, const wchar_t *text, int id) {
        return make_control(p.window, p.controls, L"BUTTON", text, id, BS_OWNERDRAW | WS_TABSTOP);
    }
    void text(PageId page, int id, const std::wstring &value) {
        HWND h = ctrl(page, id);
        if (!h)
            return;
        const int size = GetWindowTextLengthW(h);
        std::wstring old(static_cast<std::size_t>(size) + 1, L'\0');
        GetWindowTextW(h, old.data(), size + 1);
        old.resize(size);
        if (old != value)
            SetWindowTextW(h, value.c_str());
    }
    void place(HWND h, Box b, bool visible = true) {
        if (!h)
            return;
        SetWindowPos(h, nullptr, px(b.x), px(b.y), px(std::max(1, b.w)), px(std::max(1, b.h)),
                     SWP_NOZORDER | SWP_NOACTIVATE);
        ShowWindow(h, visible ? SW_SHOW : SW_HIDE);
    }
    void remake_fonts() {
        auto old = fonts;
        constexpr int heights[]{13, 12, 15, 24, 30};
        constexpr int weights[]{FW_NORMAL, FW_NORMAL, FW_SEMIBOLD, FW_SEMIBOLD, FW_SEMIBOLD};
        for (int i = 0; i < FontCount; ++i)
            fonts[i] = CreateFontW(-px(heights[i]), 0, 0, 0, weights[i], FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH,
                                   L"Segoe UI");
        for (auto &c : chrome)
            SendMessageW(c.handle, WM_SETFONT, reinterpret_cast<WPARAM>(fonts[c.font]), TRUE);
        for (auto &p : pages)
            for (auto &c : p.controls)
                SendMessageW(c.handle, WM_SETFONT, reinterpret_cast<WPARAM>(fonts[c.font]), TRUE);
        for (HFONT f : old)
            if (f)
                DeleteObject(f);
    }
    void motion_preference() {
        BOOL enabled = TRUE;
        SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &enabled, 0);
        animations = enabled != FALSE;
        if (!animations) {
            for (auto &c : chrome) {
                c.hover.snap(c.hover.target());
                c.thumb.snap(c.thumb.target());
            }
            for (auto &p : pages)
                for (auto &c : p.controls) {
                    c.hover.snap(c.hover.target());
                    c.thumb.snap(c.thumb.target());
                }
            page_spring.snap(0);
            nav_spring.snap(double(current) * 44.);
            window_spring.snap(0);
            log_results_spring.snap(0);
            KillTimer(window, animation_timer);
            layout();
        }
        log_scrollbar.configure(dpi, animations);
    }
    void sync_account_list() {
        const auto list = ctrl(Account, AccountList);
        if (!list)
            return;
        std::vector<std::wstring> rows;
        for (const auto &entry : account_catalog.entries) {
            auto name = entry.username;
            if (entry.id == active_account_id && status == Status::Online)
                name += L" · 活跃中";
            rows.push_back(std::move(name));
        }
        bool same = SendMessageW(list, LB_GETCOUNT, 0, 0) == LRESULT(rows.size());
        if (same)
            for (std::size_t n = 0; n < rows.size(); ++n) {
                const auto length = SendMessageW(list, LB_GETTEXTLEN, n, 0);
                std::wstring row_text(std::size_t(std::max<LRESULT>(0, length)) + 1, L'\0');
                if (length >= 0)
                    SendMessageW(list, LB_GETTEXT, n, reinterpret_cast<LPARAM>(row_text.data()));
                row_text.resize(std::size_t(std::max<LRESULT>(0, length)));
                if (row_text != rows[n]) {
                    same = false;
                    break;
                }
            }
        if (!same && !account_pointer.active()) {
            SendMessageW(list, WM_SETREDRAW, FALSE, 0);
            SendMessageW(list, LB_RESETCONTENT, 0, 0);
            for (const auto &row : rows)
                SendMessageW(list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row.c_str()));
            int selection = -1;
            for (std::size_t n = 0; n < account_catalog.entries.size(); ++n)
                if (account_catalog.entries[n].id == form_account_id)
                    selection = int(n);
            SendMessageW(list, LB_SETCURSEL, selection, 0);
            SendMessageW(list, WM_SETREDRAW, TRUE, 0);
        }
        InvalidateRect(list, nullptr, FALSE);
    }
    void edit_account(std::string id, bool focus = false) {
        const auto *entry = account_catalog.find(id);
        form_account_id = entry ? entry->id : std::string{};
        if (!ctrl(Account, UserInput))
            return;
        SetWindowTextW(ctrl(Account, UserInput), entry ? entry->username.c_str() : L"");
        SetWindowTextW(ctrl(Account, PasswordInput), L"");
        SendMessageW(ctrl(Account, PasswordInput), EM_SETCUEBANNER, 0,
                     reinterpret_cast<LPARAM>(entry ? L"已保存" : L"密码"));
        text(Account, FormMessage, L"");
        int selected = -1;
        for (std::size_t n = 0; n < account_catalog.entries.size(); ++n)
            if (account_catalog.entries[n].id == form_account_id)
                selected = int(n);
        SendMessageW(ctrl(Account, AccountList), LB_SETCURSEL, selected, 0);
        update_page(Account);
        if (focus)
            SetFocus(ctrl(Account, entry ? PasswordInput : UserInput));
    }
    void select_account() {
        if (pending_credential)
            return;
        const auto selected = SendMessageW(ctrl(Account, AccountList), LB_GETCURSEL, 0, 0);
        if (selected >= 0 && std::size_t(selected) < account_catalog.entries.size()) {
            form_account_id = account_catalog.entries[std::size_t(selected)].id;
        } else
            form_account_id.clear();
    }
    void clear_account_selection() {
        if (current == Account && !account_editor && !account_service && !settings.mini)
            account_pointer.clear_selection();
    }
    void create_campus_controls() {
        if (ctrl(Account, CampusUser)) return;
        auto& p = pages[Account];
        label(p, L"", CampusUser, Medium);
        label(p, L"未知", CampusStateValue, Title);
        label(p, L"未知", CampusDevices, Title);
        label(p, L"", CampusMessage, Small);
        label(p, L"", CampusConfirmation);
        button(p, L"暂停校园网", CampusActionButton);
        button(p, L"刷新", CampusRefresh);
        button(p, L"取消", CampusCancel);
        if (!ctrl(Account,Progress)) label(p, L"正在查询", Progress, Small);
    }
    bool campus_permitted() const {
        const auto* account = account_catalog.find(campus_account_id);
        return !campus_busy && account && account->secret_id == campus_secret &&
               !campus_ticket.empty() && campus_view.error == CampusError::None &&
               (campus_view.can_pause || campus_view.can_resume);
    }
    void query_campus() {
        if (!account_service || campus_busy) return;
        campus_busy = true;
        campus_confirming = false;
        campus_ticket.clear();
        campus_message = L"正在查询";
        backend->prepare_campus(campus_account_id, ++campus_request);
        update_page(Account);
        layout(); timers();
    }
    void open_campus(std::string id) {
        if (settings.mini || pending_credential || !account_catalog.find(id)) return;
        const bool same_page = current == Account;
        account_editor = false;
        account_service = true;
        campus_account_id = std::move(id);
        campus_secret = account_catalog.find(campus_account_id)->secret_id;
        campus_view = {}; campus_ticket.clear(); campus_message.clear();
        campus_busy = false; campus_confirming = false;
        create_page(Account);
        create_campus_controls();
        if (same_page) account_transition(14); else show(Account);
        query_campus();
        SetFocus(ctrl(Account, AccountBack));
    }
    void close_campus() {
        account_service = false;
        campus_confirming = false;
        campus_ticket.clear();
        ++campus_request; // Late replies may update counts, never reopen a confirmation.
        update_page(Account);
        account_transition(-14);
        request_visible_packages();
        SetFocus(ctrl(Account, AccountList));
    }
    void create_account_editor() {
        if (ctrl(Account, UserInput))
            return;
        auto &p = pages[Account];
        label(p, L"账号", UserLabel);
        auto user =
            make_control(p.window, p.controls, L"EDIT", L"", UserInput, WS_TABSTOP | ES_AUTOHSCROLL, Body);
        label(p, L"密码", PasswordLabel);
        auto password = make_control(p.window, p.controls, L"EDIT", L"", PasswordInput,
                                     WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, Body);
        for (auto input : {user, password}) {
            SendMessageW(input, EM_SETLIMITTEXT, 256, 0);
            SendMessageW(input, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, 0);
        }
        SendMessageW(password, EM_SETPASSWORDCHAR, L'●', 0);
        SendMessageW(user, EM_SETCUEBANNER, 0, reinterpret_cast<LPARAM>(L"校园网账号"));
        button(p, L"显示", PasswordEye);
        button(p, L"保存", SaveCredential);
    }
    void clear_password_fields() {
        for (int id : {OldPasswordInput, NewPasswordInput, ConfirmPasswordInput})
            if (auto input = ctrl(Account,id)) SetWindowTextW(input,L"");
    }
    void create_password_controls() {
        if (ctrl(Account,OldPasswordInput)) return;
        auto& p = pages[Account];
        label(p,L"",PasswordAccount,Medium);
        for (auto field : {std::pair{OldPasswordLabel,L"旧密码"},std::pair{NewPasswordLabel,L"新密码"},
                           std::pair{ConfirmPasswordLabel,L"确认密码"}}) {
            label(p,field.second,field.first);
            auto input = make_control(p.window,p.controls,L"EDIT",L"",field.first+1,
                                      WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD);
            SendMessageW(input,EM_SETLIMITTEXT,256,0);
            SendMessageW(input,EM_SETPASSWORDCHAR,L'●',0);
            SendMessageW(input,EM_SETMARGINS,EC_LEFTMARGIN | EC_RIGHTMARGIN,0);
        }
        button(p,L"修改密码",SubmitPasswordChange);
        button(p,L"信息门户改密",PortalPasswordLink);
        button(p,L"官方自助",OfficialPasswordLink);
        if (!ctrl(Account,Progress)) label(p,L"正在修改",Progress,Small);
    }
    void open_password_view(std::string id) {
        if (settings.mini || pending_credential || password_busy || !account_catalog.find(id)) return;
        const bool same_page = current == Account;
        account_editor = false; account_service = false; campus_confirming = false; campus_ticket.clear(); ++campus_request;
        create_page(Account);
        password_account_id = std::move(id);
        password_secret = account_catalog.find(password_account_id)->secret_id;
        password_view = account_editor = true;
        password_confirming = password_submitted = password_official = false; password_message.clear();
        create_password_controls(); clear_password_fields();
        update_page(Account);
        if (same_page) account_transition(14); else show(Account);
        SetFocus(ctrl(Account,OldPasswordInput));
    }
    void submit_password_change() {
        if (!password_view || password_busy || password_submitted) return;
        auto input = std::make_shared<PasswordEdit>();
        const auto read = [&](int id,std::wstring& target) {
            std::array<wchar_t,257> buffer{};
            GetWindowTextW(ctrl(Account,id),buffer.data(),int(buffer.size())); target = buffer.data();
            SecureZeroMemory(buffer.data(),sizeof(buffer));
        };
        read(OldPasswordInput,input->old_password); read(NewPasswordInput,input->new_password);
        read(ConfirmPasswordInput,input->confirmation);
        Credential entered; entered.username = L"form-validation"; entered.password = input->old_password;
        const auto error = validate_password_change(entered,input->old_password,input->new_password,input->confirmation);
        if (error != PasswordChangeError::None) {
            password_message = password_change_error_text(error);
            password_official = error == PasswordChangeError::UnsupportedCharacters ||
                                error == PasswordChangeError::PasswordLength || error == PasswordChangeError::TooLong;
            update_page(Account); layout(); return;
        }
        if (!password_confirming) {
            password_confirming = true; password_message = L"确认修改校园网密码";
            update_page(Account); account_transition(4); SetFocus(ctrl(Account,SubmitPasswordChange)); return;
        }
        password_busy = true; password_confirming = false; password_message = L"正在修改";
        backend->change_password(password_account_id,password_secret,std::move(input),++password_request);
        update_page(Account); layout(); timers();
    }
    void account_transition(double distance) {
        if (animations && current == Account && IsWindowVisible(window)) {
            page_spring.enter(distance);
            start_animation();
        }
        layout();
    }
    void open_account_editor(std::string id) {
        if (pending_credential)
            return;
        const bool same_page = current == Account && pages[Account].window;
        if (password_view) { clear_password_fields(); password_view = false; }
        account_service = false;
        campus_confirming = false;
        campus_ticket.clear();
        ++campus_request;
        account_editor = true;
        create_page(Account);
        create_account_editor();
        edit_account(std::move(id));
        if (same_page)
            account_transition(14);
        else
            show(Account);
        SetFocus(ctrl(Account, form_account_id.empty() ? UserInput : PasswordInput));
    }
    void close_account_editor() {
        if (password_view) { clear_password_fields(); password_view = false; password_confirming = false; }
        account_editor = false;
        if (ctrl(Account, PasswordInput))
            SetWindowTextW(ctrl(Account, PasswordInput), L"");
        text(Account, FormMessage, L"");
        update_page(Account);
        account_transition(-14);
        SetFocus(ctrl(Account, account_catalog.entries.empty() ? AddAccount : AccountList));
    }
    void account_menu(HWND list, POINT point) {
        if (pending_credential || account_editor || account_service || settings.mini)
            return;
        int selected;
        if (point.x == -1 && point.y == -1) {
            selected = int(SendMessageW(list, LB_GETCURSEL, 0, 0));
            RECT row{};
            if (selected < 0 ||
                SendMessageW(list, LB_GETITEMRECT, selected, reinterpret_cast<LPARAM>(&row)) == LB_ERR)
                return;
            point = {row.left + px(88), row.bottom - px(8)};
            ClientToScreen(list, &point);
        } else {
            auto client = point;
            ScreenToClient(list, &client);
            selected = account_pointer.hit_test(client);
        }
        if (selected < 0 || std::size_t(selected) >= account_catalog.entries.size()) {
            account_pointer.clear_selection();
            return;
        }
        account_pointer.cancel();
        SendMessageW(list, LB_SETCURSEL, selected, 0);
        form_account_id = account_catalog.entries[std::size_t(selected)].id;
        SetFocus(list);
        InvalidateRect(list, nullptr, FALSE);
        const bool active = connected_or_busy(status) && form_account_id == active_account_id;
        popup.show(
            window, point,
            {{ManageAccount, L"管理", visual::Icon::User},
             {ChangePasswordMenu, L"修改密码", visual::Icon::Key, !password_busy},
             {CampusAccount, L"校园网", visual::Icon::Network},
             {DeleteAccount, L"删除", visual::Icon::Trash, !active, true},
             {PinAccount, L"置顶", visual::Icon::Pin, selected != 0}},
            [this](int chosen) { command(chosen); }, dpi, animations, L"账号操作");
    }
    void move_account(int from, int to) {
        if (pending_credential || from < 0 || to < 0 || std::size_t(from) >= account_catalog.entries.size() ||
            std::size_t(to) >= account_catalog.entries.size() || from == to)
            return;
        std::vector<std::string> ids;
        for (const auto &entry : account_catalog.entries)
            ids.push_back(entry.id);
        const auto id = ids[std::size_t(from)];
        ids.erase(ids.begin() + from);
        ids.insert(ids.begin() + to, id);
        pending_credential = true;
        text(Account, FormMessage, L"");
        update_page(Account);
        backend->reorder_accounts(std::move(ids));
    }
    void create_page(PageId id) {
        auto &p = pages[id];
        if (p.window)
            return;
        p.app = this;
        p.id = id;
        p.window = CreateWindowExW(WS_EX_CONTROLPARENT, page_class, L"", WS_CHILD | WS_CLIPCHILDREN, 0, 0, 1,
                                   1, window, nullptr, instance, &p);
        if (!p.window)
            throw std::runtime_error("Cannot create native page");
        if (id == Home) {
            label(p, L"连接", Heading, Title);
            button(p, L"有线 802.1X", ConnectionModePicker);
            label(p, L"正在加载", StateText, Large);
            label(p, L"", StateMessage, Small);
            label(p, L"", AccountValue);
            button(p, L"登录", Action);
            button(p, L"登录", Login);
            button(p,L"使用此认证页面",PortalAccept);
            button(p, L"连接详情", Details);
            label(p, L"", Duration);
            label(p, L"", AdapterValue);
            label(p, L"余额 未知", HomeBalance);
            label(p, L"到期时间 未知", HomeExpiry, Small);
            label(p, L"", PackageStatus, Small);
            label(p, L"未知", HomeDevices);
            label(p, L"正在连接", Progress, Small);
        } else if (id == Account) {
            label(p, L"账号", Heading, Title);
            button(p, L"新增", AddAccount);
            button(p, L"返回", AccountBack);
            auto list = make_control(p.window, p.controls, L"LISTBOX", L"已保存账号", AccountList,
                                     WS_TABSTOP | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_NOTIFY |
                                         LBS_OWNERDRAWFIXED | LBS_HASSTRINGS,
                                     Body);
            account_pointer.attach(
                list, [this](int) { select_account(); }, [this](int from, int to) { move_account(from, to); },
                [this](HDC dc, RECT bounds, int index) {
                    if (renderer.begin(dc, bounds, dpi, visual::Soft)) {
                        draw_account_strip(index,
                                           {.5f, .5f, float(bounds.right) * 96 / dpi - 1,
                                            float(bounds.bottom) * 96 / dpi - 1},
                                           true, false, true);
                        renderer.end();
                    }
                });
            SetWindowSubclass(list, account_list_proc, 0, reinterpret_cast<DWORD_PTR>(this));
            label(p, L"暂无账号", AccountsEmpty, Small);
            label(p, L"", FormMessage, Small);
            if (account_editor || settings.mini) {
                create_account_editor();
                edit_account(form_account_id);
            }
        } else if (id == Preferences) {
            label(p, L"设置", Heading, Title);
            button(p,L"检查更新",CheckUpdate);
            label(p,updates::current_version,UpdateStatus,Small);
            make_control(p.window, p.controls, L"BUTTON", L"小窗模式", MiniToggle,
                         WS_TABSTOP | BS_AUTOCHECKBOX);
            label(p, L"启动方式", StartupHeading, Medium);
            button(p, L"开机连接：跟随上次选择", StartupMode1);
            button(p, L"添加备用方式", StartupMode2);
            button(p, L"添加备用方式", StartupMode3);
            make_control(p.window, p.controls, L"BUTTON", L"开机自启", AutoStartToggle,
                         WS_TABSTOP | BS_AUTOCHECKBOX);
            make_control(p.window, p.controls, L"BUTTON", L"静默启动", SilentToggle,
                         WS_TABSTOP | BS_AUTOCHECKBOX);
            button(p, L"退出小窗模式", ExitMini);
            label(p, L"", SettingsMessage, Small);
        } else {
            label(p, L"记录", Heading, Title);
            button(p, L"刷新", RefreshLogs);
            label(p, L"", LogsMessage, Small);
            label(p, L"搜索记录", LogSearchLabel, Small);
            auto search = make_control(p.window, p.controls, L"EDIT", L"", LogSearch,
                                       WS_TABSTOP | ES_AUTOHSCROLL);
            SendMessageW(search, EM_SETLIMITTEXT, 256, 0);
            SendMessageW(search, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"搜索记录"));
            button(p, L"清除搜索", ClearLogSearch);
            button(p, L"全部状态", LogStateFilter);
            button(p, L"全部时间", LogTimeFilter);
            button(p, L"最新在前", LogSort);
            label(p, L"", LogCount, Small);
            button(p, L"重置", ResetLogFilters);
            label(p, L"运行记录", LogListLabel, Small);
            auto list = make_control(p.window, p.controls, L"LISTBOX", L"运行记录", LogList,
                         WS_TABSTOP | LBS_NOINTEGRALHEIGHT | LBS_NOTIFY | LBS_OWNERDRAWFIXED |
                             LBS_HASSTRINGS,
                         Small);
            log_scrollbar.attach(list, dpi, animations,
                                 [this](HDC dc, RECT bounds, double offset) { paint_log_list(dc, bounds, offset); });
            label(p, L"正在加载", Progress, Small);
            update_log_controls();
        }
        update_page(id);
    }
    void update_page(PageId id) {
        if (!pages[id].window)
            return;
        if (id == Home) {
            text(Home, StateText, status_text(status, credentials));
            text(Home, StateMessage, message);
            text(Home, AccountValue,
                 status == Status::Online ? active_username :
                 masked(status == Status::Error && !active_username.empty() ? active_username : username));
            if (status == Status::Online && active_account_id.empty()) {
                if (const auto* account = account_catalog.find(home_package_account()))
                    text(Home, AccountValue, L"账号未确认 · 套餐账号 " + account->username);
            }
            const auto& billing = package_for(home_package_account());
            SYSTEMTIME local{}; GetLocalTime(&local);
            const std::chrono::year_month_day today{std::chrono::year{int(local.wYear)},
                                                     std::chrono::month{local.wMonth}, std::chrono::day{local.wDay}};
            text(Home, HomeBalance, L"余额 " + (billing.state == PackageState::Loading && !billing.balance
                                                   ? std::wstring(L"加载中") : money_text(billing.balance)));
            const auto query_status = package_status_text(billing.state);
            text(Home, HomeExpiry, !billing.balance && !query_status.empty() ? query_status : package_expiry_text(billing, today));
            text(Home, PackageStatus, package_status_text(billing.state));
            text(Home, HomeDevices, device_count_text(billing.online_devices));
            text(Home, Action, settings.mini && !portal_ticket.empty() ? L"登录" : connected_or_busy(status) ? L"断开连接" : credentials ? L"连接" : L"登录");
            text(Home, Login, !portal_ticket.empty() ? L"断开连接" : L"登录");
            EnableWindow(ctrl(Home,PortalAccept),!portal_approving);
            text(Home, AdapterValue, adapter);
            text(Home, Details, show_details ? L"收起详情" : L"连接详情");
            text(Home, ConnectionModePicker, connection_mode_label(display_mode()));
            EnableWindow(ctrl(Home, ConnectionModePicker), initialized && !connected_or_busy(status) &&
                         status != Status::Stopping && !pending_settings && !pending_credential);
            EnableWindow(ctrl(Home, Action),
                         initialized && status != Status::Stopping && !pending_credential && !pending_settings &&
                         !(settings.mini && portal_approving));
            update_uptime();
        } else if (id == Account) {
            if (password_view) {
                text(Account,Heading,L"校园网密码");
                const auto* entry = account_catalog.find(password_account_id);
                text(Account,PasswordAccount,entry ? entry->username : L"");
                text(Account,FormMessage,password_message);
                text(Account,SubmitPasswordChange,password_busy ? L"正在修改" : password_confirming ? L"确认修改" : L"修改密码");
                for (int field : {OldPasswordInput,NewPasswordInput,ConfirmPasswordInput,SubmitPasswordChange})
                    EnableWindow(ctrl(Account,field),!password_busy && !password_submitted);
                EnableWindow(ctrl(Account,AccountBack),!password_busy);
                return;
            }
            text(Account, Heading,
                 account_service ? L"校园网" : account_editor ? (!credentials ? L"登录" : form_account_id.empty() ? L"新增账号" : L"管理账号") : L"账号");
            if (account_service) {
                const auto* account = account_catalog.find(campus_account_id);
                text(Account, CampusUser, account ? account->username : L"");
                text(Account, CampusStateValue, campus_busy && campus_view.state == CampusState::Unknown
                                                   ? L"查询中" : campus_state_text(campus_view.state));
                text(Account, CampusDevices, device_count_text(campus_view.online_devices));
                const bool resume = campus_view.state == CampusState::Paused;
                text(Account, CampusActionButton, campus_busy ? L"正在处理" : campus_confirming
                     ? (resume ? L"确认恢复" : L"确认暂停") : (resume ? L"恢复校园网" : L"暂停校园网"));
                text(Account, CampusConfirmation, resume ? L"恢复后可重新认证上网。"
                     : L"暂停将断网，恢复前无法认证；套餐周期恢复后顺延。");
                text(Account, CampusMessage, campus_message);
                EnableWindow(ctrl(Account, CampusActionButton), campus_permitted());
                EnableWindow(ctrl(Account, CampusRefresh), !campus_busy);
                EnableWindow(ctrl(Account, CampusCancel), !campus_busy);
            }
            text(Account, SaveCredential,
                 pending_credential ? L"正在保存"
                 : connect_after_save() ? L"登录"
                                    : L"保存");
            const bool editable = !pending_credential && status != Status::Stopping;
            for (int control : {UserInput, PasswordInput, SaveCredential, PasswordEye, AccountList,
                                AddAccount, AccountBack})
                if (auto handle = ctrl(Account, control))
                    EnableWindow(handle, editable);
            sync_account_list();
        } else if (id == Preferences) {
            SendMessageW(ctrl(Preferences, MiniToggle), BM_SETCHECK,
                         settings.mini ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessageW(ctrl(Preferences, AutoStartToggle), BM_SETCHECK,
                         settings.auto_start ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessageW(ctrl(Preferences, SilentToggle), BM_SETCHECK,
                         settings.silent ? BST_CHECKED : BST_UNCHECKED, 0);
            for (int id2 : {MiniToggle, AutoStartToggle, SilentToggle, ExitMini,StartupMode1,StartupMode2,StartupMode3})
                EnableWindow(ctrl(Preferences, id2), !pending_settings);
            for (int slot=0;slot<3;++slot) {
                const auto title = std::size_t(slot) < settings.startup_modes.size()
                    ? std::to_wstring(slot+1)+L". "+connection_mode_label(settings.startup_modes[slot])
                    : slot == 0 ? std::wstring(L"开机连接：跟随上次选择") : std::wstring(L"添加备用方式");
                text(Preferences,StartupMode1+slot,title);
            }
            for (auto entry :
                 {std::pair{MiniToggle, settings.mini}, std::pair{AutoStartToggle, settings.auto_start},
                  std::pair{SilentToggle, settings.silent}}) {
                if (auto *c = control(ctrl(Preferences, entry.first))) {
                    if (animations && current == Preferences && IsWindowVisible(window))
                        c->thumb.move_to(entry.second ? 1. : 0.);
                    else
                        c->thumb.snap(entry.second ? 1. : 0.);
                    InvalidateRect(c->handle, nullptr, FALSE);
                }
            }
            if (controls_moving())
                start_animation();
            refresh_update_controls();
        }
    }
    void layout_page(PageId id, int width, int height) {
        auto &p = pages[id];
        if (!p.window)
            return;
        auto put = [&](int control, Box b, bool visible = true) { place(ctrl(id, control), b, visible); };
        if (id == Home) {
            if (settings.mini) {
                put(Heading, {0, 0, 1, 1}, false);
                put(ConnectionModePicker, {0, 0, 1, 1}, false);
                put(PortalAccept,{0,0,1,1},false);
                put(StateText, {64, 2, width - 64, 44});
                put(StateMessage, {0, 60, width, 36}, !message.empty());
                const int action_y = message.empty() ? 80 : 114;
                put(Action, {0, action_y, width, 40});
                put(Login, {0, action_y + 46, width, 30},
                    !portal_ticket.empty() || (credentials && !connected_or_busy(status) && status != Status::Stopping));
                put(AccountValue, {0, 0, 1, 1}, false);
                put(Duration, {0, 0, 1, 1}, false);
                put(AdapterValue, {0, 0, 1, 1}, false);
                put(HomeBalance, {0, 0, 1, 1}, false);
                put(HomeExpiry, {0, 0, 1, 1}, false);
                put(PackageStatus, {0, 0, 1, 1}, false);
                put(HomeDevices, {0, 0, 1, 1}, false);
                put(Details, {0, 0, 1, 1}, false);
                put(Progress, {0, action_y - 12, width, 3},
                    status == Status::Connecting || status == Status::Recovering ||
                        status == Status::Loading);
            } else {
                put(Heading, {0, 0, width - 176, 38});
                put(ConnectionModePicker, {width - 164, 0, 164, 34});
                put(StateText, {28, 124, width - 205, 48});
                put(AccountValue, {50, 178, width - 230, 26}, credentials);
                put(PortalAccept,{28,258,192,40},!portal_ticket.empty());
                put(Action, {!portal_ticket.empty() ? 232 : 28, 258, 146, 40});
                put(Login, {186, 258, 100, 40},
                    credentials && !connected_or_busy(status) && status != Status::Stopping);
                put(StateMessage, {28, !portal_ticket.empty() ? 196 : 207, width - 205, !portal_ticket.empty() ? 52 : 36}, !message.empty());
                put(Details, {0, 354, width, 44});
                put(Duration, {28, 461, width / 3 - 48, 30}, show_details);
                put(AdapterValue, {width / 3 + 28, 461, width / 3 - 48, 30}, show_details);
                put(HomeDevices, {2 * width / 3 + 28, 461, width / 3 - 56, 30}, show_details);
                put(HomeBalance, {width - 184, 254, 156, 26}, status == Status::Online);
                put(HomeExpiry, {width - 184, 282, 156, 24}, status == Status::Online);
                put(PackageStatus, {28, 508, width - 56, 24}, show_details && status == Status::Online &&
                    !package_status_text(package_for(home_package_account()).state).empty());
                put(Progress, {28, 321, width - 56, 3},
                    status == Status::Connecting || status == Status::Recovering ||
                        status == Status::Loading);
            }
        } else if (id == Account) {
            if (password_view) {
                for (auto& control : p.controls) place(control.handle,{0,0,1,1},false);
                const auto form = account_form(width);
                const int left = form.x + 28, field = form.w - 56;
                put(Heading,{44,0,width-44,38}); put(AccountBack,{0,2,32,34});
                put(PasswordAccount,{left,96,field-164,28});
                put(PortalPasswordLink,{left+field-152,98,152,28});
                for (auto item : {std::pair{OldPasswordLabel,144},std::pair{NewPasswordLabel,232},std::pair{ConfirmPasswordLabel,320}}) {
                    put(item.first,{left,item.second,field,22});
                    put(item.first+1,{left+36,item.second+44,field-52,20});
                }
                put(SubmitPasswordChange,{left,418,field,42});
                put(FormMessage,{left,466,field-(password_official ? 104 : 0),46},!password_message.empty());
                put(OfficialPasswordLink,{left+field-96,472,96,30},password_official);
                put(Progress,{left,514,field,3},password_busy);
                return;
            }
            for (auto& control : p.controls)
                if (control.id >= PasswordAccount && control.id <= OfficialPasswordLink)
                    place(control.handle,{0,0,1,1},false);
            const auto form = account_form(width);
            const bool service = !settings.mini && account_service;
            const bool editor = settings.mini || (account_editor && !service);
            const int inset = settings.mini ? 0 : 28, top = settings.mini ? 0 : 100;
            const int left = form.x + inset, field = form.w - 2 * inset;
            const int rows = account_list_height(height);
            put(Heading, {account_editor || service ? 44 : 0, 0, width - 148, 38}, !settings.mini);
            put(AccountBack, {0, 2, 32, 34}, !settings.mini && (account_editor || service));
            put(AddAccount, {width - 88, 0, 88, 34}, !editor && !service);
            put(AccountList, {0, 76, width, rows}, !editor && !service && !account_catalog.entries.empty());
            SendMessageW(ctrl(Account, AccountList), LB_SETITEMHEIGHT, 0, px(account_row_height));
            account_pointer.geometry(dpi, px(account_row_height), px(account_row_gap),
                                     px(int(account_row_radius)), animations);
            put(AccountsEmpty, {16, 76 + rows / 2 + 18, width - 32, 28},
                !editor && !service && account_catalog.entries.empty());
            put(UserLabel, {left, top, field, 22}, editor);
            put(UserInput, {left + 36, top + 44, field - 52, 20}, editor);
            put(PasswordLabel, {left, top + 96, field, 22}, editor);
            put(PasswordInput, {left + 36, top + 140, field - 82, 20}, editor);
            put(PasswordEye, {left + field - 36, top + 132, 30, 36}, editor);
            put(SaveCredential, {left, top + 202, field, 42}, editor);
            put(FormMessage, editor ? Box{left, top + 253, field, 40} : Box{0, 86 + rows, width, 30}, !service);
            put(CampusRefresh, {width - 86, 0, 86, 34}, service);
            put(CampusUser, {left + 60, 100, field - 60, 28}, service);
            put(CampusStateValue, {left + 16, 202, field / 2 - 44, 36}, service);
            put(CampusDevices, {left + field / 2 + 22, 202, field / 2 - 38, 36}, service);
            put(CampusConfirmation, {left, 270, field, 52}, service && campus_confirming);
            put(CampusActionButton, {left, campus_confirming ? 338 : 274,
                                    campus_confirming ? field - 100 : field, 42}, service);
            put(CampusCancel, {left + field - 88, 338, 88, 42}, service && campus_confirming);
            put(CampusMessage, {left, campus_confirming ? 393 : 330, field, 40}, service && !campus_message.empty());
            put(Progress, {left, campus_confirming ? 442 : 364, field, 3}, service && campus_busy);
        } else if (id == Preferences) {
            put(Heading, {0, 0, width-170, 38}, !settings.mini);
            put(CheckUpdate,{width-150,2,150,34},!settings.mini);
            put(UpdateStatus,{0,42,width,24},!settings.mini);
            put(MiniToggle, {16, 90, width - 32, 48}, !settings.mini);
            put(StartupHeading, {0, 180, width, 28}, !settings.mini);
            put(AutoStartToggle, {16, 232, width - 32, 48}, !settings.mini);
            put(SilentToggle, {16, 284, width - 32, 48}, !settings.mini);
            put(StartupMode1,{16,346,width-32,40},!settings.mini);
            put(StartupMode2,{16,392,width-32,40},!settings.mini && !settings.startup_modes.empty());
            put(StartupMode3,{16,438,width-32,40},!settings.mini && settings.startup_modes.size()>=2);
            put(ExitMini, {0, 9, width, 44}, settings.mini);
            put(SettingsMessage, {0, settings.mini ? 64 : settings.startup_modes.size()>=2 ? 496 : !settings.startup_modes.empty() ? 450 : 404, width, 32});
        } else {
            put(Heading, {0, 0, width - 100, 38});
            put(RefreshLogs, {width - 86, 0, 86, 34});
            const int search_width = log_search_width(width);
            put(LogSearchLabel, {0, 0, 1, 1}, false);
            put(LogListLabel, {0, 0, 1, 1}, false);
            put(LogSearch, {36, 80, search_width - 72, 19});
            put(ClearLogSearch, {search_width - 30, 74, 26, 28}, !log_query.search.empty());
            put(LogStateFilter, {search_width + 10, 68, 108, 40});
            put(LogTimeFilter, {search_width + 128, 68, 126, 40});
            put(LogSort, {width - 126, 68, 126, 40});
            put(LogCount, {0, 118, width - 80, 24});
            put(ResetLogFilters, {width - 58, 118, 58, 24}, log_filters_active());
            const bool empty = SendMessageW(ctrl(Logs, LogList), LB_GETCOUNT, 0, 0) == 0;
            put(LogsMessage, {16, 152 + std::max(100, height - 156) / 2 + 12, width - 32, 28}, empty);
            put(LogList, {12, 164 + int(std::lround(log_results_spring.value())), width - 24,
                          std::max(80, height - 180)}, !empty);
            SendMessageW(ctrl(Logs, LogList), LB_SETITEMHEIGHT, 0, px(68));
            log_scrollbar.sync(true);
            put(Progress, {16, 155, width - 32, 3}, logs_loading);
        }
        RedrawWindow(p.window, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
    }
    void layout() {
        if (!window)
            return;
        RECT rc{};
        GetClientRect(window, &rc);
        const int w = MulDiv(rc.right, 96, int(dpi)), h = MulDiv(rc.bottom, 96, int(dpi));
        std::wstring caption =
            settings.mini && current != Home ? (current == Preferences ? L"设置" : L"登录") : L"SCAU Link";
        if (options.demo)
            caption += L" · 演示";
        wchar_t old_caption[64]{};
        GetWindowTextW(chrome_ctrl(Brand), old_caption, 64);
        if (std::wstring_view(old_caption) != caption)
            SetWindowTextW(chrome_ctrl(Brand), caption.c_str());
        const wchar_t *maximize_name = IsZoomed(window) ? L"还原" : L"最大化";
        GetWindowTextW(chrome_ctrl(WindowMaximize), old_caption, 64);
        if (std::wstring_view(old_caption) != maximize_name)
            SetWindowTextW(chrome_ctrl(WindowMaximize), maximize_name);
        place(chrome_ctrl(Brand),
              {settings.mini && current != Home ? 50 : 16, 0, 180, settings.mini ? 52 : 44});
        for (int i = 0; i < PageCount; ++i)
            place(chrome_ctrl(NavHome + i), {12, 140 + i * 44, 160, 40}, !settings.mini);
        place(chrome_ctrl(MiniBack), {12, 10, 32, 32}, settings.mini && current != Home);
        place(chrome_ctrl(MiniSettings), {w - 78, 10, 32, 32}, settings.mini && current == Home);
        place(chrome_ctrl(WindowMinimize), {w - (settings.mini ? 42 : 132), settings.mini ? 10 : 0,
                                            settings.mini ? 32 : 44, settings.mini ? 32 : 44});
        place(chrome_ctrl(WindowMaximize), {w - 88, 0, 44, 44}, !settings.mini);
        place(chrome_ctrl(WindowClose), {w - 44, 0, 44, 44}, !settings.mini);
        const auto content = page_box(w, h);
        const int x = content.x, y = content.y, pw = content.w, ph = content.h;
        for (int i = 0; i < PageCount; ++i)
            if (pages[i].window) {
                SetWindowPos(pages[i].window, nullptr,
                             px(x + (i == current ? int(std::lround(page_spring.value())) : 0)), px(y),
                             px(std::max(1, pw)), px(std::max(1, ph)), SWP_NOZORDER | SWP_NOACTIVATE);
                layout_page(PageId(i), pw, ph);
            }
        InvalidateRect(window, nullptr, FALSE);
    }
    void start_animation() {
        if (!animations)
            return;
        last_frame = GetTickCount64();
        SetTimer(window, animation_timer, 15, nullptr);
    }
    void timer() {
        const auto now = GetTickCount64();
        const double seconds = double(now - last_frame) / 1000.;
        last_frame = now;
        const bool moving_window = window_spring.active(), moving_page = page_spring.active();
        page_spring.step(seconds);
        nav_spring.step(seconds);
        window_spring.step(seconds);
        const bool moving_results = log_results_spring.active();
        log_results_spring.step(seconds);
        if (current == Logs && moving_results && pages[Logs].window) {
            const auto list = ctrl(Logs, LogList);
            RECT rect{};
            GetWindowRect(list, &rect);
            MapWindowPoints(HWND_DESKTOP, pages[Logs].window, reinterpret_cast<POINT *>(&rect), 2);
            SetWindowPos(list, nullptr, rect.left, px(164 + int(std::lround(log_results_spring.value()))),
                         0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
        if (pages[current].window && moving_page) {
            RECT rc{};
            GetClientRect(window, &rc);
            const auto content = page_box(MulDiv(rc.right, 96, int(dpi)), MulDiv(rc.bottom, 96, int(dpi)));
            SetWindowPos(pages[current].window, nullptr,
                         px(content.x + int(std::lround(page_spring.value()))), px(content.y), 0, 0,
                         SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
        if (moving_window)
            SetWindowPos(window, nullptr, window_destination.x,
                         window_destination.y + px(int(std::lround(window_spring.value()))), 0, 0,
                         SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        RECT marker{px(7), px(140), px(12), px(318)};
        if (!settings.mini)
            InvalidateRect(window, &marker, FALSE);
        for (auto &c : chrome) {
            const bool active = c.hover.active() || c.thumb.active();
            c.hover.step(seconds);
            c.thumb.step(seconds);
            if (active)
                InvalidateRect(c.handle, nullptr, FALSE);
        }
        for (auto &p : pages)
            if (p.window && IsWindowVisible(p.window))
                for (auto &c : p.controls) {
                    const bool active = c.hover.active() || c.thumb.active();
                    c.hover.step(seconds);
                    c.thumb.step(seconds);
                    if (active)
                        InvalidateRect(c.handle, nullptr, FALSE);
                }
        if (!page_spring.active() && !nav_spring.active() && !window_spring.active() &&
            !log_results_spring.active() && !controls_moving()) {
            KillTimer(window, animation_timer);
            if (pages[current].window)
                layout();
        }
    }
    void update_uptime() {
        if (!pages[Home].window)
            return;
        const auto seconds = status == Status::Online ? (GetTickCount64() - online_since) / 1000 : 0;
        wchar_t t[64]{};
        swprintf_s(t, L"%02llu:%02llu:%02llu", seconds / 3600, (seconds / 60) % 60, seconds % 60);
        text(Home, Duration, t);
    }
    void timers() {
        const bool visible = IsWindowVisible(window) && !IsIconic(window);
        if (visible && !settings.mini &&
            ((current == Home && status == Status::Online) || (current == Account && !account_editor && !account_service)))
            SetTimer(window, package_timer, 15000, nullptr); // Backend deduplicates and applies per-account backoff.
        else KillTimer(window, package_timer);
        if (visible && current == Home && !settings.mini && status == Status::Online && show_details)
            SetTimer(window, uptime_timer, 1000, nullptr);
        else
            KillTimer(window, uptime_timer);
        const bool progress = visible &&
            ((current == Home && (status == Status::Loading || status == Status::Connecting || status == Status::Recovering)) ||
             (current == Logs && logs_loading) || (current == Account && ((account_service && campus_busy) || (password_view && password_busy))));
        if (progress && animations)
            SetTimer(window, progress_timer, 16, nullptr);
        else
            KillTimer(window, progress_timer);
        if (!visible) {
            KillTimer(window, animation_timer);
            page_spring.snap(0);
            nav_spring.snap(double(current) * 44.);
            window_spring.snap(0);
            log_results_spring.snap(0);
        }
    }
    void navigate(PageId id, bool animate = true) {
        if (settings.mini && id == Logs)
            id = Home;
        if (id != Account && password_view) {
            clear_password_fields(); password_view = false; account_editor = false; password_confirming = false;
        }
        if (current == id && pages[id].window) {
            update_page(id);
            layout();
            request_visible_packages();
            return;
        }
        const auto previous = current;
        popup.close();
        account_pointer.cancel();
        if (pages[current].window)
            ShowWindow(pages[current].window, SW_HIDE);
        current = id;
        create_page(id);
        update_page(id);
        for (int nav = NavHome; nav <= NavLogs; ++nav)
            InvalidateRect(chrome_ctrl(nav), nullptr, FALSE);
        if (animate && animations) {
            if (!page_spring.active())
                page_spring.enter(previous < id ? 16. : -16.);
            nav_spring.move_to(double(id) * 44.);
            start_animation();
        } else {
            page_spring.snap(0);
            nav_spring.snap(double(id) * 44.);
        }
        if (settings.mini)
            resize_mode(false);
        ShowWindow(pages[id].window, SW_SHOW);
        layout();
        timers();
        request_visible_packages();
        if (id == Logs)
            request_logs();
        if (id == Account)
            SetFocus(ctrl(Account, account_service && !settings.mini ? AccountBack : settings.mini || account_editor
                                       ? (form_account_id.empty() ? UserInput : PasswordInput)
                                       : AccountList));
        else if (id == Preferences && settings.mini)
            SetFocus(ctrl(Preferences, ExitMini));
    }
    void resize_mode(bool switch_mode) {
        if (!window)
            return;
        if (switch_mode && settings.mini) {
            GetWindowRect(window, &full_bounds);
            full_bounds_saved = true;
        }
        const auto previous_style = static_cast<DWORD>(GetWindowLongPtrW(window, GWL_STYLE));
        DWORD style = WS_POPUP | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN |
                      (settings.mini ? 0 : (WS_THICKFRAME | WS_MAXIMIZEBOX)) |
                      (previous_style & (WS_VISIBLE | WS_DISABLED));
        SetWindowLongPtrW(window, GWL_STYLE, style);
        const bool login_link = !portal_ticket.empty() ||
                                (credentials && !connected_or_busy(status) && status != Status::Stopping);
        const int width = settings.mini ? 360 : 960;
        const int height = settings.mini ? (current == Account ? 392
                                            : current == Preferences
                                                ? 174
                                                : 226 + (message.empty() ? 0 : 34) + (login_link ? 38 : 0))
                                         : 650;
        RECT outer{0, 0, px(width), px(height)};
        int x = 0, y = 0;
        RECT before{};
        GetWindowRect(window, &before);
        if (settings.mini) {
            MONITORINFO monitor{sizeof(monitor)};
            GetMonitorInfoW(MonitorFromWindow(window, MONITOR_DEFAULTTOPRIMARY), &monitor);
            x = monitor.rcWork.left + (monitor.rcWork.right - monitor.rcWork.left - outer.right) / 2;
            y = monitor.rcWork.top + (monitor.rcWork.bottom - monitor.rcWork.top - outer.bottom) / 2;
        } else if (switch_mode && full_bounds_saved) {
            x = full_bounds.left;
            y = full_bounds.top;
        } else if (!switch_mode && before.left != CW_USEDEFAULT && before.right > before.left &&
                   IsWindowVisible(window)) {
            x = before.left;
            y = before.top;
        } else {
            MONITORINFO monitor{sizeof(monitor)};
            GetMonitorInfoW(MonitorFromWindow(window, MONITOR_DEFAULTTOPRIMARY), &monitor);
            x = monitor.rcWork.left +
                (monitor.rcWork.right - monitor.rcWork.left - (outer.right - outer.left)) / 2;
            y = monitor.rcWork.top +
                (monitor.rcWork.bottom - monitor.rcWork.top - (outer.bottom - outer.top)) / 2;
        }
        SetWindowPos(window, nullptr, x, y, outer.right - outer.left, outer.bottom - outer.top,
                     SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        window_destination = {x, y};
    }
    void show(PageId id = Home) {
        quiet = false;
        const bool hidden = !IsWindowVisible(window);
        navigate(id, !hidden);
        if (hidden)
            resize_mode(false);
        ShowWindow(window, IsIconic(window) ? SW_RESTORE : SW_SHOW);
        request_visible_packages();
        SetForegroundWindow(window);
        if (hidden && animations) {
            RECT rect{};
            GetWindowRect(window, &rect);
            window_destination = {rect.left, rect.top};
            window_spring.enter(9.);
            SetWindowPos(window, nullptr, rect.left, rect.top + px(9), 0, 0,
                         SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
            start_animation();
        }
        timers();
    }
    void hide() {
        popup.close();
        account_pointer.cancel();
        ShowWindow(window, SW_HIDE);
        timers();
    }
    void draw_item(const DRAWITEMSTRUCT &item);
    void draw_account_strip(int index, visual::Rect bar, bool selected, bool focused, bool floating = false);
    void paint_account_list(HDC dc);
    void paint_control_background(HWND child);
    void draw_toggle(HWND handle, HDC dc);
    void paint_root();
    void paint_page(Page &page);
    HBRUSH control_color(HDC dc, HWND child);
    void update_tray(bool add = false) {
        NOTIFYICONDATAW n{sizeof(n)};
        n.hWnd = window;
        n.uID = 1;
        n.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        n.uCallbackMessage = tray_message;
        n.hIcon = status == Status::Online                                       ? green
                  : status == Status::Connecting || status == Status::Recovering ? amber
                                                                                 : gray;
        const auto tooltip = L"SCAU Link · " + status_text(status, credentials);
        wcsncpy_s(n.szTip, tooltip.c_str(), _TRUNCATE);
        if (add || !tray_added) {
            tray_added = Shell_NotifyIconW(NIM_ADD, &n) != FALSE;
            n.uVersion = NOTIFYICON_VERSION_4;
            if (tray_added)
                Shell_NotifyIconW(NIM_SETVERSION, &n);
        } else
            Shell_NotifyIconW(NIM_MODIFY, &n);
    }
    void notify(const wchar_t *value) {
        if (quiet || options.demo)
            return;
        NOTIFYICONDATAW n{sizeof(n)};
        n.hWnd = window;
        n.uID = 1;
        n.uFlags = NIF_INFO;
        n.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
        wcscpy_s(n.szInfoTitle, L"SCAU Link");
        wcsncpy_s(n.szInfo, value, _TRUNCATE);
        Shell_NotifyIconW(NIM_MODIFY, &n);
    }
    void tray_menu(POINT point) {
        const bool active = connected_or_busy(status) || status == Status::Stopping;
        SetForegroundWindow(window);
        popup.show(
            window, point,
            {{Action,
              active        ? L"断开连接"
              : credentials ? L"连接"
                            : L"登录",
              active ? visual::Icon::Logout : visual::Icon::ArrowRight, status != Status::Stopping},
             {NavHome, settings.mini ? L"打开小窗" : L"打开主窗口", visual::Icon::Panel},
             {NavPreferences, L"设置", visual::Icon::Settings},
             {0, L""},
             {999, L"退出", visual::Icon::Power}},
            [this](int chosen) {
                if (chosen == 999)
                    exit();
                else if (chosen == NavHome)
                    show(Home);
                else if (chosen == NavPreferences)
                    show(Preferences);
                else if (chosen == Action) {
                    quiet = false;
                    command(Action);
                }
            },
            dpi, animations, L"SCAU Link 菜单");
    }
    void refresh_visible() {
        if (settings.mini && initialized && IsWindowVisible(window)) {
            RECT bounds{};
            GetWindowRect(window, &bounds);
            const bool login_link = !portal_ticket.empty() ||
                                    (credentials && !connected_or_busy(status) && status != Status::Stopping);
            const int height = current == Account ? 392
                               : current == Preferences
                                   ? 174
                                   : 226 + (message.empty() ? 0 : 34) + (login_link ? 38 : 0);
            if (bounds.bottom - bounds.top != px(height))
                resize_mode(false);
        }
        update_page(Home);
        update_page(Account);
        update_page(Preferences);
        layout();
        timers();
        update_tray();
    }
    void received(std::unique_ptr<Event> e) {
        if (e->kind == EventKind::PortalDetected) {
            if (e->success) {
                status = Status::Waiting; portal_ticket = e->portal_ticket; portal_approving = false;
                message = L"确认学校认证页面\n" + utf8_to_wide(e->portal_origin);
                if (!e->username.empty()) active_username = e->username;
                if (!e->account_id.empty()) active_account_id = e->account_id;
            } else if (portal_ticket == e->portal_ticket) { portal_approving = false; message = e->message; }
            refresh_visible(); return;
        }
        if (e->kind == EventKind::PasswordChanged) {
            account_catalog = e->accounts; credentials = e->credentials; username = e->username;
            if (e->password_request == password_request && e->account_id == password_account_id) {
                password_busy = false; password_confirming = false;
                password_submitted = password_submitted || e->password_change.request_sent;
                if (password_view) clear_password_fields();
                password_message = e->message;
                if (e->success && e->account_id == active_account_id && connected_or_busy(status))
                    password_message += L"，请重新连接";
                password_official = e->password_change.outcome == PasswordChangeOutcome::Unknown ||
                                    e->password_change.error == PasswordChangeError::UnsupportedCharacters ||
                                    e->password_change.error == PasswordChangeError::PasswordLength ||
                                    e->password_change.error == PasswordChangeError::TooLong;
                if (!password_view) notify(e->success ? L"校园网密码已修改" : e->message.c_str());
            }
            sync_account_list(); refresh_visible(); return;
        }
        if (e->kind == EventKind::Campus) {
            // A user-confirmed pause must also stop this client's recovery loop,
            // including when the user navigated away while the POST was pending.
            if (e->campus_change && e->campus_action == CampusAction::Pause &&
                (e->campus_outcome == CampusOutcome::Success ||
                 (e->campus_request_sent && e->campus_outcome == CampusOutcome::Unknown)) &&
                e->account_id == active_account_id && connected_or_busy(status)) {
                backend->disconnect();
                status = Status::Stopping;
            }
            const auto* account = account_catalog.find(e->account_id);
            if (account && account->secret_id == e->package_secret && e->campus.online_devices) {
                auto& cached = packages[e->account_id];
                if (cached.first != e->package_secret) cached = {e->package_secret, {}};
                cached.second.online_devices = e->campus.online_devices;
                update_page(Home);
                if (auto list = ctrl(Account, AccountList)) InvalidateRect(list, nullptr, FALSE);
            }
            if (account_service && e->campus_request == campus_request && e->account_id == campus_account_id &&
                account && account->secret_id == e->package_secret) {
                campus_busy = false; campus_confirming = false;
                campus_view = e->campus; campus_ticket = e->campus_ticket;
                campus_message = e->campus_outcome == CampusOutcome::Success
                    ? (e->campus_action == CampusAction::Pause ? L"已暂停" : L"已恢复")
                    : e->campus_outcome == CampusOutcome::Unknown ? L"结果未确认，请刷新"
                    : e->campus_outcome == CampusOutcome::Rejected ? L"学校未接受此操作"
                    : e->campus_outcome == CampusOutcome::Expired ? L"状态已变化，请刷新"
                    : campus_error_text(campus_view.error);
                if (campus_message.empty() && campus_ticket.empty())
                    campus_message = campus_view.error == CampusError::None &&
                        !campus_view.can_pause && !campus_view.can_resume ? L"当前账号不支持此操作" : L"请刷新状态";
                account_transition(6);
            }
            refresh_visible();
            return;
        }
        if (e->kind == EventKind::Package) {
            const auto* account = account_catalog.find(e->account_id);
            if (!account || account->secret_id != e->package_secret) return;
            auto& cached = packages[e->account_id];
            if (e->package.state == PackageState::Loading && cached.first == e->package_secret)
                cached.second.state = PackageState::Loading;
            else cached = {e->package_secret, std::move(e->package)};
            update_page(Home);
            if (current == Home && pages[Home].window) {
                layout();
                InvalidateRect(pages[Home].window, nullptr, FALSE);
            }
            if (auto list = ctrl(Account, AccountList)) InvalidateRect(list, nullptr, FALSE);
            return;
        }
        if (e->kind == EventKind::ModeSelected) {
            active_mode = e->connection_mode;
            adapter = active_mode == ConnectionMode::Wired ? L"以太网" : L"WLAN";
        } else if (e->kind == EventKind::Initialized) {
            initialized = true;
            settings = e->settings;
            active_mode = settings.mode;
            credentials = e->credentials;
            username = e->username;
            active_username = username;
            account_catalog = e->accounts;
            form_account_id = first_account_id();
            active_account_id = e->account_id;
            package_account_id = e->account_id;
            if (e->network_only) {active_account_id.clear();active_username=L"账号未确认";}
            adapter = e->adapter.empty() ? L"以太网" : e->adapter;
            status = e->status;
            message = e->message;
            const bool silent = force_silent || settings.silent;
            quiet = silent;
            resize_mode(false);
            if (!silent)
                show(Home);
            update_tray();
            if (status == Status::Online)
                online_since = GetTickCount64();
            if ((!options.demo && startup_policy(silent, credentials).auto_login) || options.demo_failure ||
                options.demo_failover || options.demo_network_only)
                backend->connect(options.startup);
        } else if (e->kind == EventKind::State) {
            portal_ticket.clear(); portal_approving = false;
            const auto before = status;
            status = e->status;
            message = e->message;
            if (!e->username.empty())
                active_username = e->username;
            else if (status == Status::Error)
                active_username.clear();
            if (!e->account_id.empty()) {
                active_account_id = e->account_id;
                package_account_id = e->account_id;
            }
            if(e->network_only) {active_account_id.clear();active_username=L"账号未确认";}
            if (status == Status::Online) {
                if (before != Status::Online) {
                    online_since = GetTickCount64();
                    notify(L"已连接");
                }
            } else if (status == Status::Error && before != Status::Error)
                notify(message.empty() ? L"登录失败" : message.c_str());
            else if (status == Status::Recovering && before == Status::Online)
                notify(L"正在重连");
            else if (status == Status::Offline && (before == Status::Online || before == Status::Stopping) &&
                     !exiting)
                notify(L"已断开连接");
            if (status == Status::Error) {
                pending_credential = false;
                pending_settings = false;
            }
        } else if (e->kind == EventKind::AccountsChanged) {
            pending_credential = false;
            account_catalog = e->accounts;
            credentials = e->credentials;
            username = e->username;
            if (account_service) {
                const auto* service_account = account_catalog.find(campus_account_id);
                if (!service_account) close_campus();
                else if (service_account->secret_id != campus_secret) {
                    campus_ticket.clear(); campus_secret = service_account->secret_id;
                    campus_busy = campus_confirming = false; ++campus_request;
                    campus_view = {}; campus_message = L"账号已更新，请刷新";
                }
            }
            if (e->success) {
                if (e->refresh_form)
                    edit_account(e->account_id);
                else if (!form_account_id.empty() && !account_catalog.find(form_account_id))
                    edit_account(first_account_id());
                if (login_after_save) {
                    login_after_save = false;
                    navigate(Home);
                } else if (e->refresh_form && account_editor && !settings.mini)
                    close_account_editor();
            } else
                login_after_save = false;
            text(Account, FormMessage, e->message);
            sync_account_list();
        } else if (e->kind == EventKind::SettingsSaved) {
            pending_settings = false;
            if (e->success) {
                const bool changed = settings.mini != e->settings.mini;
                const bool mode_changed = settings.mode != e->settings.mode;
                settings = e->settings;
                if (mode_changed) {
                    adapter = settings.mode != ConnectionMode::Wired ? L"WLAN" : L"以太网";
                    message.clear();
                    if (status == Status::Error) status = Status::Offline;
                }
                if (changed) {
                    resize_mode(true);
                    navigate(settings.mini ? Home : Preferences);
                } else
                    text(Preferences, SettingsMessage, L"已保存");
            } else
                text(Preferences, SettingsMessage, e->message);
        } else if (e->kind == EventKind::Logs) {
            if (e->log_request != log_request)
                return;
            logs_loading = false;
            log_error = e->success ? L"" : e->message;
            log_result = std::move(e->logs);
            auto list = ctrl(Logs, LogList);
            SendMessageW(list, WM_SETREDRAW, FALSE, 0);
            SendMessageW(list, LB_RESETCONTENT, 0, 0);
            for (const auto &row : log_result.entries) {
                const auto accessible = row.time_label + L"  " + row.title + L" · " + log_level_label(row.level);
                SendMessageW(list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(accessible.c_str()));
            }
            SendMessageW(list, WM_SETREDRAW, TRUE, 0);
            InvalidateRect(list, nullptr, FALSE);
            update_log_controls();
            log_scrollbar.sync(true);
            if (animations && current == Logs && IsWindowVisible(window) && !log_result.entries.empty()) {
                log_results_spring.enter(6);
                start_animation();
            }
        } else if (e->kind == EventKind::ConnectionReady) {
            if (e->success)
                adapter = e->adapter;
        }
        refresh_visible();
        request_visible_packages();
        if(update_waiting_disconnect)update_tick();
        if (exiting && !backend->running())
            DestroyWindow(window);
    }
    void command(int id) {
        if(update_installing() && id!=WindowMinimize && id!=WindowClose)return;
        if (id >= NavHome && id <= NavLogs) {
            if (id == NavAccount && !settings.mini && account_editor)
                close_account_editor();
            if (id == NavAccount && !settings.mini && account_service)
                close_campus();
            navigate(PageId(id - NavHome));
            return;
        }
        switch (id) {
        case CheckUpdate:
            update_clicked();
            break;
        case ChangePasswordMenu:
            open_password_view(form_account_id);
            break;
        case SubmitPasswordChange:
            submit_password_change();
            break;
        case PortalPasswordLink:
            ShellExecuteW(window,L"open",L"https://portal.scau.edu.cn/",nullptr,nullptr,SW_SHOWNORMAL);
            break;
        case OfficialPasswordLink:
            ShellExecuteW(window,L"open",password_change_official_url.data(),nullptr,nullptr,SW_SHOWNORMAL);
            break;
        case PortalAccept:
            if (!portal_ticket.empty() && !portal_approving) {
                portal_approving = true; backend->approve_portal(portal_ticket); refresh_visible();
            }
            break;
        case ConnectionModePicker:
            show_connection_modes();
            break;
        case WindowMinimize:
            hide();
            break;
        case WindowClose:
            hide();
            break;
        case WindowMaximize:
            ShowWindow(window, IsZoomed(window) ? SW_RESTORE : SW_MAXIMIZE);
            break;
        case MiniSettings:
            navigate(Preferences);
            break;
        case MiniBack:
            navigate(Home);
            break;
        case Action:
            if (!initialized || status == Status::Stopping)
                return;
            if (settings.mini && !portal_ticket.empty()) { command(PortalAccept); break; }
            if (connected_or_busy(status)) {
                backend->disconnect();
                status = Status::Stopping;
                refresh_visible();
            } else if (!credentials) {
                open_account_editor({});
            } else {
                backend->connect();
                status = Status::Connecting;
                message.clear();
                refresh_visible();
            }
            break;
        case Login:
            if (!portal_ticket.empty()) { backend->disconnect(); break; }
            if (settings.mini)
                open_account_editor(first_account_id());
            else {
                account_editor = false;
                account_service = false;
                show(Account);
            }
            break;
        case AddAccount:
            open_account_editor({});
            break;
        case AccountBack:
            if (!pending_credential) {
                if (account_service) close_campus(); else close_account_editor();
            }
            break;
        case CampusAccount:
            open_campus(form_account_id);
            break;
        case CampusRefresh:
            query_campus();
            break;
        case CampusCancel:
            if (campus_busy) break;
            campus_confirming = false;
            update_page(Account); account_transition(-6);
            SetFocus(ctrl(Account, CampusActionButton));
            break;
        case CampusActionButton:
            if (!account_service || !campus_permitted()) break;
            if (!campus_confirming) {
                campus_confirming = true;
                campus_message.clear();
                update_page(Account); account_transition(6);
                SetFocus(ctrl(Account, CampusCancel)); // A new Enter keypress cannot confirm by accident.
            } else {
                campus_busy = true; campus_message = L"正在提交";
                auto ticket = std::move(campus_ticket); campus_ticket.clear();
                backend->change_campus(campus_account_id, std::move(ticket),
                    campus_view.state == CampusState::Paused ? CampusAction::Resume : CampusAction::Pause,
                    ++campus_request);
                update_page(Account); layout(); timers();
            }
            break;
        case ManageAccount:
            open_account_editor(form_account_id);
            break;
        case PinAccount:
            if (!pending_credential && !form_account_id.empty()) {
                pending_credential = true;
                text(Account, FormMessage, L"");
                backend->pin_account(form_account_id);
                update_page(Account);
            }
            break;
        case DeleteAccount:
            if (!pending_credential && !form_account_id.empty() &&
                !(connected_or_busy(status) && form_account_id == active_account_id) &&
                MessageBoxW(window, L"删除这个已保存的账号？", L"删除账号",
                            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES) {
                pending_credential = true;
                text(Account, FormMessage, L"");
                backend->remove_account(form_account_id);
                update_page(Account);
            }
            break;
        case Details:
            show_details = !show_details;
            refresh_visible();
            break;
        case PasswordEye: {
            auto input = ctrl(Account, PasswordInput);
            const bool visible = SendMessageW(input, EM_GETPASSWORDCHAR, 0, 0) != 0;
            SendMessageW(input, EM_SETPASSWORDCHAR, visible ? 0 : L'●', 0);
            text(Account, PasswordEye, visible ? L"隐藏" : L"显示");
            InvalidateRect(input, nullptr, TRUE);
            break;
        }
        case SaveCredential: {
            if (pending_credential)
                return;
            auto value = std::make_shared<Credential>();
            std::array<wchar_t, 257> user{}, password{};
            GetWindowTextW(ctrl(Account, UserInput), user.data(), int(user.size()));
            GetWindowTextW(ctrl(Account, PasswordInput), password.data(), int(password.size()));
            value->username = user.data();
            value->password = password.data();
            SecureZeroMemory(password.data(), sizeof(password));
            const auto *existing = account_catalog.find(form_account_id);
            if (value->username.empty() ||
                ((!existing || existing->username != value->username) && value->password.empty())) {
                text(Account, FormMessage, L"请输入账号和密码");
                SetFocus(ctrl(Account, value->username.empty() ? UserInput : PasswordInput));
                break;
            }
            pending_credential = true;
            login_after_save = connect_after_save();
            text(Account, FormMessage, L"");
            backend->save_account(form_account_id, std::move(value), login_after_save);
            update_page(Account);
            break;
        }
        case MiniToggle:
        case AutoStartToggle:
        case SilentToggle:
        case ExitMini: {
            if (pending_settings)
                return;
            Settings next = settings;
            if (id == MiniToggle)
                next.mini = SendMessageW(ctrl(Preferences, MiniToggle), BM_GETCHECK, 0, 0) == BST_CHECKED;
            else if (id == AutoStartToggle)
                next.auto_start =
                    SendMessageW(ctrl(Preferences, AutoStartToggle), BM_GETCHECK, 0, 0) == BST_CHECKED;
            else if (id == SilentToggle)
                next.silent = SendMessageW(ctrl(Preferences, SilentToggle), BM_GETCHECK, 0, 0) == BST_CHECKED;
            else
                next.mini = false;
            pending_settings = true;
            text(Preferences, SettingsMessage, L"");
            backend->save_preferences(next);
            for (int control : {MiniToggle, AutoStartToggle, SilentToggle, ExitMini})
                EnableWindow(ctrl(Preferences, control), FALSE);
            break;
        }
        case RefreshLogs:
            request_logs();
            break;
        case StartupMode1:
        case StartupMode2:
        case StartupMode3:
            show_startup_modes(id);
            break;
        case LogStateFilter:
        case LogTimeFilter:
        case LogSort:
            show_log_choices(id);
            break;
        case ClearLogSearch:
            SetWindowTextW(ctrl(Logs, LogSearch), L"");
            SetFocus(ctrl(Logs, LogSearch));
            break;
        case ResetLogFilters:
            log_query = {};
            SetWindowTextW(ctrl(Logs, LogSearch), L"");
            request_logs();
            break;
        }
    }
    void exit() {
        if (exiting)
            return;
        exiting = true;
        backend->disconnect();
        hide();
        if (!backend->running())
            DestroyWindow(window);
        else
            SetTimer(window, exit_timer, 50, nullptr);
    }
    int run() {
        for (int i = 0; i < PageCount; ++i) {
            pages[i].app = this;
            pages[i].id = PageId(i);
        }
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS};
        InitCommonControlsEx(&controls);
        WNDCLASSEXW wc{sizeof(wc)};
        wc.hInstance = instance;
        wc.lpfnWndProc = root_proc;
        wc.lpszClassName = root_class;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        RegisterClassExW(&wc);
        wc.lpfnWndProc = page_proc;
        wc.lpszClassName = page_class;
        wc.style = 0;
        RegisterClassExW(&wc);
        window = CreateWindowExW(
            WS_EX_APPWINDOW, root_class, options.demo ? L"SCAU Link · 演示" : L"SCAU Link",
            WS_POPUP | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_CLIPCHILDREN,
            CW_USEDEFAULT, CW_USEDEFAULT, 960, 650, nullptr, nullptr, instance, this);
        if (!window)
            return 1;
        dpi = GetDpiForWindow(window);
        remake_fonts();
        motion_preference();
        green = static_cast<HICON>(
            LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR));
        gray = static_cast<HICON>(
            LoadImageW(instance, MAKEINTRESOURCEW(2), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR));
        amber = static_cast<HICON>(
            LoadImageW(instance, MAKEINTRESOURCEW(3), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR));
        SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(green));
        SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(green));
        make_control(window, chrome, L"STATIC", L"SCAU Link", Brand, SS_LEFT | SS_CENTERIMAGE, Body);
        make_control(window, chrome, L"BUTTON", L"最小化", WindowMinimize, WS_TABSTOP | BS_OWNERDRAW);
        make_control(window, chrome, L"BUTTON", L"最大化", WindowMaximize, WS_TABSTOP | BS_OWNERDRAW);
        make_control(window, chrome, L"BUTTON", L"关闭", WindowClose, WS_TABSTOP | BS_OWNERDRAW);
        const int corners = 2;
        const COLORREF frame = RGB(195, 209, 194);
        DwmSetWindowAttribute(window, static_cast<DWMWINDOWATTRIBUTE>(33), &corners, sizeof(corners));
        DwmSetWindowAttribute(window, static_cast<DWMWINDOWATTRIBUTE>(34), &frame, sizeof(frame));
        MARGINS margins{1, 1, 1, 1};
        DwmExtendFrameIntoClientArea(window, &margins);
        const wchar_t *labels[]{L"连接", L"账号", L"设置", L"记录"};
        for (int i = 0; i < PageCount; ++i)
            make_control(window, chrome, L"BUTTON", labels[i], NavHome + i, WS_TABSTOP | BS_OWNERDRAW);
        make_control(window, chrome, L"BUTTON", L"返回", MiniBack, WS_TABSTOP | BS_OWNERDRAW);
        make_control(window, chrome, L"BUTTON", L"设置", MiniSettings, WS_TABSTOP | BS_OWNERDRAW);
        taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
        update_tray(true);
        backend = std::make_unique<Backend>(window, options);
        backend->initialize();
        if(options.demo && !demo_update_live) {
            if(demo_update_ready)update_snapshot={updates::Phase::Ready,L"0.14.0",100,0};
        } else {
            try {
                updates::Options update_options;
                update_options.directory=data_directory()/(demo_update_live?L"update-demo":L"updates");
                update_options.installation=executable_path().parent_path();
                update_options.current=updates::current_version;
                update_options.allow_preview=updates::preview_channel;
                update_options.public_key=updates::signing_public_key;
                update_options.restart_silent=force_silent;
                update_options.changed=[target=window]{PostMessageW(target,updates::changed_message,0,0);};
                updater=std::make_unique<updates::Manager>(std::move(update_options));
                SetTimer(window,update_timer,10000,nullptr);
            }catch(...){update_snapshot.phase=updates::Phase::Failed;update_snapshot.error=ERROR_ACCESS_DENIED;}
        }
        MSG msg{};
        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
            if (popup.filter(msg))
                continue;
            if (msg.message == WM_KEYDOWN && current == Logs) {
                if (msg.wParam == 'F' && (GetKeyState(VK_CONTROL) & 0x8000)) {
                    SetFocus(ctrl(Logs, LogSearch));
                    SendMessageW(ctrl(Logs, LogSearch), EM_SETSEL, 0, -1);
                    continue;
                }
                if (msg.hwnd == ctrl(Logs, LogSearch) && msg.wParam == VK_RETURN) {
                    request_logs();
                    continue;
                }
                if (msg.hwnd == ctrl(Logs, LogSearch) && msg.wParam == VK_ESCAPE) {
                    if (!log_query.search.empty())
                        SetWindowTextW(ctrl(Logs, LogSearch), L"");
                    else
                        SetFocus(ctrl(Logs, LogList));
                    continue;
                }
            }
            if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
                if (account_pointer.active()) {
                    account_pointer.cancel();
                    sync_account_list();
                } else if (current == Account && account_service && !settings.mini) {
                    if (campus_confirming && !campus_busy) command(CampusCancel);
                    else close_campus();
                } else if (current == Account && account_editor && !settings.mini && !pending_credential && !password_busy)
                    close_account_editor();
                else if (current != Home)
                    navigate(Home);
                else
                    hide();
                continue;
            }
            if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && current == Account &&
                account_service && (msg.hwnd == ctrl(Account, CampusActionButton) ||
                msg.hwnd == ctrl(Account, CampusCancel) || msg.hwnd == ctrl(Account, CampusRefresh))) {
                if (!(msg.lParam & (1L << 30))) command(GetDlgCtrlID(msg.hwnd));
                continue;
            }
            if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && current == Account &&
                password_view && (msg.hwnd == ctrl(Account,OldPasswordInput) || msg.hwnd == ctrl(Account,NewPasswordInput) ||
                                  msg.hwnd == ctrl(Account,ConfirmPasswordInput) || msg.hwnd == ctrl(Account,SubmitPasswordChange))) {
                if (!(msg.lParam & (LPARAM(1) << 30))) command(SubmitPasswordChange);
                continue;
            }
            if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && current == Account &&
                (msg.hwnd == ctrl(Account, UserInput) || msg.hwnd == ctrl(Account, PasswordInput))) {
                command(SaveCredential);
                continue;
            }
            if (!IsDialogMessageW(window, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        updater.reset();
        backend.reset();
        while (PeekMessageW(&msg, nullptr, backend_message, backend_message, PM_REMOVE))
            delete reinterpret_cast<Event *>(msg.lParam);
        for (auto f : fonts)
            if (f)
                DeleteObject(f);
        if (green)
            DestroyIcon(green);
        if (gray)
            DestroyIcon(gray);
        if (amber)
            DestroyIcon(amber);
        return int(msg.wParam);
    }
};

std::pair<COLORREF, COLORREF> hero_colors(Status status) {
    if (status == Status::Online)
        return {RGB(240, 247, 236), RGB(231, 240, 227)};
    if (status == Status::Error)
        return {RGB(252, 245, 242), RGB(248, 236, 231)};
    if (status == Status::Recovering || status == Status::Waiting)
        return {RGB(252, 248, 238), RGB(247, 241, 226)};
    return {RGB(247, 249, 244), RGB(241, 245, 238)};
}
COLORREF state_color(Status status) {
    if (status == Status::Online)
        return visual::Deep;
    if (status == Status::Error)
        return visual::Error;
    if (status == Status::Recovering || status == Status::Waiting)
        return visual::Warn;
    return RGB(78, 97, 79);
}
visual::Icon state_glyph(Status status, ConnectionMode mode) {
    if (status == Status::Error)
        return visual::Icon::Alert;
    if (status == Status::Recovering || status == Status::Connecting)
        return visual::Icon::Refresh;
    if (mode != ConnectionMode::Wired)
        return visual::Icon::Wifi;
    if (status == Status::Waiting)
        return visual::Icon::Ethernet;
    return visual::Icon::Network;
}
void App::paint_control_background(HWND child) {
    RECT bounds{};
    GetClientRect(child, &bounds);
    const visual::Rect box{0, 0, float(bounds.right) * 96 / dpi, float(bounds.bottom) * 96 / dpi};
    HWND parent = GetParent(child);
    const int id = GetDlgCtrlID(child);
    if (parent == window)
        renderer.fill(box, settings.mini ? paper : nav_bg);
    else if (parent == pages[Account].window && account_service &&
             (id == CampusStateValue || id == CampusDevices))
        renderer.fill(box, paper);
    else if (parent == pages[Account].window && !settings.mini && id != Heading && id != AccountBack &&
             id != CampusRefresh &&
             id != AddAccount && (id != FormMessage || account_editor))
        renderer.fill(box, visual::White);
    else if (parent == pages[Home].window && !settings.mini && (id == Duration || id == AdapterValue || id == HomeDevices))
        renderer.fill(box, visual::White);
    else if (parent == pages[Logs].window &&
             (id == ClearLogSearch || id == LogList || id == LogsMessage || id == Progress))
        renderer.fill(box, visual::White);
    else if (parent == pages[Home].window && !settings.mini && id != Heading) {
        RECT position{};
        GetWindowRect(child, &position);
        MapWindowPoints(HWND_DESKTOP, parent, reinterpret_cast<POINT *>(&position), 2);
        if (position.top >= px(76) && position.top < px(336)) {
            RECT page{};
            GetClientRect(parent, &page);
            auto [a, b] = hero_colors(status);
            renderer.gradient({-float(position.left) * 96 / dpi, 76 - float(position.top) * 96 / dpi,
                               float(page.right) * 96 / dpi, 260},
                              a, b, 10);
        }
    }
}
void App::draw_account_strip(int index, visual::Rect bar, bool selected, bool focused, bool floating) {
    using namespace visual;
    if (index < 0 || std::size_t(index) >= account_catalog.entries.size())
        return;
    const auto &entry = account_catalog.entries[std::size_t(index)];
    renderer.fill(bar, selected ? Soft : White, account_row_radius);
    renderer.outline(bar,
                     floating   ? RGB(138, 179, 151)
                     : selected ? RGB(200, 220, 200)
                                : Line,
                     account_row_radius, floating ? 1.3f : 1.f);
    renderer.icon(Icon::Grip, {bar.x + 14, bar.y + (bar.h - 16) / 2, 12, 16}, floating ? Pine : Subtle,
                  1.55f);
    renderer.fill({bar.x + 40, bar.y + (bar.h - 40) / 2, 40, 40}, selected ? RGB(220, 234, 218) : Paper, 11);
    renderer.icon(Icon::User, {bar.x + 51, bar.y + (bar.h - 18) / 2, 18, 18}, Pine, 1.65f);
    const auto& billing = package_for(entry.id);
    const float metrics = bar.x + bar.w - 334;
    renderer.text(entry.username, {bar.x + 96, bar.y + 13, std::max(60.f, metrics - bar.x - 112), 24}, Ink, BrandText);
    const float money_x = metrics, fee_x = metrics + 108, date_x = metrics + 210;
    SYSTEMTIME local{}; GetLocalTime(&local);
    const std::chrono::year_month_day today{std::chrono::year{int(local.wYear)},
        std::chrono::month{local.wMonth}, std::chrono::day{local.wDay}};
    const auto fee = package_fee(billing);
    const auto estimated = billing.next_charge ? std::optional<BillingDate>{} : estimate_next_charge(billing, today);
    const auto charge = billing.next_charge ? billing.next_charge : estimated;
    renderer.text(L"余额", {money_x, bar.y + 8, 94, 20}, Subtle, SmallText, DWRITE_TEXT_ALIGNMENT_TRAILING);
    renderer.text(package_fee_label(billing), {fee_x, bar.y + 8, 94, 20}, Subtle, SmallText, DWRITE_TEXT_ALIGNMENT_TRAILING);
    renderer.text(estimated ? L"预计下次扣费" : L"下次扣费", {date_x, bar.y + 8, 108, 20}, Subtle, SmallText, DWRITE_TEXT_ALIGNMENT_TRAILING);
    const auto unknown = billing.state == PackageState::Loading ? L"加载中" : L"未知";
    renderer.text(billing.balance ? money_text(billing.balance) : std::wstring(unknown),
                  {money_x, bar.y + 31, 94, 26}, billing.balance ? Ink : Muted, BrandText, DWRITE_TEXT_ALIGNMENT_TRAILING);
    renderer.text(fee ? money_text(fee) : std::wstring(unknown),
                  {fee_x, bar.y + 31, 94, 26}, fee ? Ink : Muted, BrandText, DWRITE_TEXT_ALIGNMENT_TRAILING);
    renderer.text(charge ? billing_date_text(charge) : std::wstring(unknown),
                  {date_x, bar.y + 28, 108, 22},
                  charge ? Ink : Muted, SmallText, DWRITE_TEXT_ALIGNMENT_TRAILING);
    renderer.text(billing_date_text(billing.next_charge, true), {date_x, bar.y + 46, 108, 18},
                  Subtle, SmallText, DWRITE_TEXT_ALIGNMENT_TRAILING);
    const bool active = entry.id == active_account_id && status == Status::Online;
    if (active) {
        const float badge = bar.x + 96;
        renderer.fill({badge, bar.y + 42, 72, 21}, RGB(231, 241, 230), 10.5f);
        renderer.dot(badge + 11, bar.y + 52.5f, 2.f, Pine);
        renderer.text(L"活跃中", {badge + 21, bar.y + 41, 47, 23}, Pine, SmallText);
    }
    const float devices_x = bar.x + (active ? 182 : 96);
    renderer.text(L"在线 " + device_count_text(billing.online_devices),
                  {devices_x, bar.y + 41, std::max(36.f, metrics - devices_x - 12), 23}, Muted, SmallText);
    if (focused)
        renderer.outline(bar.inset(2), RGB(127, 174, 147), account_row_radius - 2, 1.2f);
}
void App::paint_account_list(HDC dc) {
    using namespace visual;
    const auto list = ctrl(Account, AccountList);
    RECT client{};
    GetClientRect(list, &client);
    if (!renderer.begin(dc, client, dpi, paper))
        return;
    const float width = float(client.right) * 96 / dpi, height = float(client.bottom) * 96 / dpi;
    const int top = int(SendMessageW(list, LB_GETTOPINDEX, 0, 0));
    const int selected = int(SendMessageW(list, LB_GETCURSEL, 0, 0));
    const bool lifted = account_pointer.lifted();
    if (lifted && account_pointer.slot() >= 0) {
        const Rect hole{.5f, float((account_pointer.slot() - top) * account_row_height) + .5f, width - 1,
                        float(account_row_height - account_row_gap - 1)};
        renderer.fill(hole, RGB(242, 247, 241), account_row_radius);
        renderer.outline(hole, RGB(198, 218, 198), account_row_radius);
    }
    const bool focus = GetFocus() == list && !(SendMessageW(list, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS);
    for (int i = 0; i < int(account_catalog.entries.size()); ++i) {
        if (lifted && i == account_pointer.from())
            continue;
        const float y = float((i - top) * account_row_height + account_pointer.row_offset(i) * 96 / dpi);
        if (y >= height || y + account_row_height <= 0)
            continue;
        draw_account_strip(i, {.5f, y + .5f, width - 1, float(account_row_height - account_row_gap - 1)},
                           selected == i, focus && selected == i && !lifted);
    }
    renderer.end();
}
void App::paint_log_list(HDC dc, RECT bounds, double offset) {
    using namespace visual;
    if (!renderer.begin(dc, bounds, dpi, White))
        return;
    const auto list = ctrl(Logs, LogList);
    const float width = float(bounds.right) * 96 / dpi;
    const int row = std::max(1, int(SendMessageW(list, LB_GETITEMHEIGHT, 0, 0)));
    const float height = float(row) * 96 / dpi;
    const double painted_offset = std::round(offset);
    const int top = int(painted_offset / row);
    const int selected = int(SendMessageW(list, LB_GETCURSEL, 0, 0));
    const int end = std::min(int(log_result.entries.size()), int(std::ceil((painted_offset + bounds.bottom) / row)));
    for (int index = std::max(0, top); index < end; ++index) {
        const float y = float(index * row - painted_offset) * 96 / dpi;
        const auto &record = log_result.entries[std::size_t(index)];
        const COLORREF tint = record.level == LogLevel::Error ? Error
                              : record.level == LogLevel::Warning ? Warn
                              : record.level == LogLevel::Success ? Pine : Muted;
        const COLORREF soft = record.level == LogLevel::Error ? RGB(252, 240, 236)
                              : record.level == LogLevel::Warning ? RGB(250, 243, 228)
                              : record.level == LogLevel::Success ? Soft : RGB(244, 246, 242);
        if (selected == index)
            renderer.fill({1, y + 2, width - 16, height - 4}, Soft, 7);
        renderer.fill({8, y + 18, 30, 30}, soft, 10);
        renderer.icon(record.level == LogLevel::Success ? Icon::Shield
                      : record.level == LogLevel::Info ? Icon::File : Icon::Alert,
                      {15, y + 25, 16, 16}, tint, 1.65f);
        renderer.text(record.title, {50, y + 8, width - 156, 27}, Ink);
        renderer.text(record.time_label, {50, y + 34, width - 156, 22}, Subtle, SmallText);
        renderer.fill({width - 76, y + 23, 48, 22}, soft, 11);
        renderer.text(log_level_label(record.level), {width - 76, y + 23, 48, 22}, tint, SmallText,
                      DWRITE_TEXT_ALIGNMENT_CENTER);
        if (std::size_t(index) + 1 < log_result.entries.size())
            renderer.line(50, y + height - .5f, width - 28, y + height - .5f, Line);
    }
    renderer.end();
}
void App::draw_item(const DRAWITEMSTRUCT &item) {
    using namespace visual;
    if (item.CtlType == ODT_LISTBOX) {
        // Native notifications only invalidate; viewport painting owns the DC.
        InvalidateRect(item.hwndItem, nullptr, FALSE);
        return;
    }
    const float width = float(item.rcItem.right - item.rcItem.left) * 96 / dpi;
    const float height = float(item.rcItem.bottom - item.rcItem.top) * 96 / dpi;
    if (!renderer.begin(item.hDC, item.rcItem, dpi, paper))
        return;
    paint_control_background(item.hwndItem);
    const int id = int(item.CtlID);
    wchar_t value[256]{};
    GetWindowTextW(item.hwndItem, value, 256);
    if (item.CtlType == ODT_STATIC) {
        if (id == Progress) {
            const float segment = std::min(96.f, width * .28f);
            const double travel = animations ? (1 - std::cos(double(GetTickCount64() % 1800) / 1800. * 6.283185307)) / 2 : .5;
            renderer.fill({0, 0, width, height}, RGB(223, 236, 224), height / 2);
            renderer.fill({float(travel) * (width - segment), 0, segment, height}, Pine, height / 2);
        } else if (id == Brand) {
            if (settings.mini && current != Home)
                renderer.text(current == Preferences ? L"设置" : L"登录", {0, 0, width, height}, Ink,
                              BrandText);
            else {
                renderer.logo({0, (height - 20) / 2, 20, 20});
                renderer.text(L"SCAU Link", {26, 0, width - 26, height}, RGB(56, 76, 62), BrandText);
            }
            if (options.demo) {
                const float left = settings.mini && current != Home ? 44.f : 104.f;
                renderer.fill({left, (height - 18) / 2, 34, 18}, Soft, 4);
                renderer.text(L"演示", {left, (height - 18) / 2, 34, 18}, Pine, SmallText,
                              DWRITE_TEXT_ALIGNMENT_CENTER);
            }
        } else {
            auto *c = control(item.hwndItem);
            Type font = c ? type(c->font) : Text;
            COLORREF tint = Ink;
            if (id == StateText) {
                font = settings.mini ? HeadingText : StatusText;
                tint = state_color(status);
            } else if (id == AccountValue || id == UserLabel || id == PasswordLabel || id == LogsMessage ||
                       id == AccountsEmpty || id == LogCount)
                tint = Muted;
            else if (id == StateMessage || id == FormMessage || id == SettingsMessage)
                tint = id == StateMessage && !portal_ticket.empty() ? Muted :
                       std::wstring_view(value) == L"已保存" ||
                       (id == FormMessage && password_view && std::wstring_view(value).starts_with(L"校园网密码已修改")) ? Pine : Error;
            else if (id == HomeExpiry || id == PackageStatus) tint = Muted;
            else if (id == CampusStateValue) tint = campus_view.state == CampusState::Paused ? Warn : Pine;
            else if (id == CampusMessage)
                tint = campus_message == L"已暂停" || campus_message == L"已恢复" ? Pine : Muted;
            else if (id == CampusConfirmation) tint = campus_view.state == CampusState::Paused ? Pine : Warn;
            renderer.text(value, {0, 0, width, height}, tint, font,
                          id == LogsMessage || id == AccountsEmpty ? DWRITE_TEXT_ALIGNMENT_CENTER
                          : id == HomeBalance || id == HomeExpiry ? DWRITE_TEXT_ALIGNMENT_TRAILING
                                                                   : DWRITE_TEXT_ALIGNMENT_LEADING,
                          id == StateMessage || id == FormMessage || id == SettingsMessage ||
                          id == CampusMessage || id == CampusConfirmation);
        }
        renderer.end();
        return;
    }
    const bool disabled = (item.itemState & ODS_DISABLED) != 0, down = (item.itemState & ODS_SELECTED) != 0;
    auto *c = control(item.hwndItem);
    const double hot = c ? std::clamp(c->hover.value(), 0., 1.) : 0;
    const bool nav = id >= NavHome && id <= NavLogs, selected = nav && current == id - NavHome;
    const bool title = id == WindowClose || id == WindowMinimize || id == WindowMaximize ||
                       id == MiniSettings || id == MiniBack || id == AccountBack || id == ClearLogSearch;
    const bool eye = id == PasswordEye;
    const bool primary =
        id == SaveCredential || id == CampusActionButton || id == SubmitPasswordChange || id == PortalAccept ||
        (id == Action && settings.mini && !portal_ticket.empty()) ||
        (id == Action && !connected_or_busy(status) && status != Status::Stopping);
    Icon glyph = Icon::None;
    COLORREF tint = disabled ? Subtle : Ink;
    Rect button{.5f, .5f, width - 1, height - 1};
    if (nav) {
        renderer.fill(button, selected ? RGB(230, 238, 226) : mix(Sidebar, RGB(232, 239, 227), hot), 7);
        constexpr Icon nav_icons[]{Icon::Network, Icon::User, Icon::Settings, Icon::List};
        tint = selected ? Deep : mix(Muted, Deep, hot);
        renderer.icon(nav_icons[id - NavHome], {14, 11, 18, 18}, tint, 1.55f);
        renderer.text(value, {44, 0, width - 50, height}, tint, selected ? BrandText : Text);
    } else if (title || eye) {
        const bool closing = id == WindowClose;
        if (hot > .001 || down)
            renderer.fill(button,
                          closing
                              ? mix(Sidebar, RGB(218, 67, 61), hot)
                              : mix(id == ClearLogSearch ? White : settings.mini || eye || id == AccountBack ? paper : Sidebar, Soft, hot),
                          settings.mini || eye || id == ClearLogSearch ? 6.f : 0.f);
        tint = disabled ? Subtle : closing && hot > .5 ? White : mix(Muted, Deep, hot);
        glyph = id == WindowClose || id == ClearLogSearch ? Icon::Close
                : id == WindowMinimize                ? Icon::Minimize
                : id == WindowMaximize                ? Icon::Maximize
                : id == MiniSettings                  ? Icon::Settings
                : id == MiniBack || id == AccountBack ? Icon::ArrowLeft
                : std::wstring_view(value) == L"隐藏" ? Icon::EyeOff
                                                      : Icon::Eye;
        if (id == WindowMaximize && IsZoomed(window))
            glyph = Icon::Restore;
        if (id == WindowMinimize || id == WindowMaximize || id == WindowClose)
            renderer.caption_icon(glyph, {0, 0, width, height}, tint);
        else
            renderer.icon(glyph, {(width - 16) / 2, (height - 16) / 2, 16, 16}, tint, 1.65f);
    } else if (id == LogStateFilter || id == LogTimeFilter || id == LogSort || id == ConnectionModePicker ||
               id == StartupMode1 || id == StartupMode2 || id == StartupMode3) {
        const bool boot = id == StartupMode1 || id == StartupMode2 || id == StartupMode3;
        const bool active = boot ? !settings.startup_modes.empty() : id == ConnectionModePicker ? display_mode() != ConnectionMode::Wired
                            : id == LogStateFilter ? log_query.level != LogLevel::All
                            : id == LogTimeFilter ? log_query.range != LogRange::All
                                                  : log_query.order != LogOrder::Newest;
        const double expanded = c ? std::clamp(c->thumb.value(), 0., 1.) : 0.;
        renderer.fill(button, mix(active ? Soft : White, RGB(231, 241, 231), hot * .6), 8);
        renderer.outline(button, expanded > .1 ? RGB(124, 170, 140) : active ? RGB(199, 219, 201) : Line, 8);
        if (id == ConnectionModePicker)
            renderer.icon(display_mode() != ConnectionMode::Wired ? Icon::Wifi : Icon::Ethernet,
                          {12, (height - 16) / 2, 16, 16}, disabled ? Subtle : Pine, 1.55f);
        renderer.text(value, {id == ConnectionModePicker ? 36.f : 13.f, 0,
                             width - (id == ConnectionModePicker ? 66.f : 43.f), height}, disabled ? Subtle : active ? Deep : Ink);
        renderer.icon(Icon::ChevronDown, {width - 28, (height - 14) / 2, 14, 14},
                      active ? Pine : Muted, 1.7f, c ? float(c->thumb.value() * 180) : 0.f);
    } else if (id == ResetLogFilters) {
        renderer.fill(button, mix(paper, Soft, hot), 6);
        renderer.text(value, {0, 0, width, height}, mix(Muted, Pine, hot), SmallText,
                      DWRITE_TEXT_ALIGNMENT_CENTER);
    } else if (id == Details) {
        renderer.fill(button, mix(White, Soft, hot), 8);
        renderer.outline(button, Line, 8);
        renderer.text(value, {16, 0, width - 52, height}, mix(Muted, Deep, hot));
        renderer.icon(show_details ? Icon::ChevronDown : Icon::ChevronRight,
                      {width - 30, (height - 15) / 2, 15, 15}, Muted);
    } else if (id == Login || id == PortalPasswordLink || id == OfficialPasswordLink) {
        renderer.text(value, {0, 0, width-(id == Login ? 0.f : 20.f), height}, disabled ? Subtle : mix(Muted, Pine, hot), SmallText,
                      DWRITE_TEXT_ALIGNMENT_CENTER);
        if (id != Login) renderer.icon(Icon::ExternalLink,{width-17,(height-13)/2,13,13},disabled ? Subtle : Pine,1.55f);
    } else {
        const COLORREF background = primary ? (disabled ? RGB(157, 183, 168)
                                               : down   ? Deep
                                                        : mix(Pine, Deep, hot))
                                            : mix(White, Soft, hot);
        renderer.fill(button, background, 6);
        renderer.outline(button, primary ? background : mix(Border, RGB(171, 193, 176), hot), 6);
        tint = primary ? White : disabled ? Subtle : RGB(74, 95, 77);
        glyph = id == Action           ? (connected_or_busy(status) ? Icon::Logout : Icon::ArrowRight)
                : id == SaveCredential ? (connect_after_save() ? Icon::ArrowRight : Icon::Check)
                : id == AddAccount     ? Icon::Plus
                : id == ExitMini       ? Icon::Panel
                : id == RefreshLogs || id == CampusRefresh || id == CheckUpdate ? Icon::Refresh
                : id == CampusActionButton ? Icon::Power
                : id == SubmitPasswordChange ? Icon::Key
                : id == PortalAccept ? Icon::Check
                                       : Icon::None;
        const float total = renderer.measure(value, Text) + (glyph == Icon::None ? 0 : 23);
        const float start = (width - total) / 2;
        if (glyph != Icon::None)
            renderer.icon(glyph, {start, (height - 15) / 2, 15, 15}, tint, 1.65f);
        renderer.text(value, {start + (glyph == Icon::None ? 0 : 23), 0, total, height}, tint);
    }
    if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT))
        renderer.outline({2.5f, 2.5f, width - 5, height - 5},
                         primary ? RGB(194, 224, 204) : RGB(127, 174, 147), 5, 1.2f);
    renderer.end();
}
void App::draw_toggle(HWND handle, HDC dc) {
    using namespace visual;
    RECT bounds{};
    GetClientRect(handle, &bounds);
    const float width = float(bounds.right) * 96 / dpi, height = float(bounds.bottom) * 96 / dpi;
    if (!renderer.begin(dc, bounds, dpi, White))
        return;
    auto *c = control(handle);
    const bool checked = SendMessageW(handle, BM_GETCHECK, 0, 0) == BST_CHECKED;
    const float t = c ? float(c->thumb.value()) : checked ? 1.f : 0.f;
    const double hot = c ? c->hover.value() : 0;
    renderer.fill({0, 0, width, height}, mix(White, Paper, hot), 6);
    const int id = GetDlgCtrlID(handle);
    const Icon glyph = id == MiniToggle ? Icon::Panel : id == AutoStartToggle ? Icon::Power : Icon::Moon;
    renderer.icon(glyph, {12, (height - 19) / 2, 19, 19}, mix(Muted, Pine, hot), 1.55f);
    wchar_t value[128]{};
    GetWindowTextW(handle, value, 128);
    renderer.text(value, {48, 0, width - 116, height}, IsWindowEnabled(handle) ? Ink : Subtle);
    const float left = width - 53, top = (height - 20) / 2;
    renderer.fill({left, top, 36, 20}, mix(RGB(228, 233, 223), Pine, t), 10);
    renderer.outline({left + .5f, top + .5f, 35, 19}, mix(RGB(209, 219, 201), Pine, t), 9.5f);
    const float knob = left + 10 + 16 * std::clamp(t, -.08f, 1.08f);
    renderer.dot(knob, top + 10, 6.5f, White);
    if (GetFocus() == handle && !(SendMessageW(handle, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS))
        renderer.outline({2, 2, width - 4, height - 4}, RGB(127, 174, 147), 5, 1.2f);
    renderer.end();
}
void App::paint_root() {
    using namespace visual;
    PAINTSTRUCT ps{};
    BeginPaint(window, &ps);
    RECT bounds{};
    GetClientRect(window, &bounds);
    const float w = float(bounds.right) * 96 / dpi, h = float(bounds.bottom) * 96 / dpi;
    if (renderer.begin(ps.hdc, bounds, dpi, paper)) {
        if (settings.mini)
            renderer.line(1, 52, w - 1, 52, RGB(237, 240, 233));
        else {
            renderer.fill({0, 0, w, 44}, Sidebar);
            renderer.line(0, 44, w, 44, RGB(237, 240, 233));
            renderer.fill({0, 44, 184, h - 44}, Sidebar);
            renderer.line(184, 44, 184, h, RGB(235, 240, 232));
            renderer.text(L"SCAU Link", {24, 75, 145, 30}, Ink, HeadingText);
            const float y = 151 + float(nav_spring.value());
            renderer.fill({8, y, 3, 18}, Pine, 1.5f);
            renderer.line(24, h - 66, 160, h - 66, Line);
            renderer.dot(27, h - 39, 2.5f, status == Status::Online ? RGB(88, 144, 108) : Subtle);
            renderer.text(status_text(status, credentials), {36, h - 50, 94, 22}, Muted, SmallText);
            renderer.text(updates::current_version, {123, h - 50, 46, 22}, Subtle, SmallText);
        }
        if (!IsZoomed(window))
            renderer.outline({.5f, .5f, w - 1, h - 1}, RGB(203, 215, 200), settings.mini ? 10.f : 8.f);
        renderer.end();
    }
    EndPaint(window, &ps);
}
void App::paint_page(Page &p) {
    using namespace visual;
    PAINTSTRUCT ps{};
    BeginPaint(p.window, &ps);
    RECT bounds{};
    GetClientRect(p.window, &bounds);
    const float w = float(bounds.right) * 96 / dpi, h = float(bounds.bottom) * 96 / dpi;
    if (renderer.begin(ps.hdc, bounds, dpi, paper)) {
        if (p.id == Home) {
            const auto tint = state_color(status);
            if (settings.mini) {
                renderer.fill({0, 0, 48, 48},
                              status == Status::Online  ? RGB(232, 242, 235)
                              : status == Status::Error ? RGB(252, 240, 233)
                              : status == Status::Recovering || status == Status::Waiting
                                  ? RGB(250, 240, 221)
                                  : RGB(240, 243, 237),
                              13);
                renderer.outline({.5f, .5f, 47, 47}, status == Status::Online ? RGB(212, 229, 217) : Line,
                                 12.5f);
                renderer.icon(state_glyph(status, display_mode()), {11, 11, 26, 26}, tint, 1.55f);
            } else {
                const auto [a, b] = hero_colors(status);
                renderer.gradient({0, 76, w, 260}, a, b, 10);
                renderer.outline({.5f, 76.5f, w - 1, 259},
                                 status == Status::Error ? RGB(236, 217, 208) : RGB(221, 233, 217), 9.5f);
                renderer.dot(31, 104, 2.5f, status == Status::Online ? RGB(89, 145, 107) : tint);
                renderer.text(L"校园网认证", {40, 92, w - 100, 24}, RGB(122, 142, 117), SmallText);
                const float cx = w - 100, cy = 179;
                renderer.fill({cx - 62, cy - 62, 124, 124}, White, 62, .17f);
                renderer.fill({cx - 50, cy - 50, 100, 100}, White, 50, .3f);
                renderer.ring(cx, cy, 49.5f,
                              status == Status::Error ? RGB(229, 195, 184) : RGB(208, 226, 201));
                renderer.icon(state_glyph(status, display_mode()), {cx - 23, cy - 23, 46, 46},
                              status == Status::Error ? tint : mix(tint, RGB(119, 145, 101), .4), 1.3f);
                if (credentials)
                    renderer.icon(Icon::User, {28, 184, 14, 14}, RGB(139, 155, 132));
                if (show_details) {
                    const float detail_height = status == Status::Online &&
                        !package_status_text(package_for(home_package_account()).state).empty() ? 128.f : 98.f;
                    renderer.fill({0, 416, w, detail_height}, White, 8);
                    renderer.outline({.5f, 416.5f, w - 1, detail_height - 1}, Line, 7.5f);
                    renderer.line(w / 3, 434, w / 3, 496, Line);
                    renderer.line(2 * w / 3, 434, 2 * w / 3, 496, Line);
                    renderer.icon(Icon::Clock, {28, 434, 14, 14}, Muted);
                    renderer.text(L"在线时长", {50, 427, w / 3 - 78, 28}, Muted, SmallText);
                    renderer.icon(settings.mode != ConnectionMode::Wired ? Icon::Wifi : Icon::Ethernet, {w / 3 + 28, 434, 14, 14}, Muted);
                    renderer.text(L"认证网卡", {w / 3 + 50, 427, w / 3 - 78, 28}, Muted, SmallText);
                    renderer.icon(Icon::Monitor, {2 * w / 3 + 28, 434, 14, 14}, Muted);
                    renderer.text(L"在线设备", {2 * w / 3 + 50, 427, w / 3 - 78, 28}, Muted, SmallText);
                }
            }
        } else if (p.id == Account) {
            if (password_view) {
                const auto form = account_form(int(w));
                const float left = float(form.x) + 28, field = float(form.w) - 56;
                const Rect card{float(form.x),76,float(form.w),450};
                renderer.fill(card,White,9); renderer.outline(card.inset(.5f),Line,8.5f);
                for (auto item : {std::pair{OldPasswordInput,174.f},std::pair{NewPasswordInput,262.f},std::pair{ConfirmPasswordInput,350.f}}) {
                    const Rect well{left,item.second,field,44}; const bool focus = GetFocus() == ctrl(Account,item.first);
                    if (focus) renderer.outline({left-1.5f,item.second-1.5f,field+3,47},RGB(220,235,221),7.5f,2);
                    renderer.fill(well,White,6); renderer.outline(well.inset(.5f),focus ? RGB(98,152,123) : Border,5.5f);
                    renderer.icon(Icon::Key,{left+12,item.second+13,18,18},focus ? Pine : Subtle,1.55f);
                }
            } else if (!settings.mini && account_service) {
                const auto form = account_form(int(w));
                const float left = float(form.x) + 28, field = float(form.w) - 56;
                const Rect card{float(form.x), 76, float(form.w), campus_confirming ? 380.f : 300.f};
                renderer.fill(card, White, 9);
                renderer.outline(card.inset(.5f), Line, 8.5f);
                renderer.fill({left, 100, 44, 44}, Soft, 12);
                renderer.icon(Icon::Network, {left + 12, 112, 20, 20}, Pine, 1.6f);
                renderer.text(L"校园网", {left + 60, 128, field - 60, 22}, Muted, SmallText);
                for (int i = 0; i < 2; ++i) {
                    const float x = left + i * (field / 2 + 6);
                    renderer.fill({x, 166, field / 2 - 6, 82}, paper, 8);
                    renderer.text(i == 0 ? L"服务状态" : L"在线设备",
                                  {x + 16, 177, field / 2 - 38, 22}, Muted, SmallText);
                }
                if (campus_confirming) renderer.line(left, 258, left + field, 258, Line);
            } else if (!settings.mini && !account_editor) {
                const float rows = float(account_list_height(int(h)));
                if (account_catalog.entries.empty())
                    renderer.icon(Icon::User, {w / 2 - 17, 76 + rows / 2 - 28, 34, 34}, Subtle, 1.5f);
            } else {
                const auto form = account_form(int(w));
                const float inset = settings.mini ? 0.f : 28.f, top = settings.mini ? 0.f : 100.f;
                if (!settings.mini) {
                    const Rect card{float(form.x), 76, float(form.w), float(form.h)};
                    renderer.fill(card, White, 9);
                    renderer.outline(card.inset(.5f), Line, 8.5f);
                }
                for (auto field : {std::pair{UserInput, 0.f}, std::pair{PasswordInput, 96.f}}) {
                    const Rect well{float(form.x) + inset, top + 30 + field.second, float(form.w) - 2 * inset,
                                    44};
                    const bool focus = GetFocus() == ctrl(Account, field.first);
                    if (focus)
                        renderer.outline({well.x - 1.5f, well.y - 1.5f, well.w + 3, well.h + 3},
                                         RGB(220, 235, 221), 7.5f, 2);
                    renderer.fill(well, White, 6);
                    renderer.outline(well.inset(.5f), focus ? RGB(98, 152, 123) : Border, 5.5f);
                    renderer.icon(field.first == UserInput ? Icon::User : Icon::Key,
                                  {well.x + 12, well.y + 13, 18, 18}, focus ? Pine : Subtle, 1.55f);
                }
            }
        } else if (p.id == Preferences && !settings.mini) {
            if(update_snapshot.phase==updates::Phase::Downloading) {
                renderer.fill({0,70,w,3},Soft,1.5f);
                renderer.fill({0,70,w*update_snapshot.progress/100.f,3},Pine,1.5f);
            }
            for (Rect r : {Rect{0, 76, w, 76}, Rect{0, 226, w, settings.startup_modes.size()>=2 ? 266.f : !settings.startup_modes.empty() ? 220.f : 174.f}}) {
                renderer.fill(r, White, 9);
                renderer.outline(r.inset(.5f), Line, 8.5f);
            }
            renderer.line(28, 282, w - 28, 282, Line);
            renderer.line(28, 338, w - 28, 338, Line);
        } else if (p.id == Logs) {
            const float search_width = float(log_search_width(int(w)));
            const Rect search{0, 68, search_width, 40};
            const bool focus = GetFocus() == ctrl(Logs, LogSearch);
            if (focus)
                renderer.outline({-1, 67, search_width + 2, 42}, RGB(224, 237, 225), 9, 2);
            renderer.fill(search, White, 8);
            renderer.outline(search.inset(.5f), focus ? RGB(105, 157, 127) : Line, 7.5f);
            renderer.icon(Icon::Search, {12, 80, 16, 16}, focus ? Pine : Subtle, 1.7f);
            renderer.fill({0, 152, w, std::max(100.f, h - 156)}, White, 9);
            renderer.outline({.5f, 152.5f, w - 1, std::max(99.f, h - 157)}, Line, 8.5f);
            if (SendMessageW(ctrl(Logs, LogList), LB_GETCOUNT, 0, 0) == 0)
                renderer.icon(log_filters_active() ? Icon::Search : Icon::File,
                              {w / 2 - 16, 152 + std::max(100.f, h - 156) / 2 - 32, 32, 32},
                              RGB(161, 178, 153), 1.3f);
        }
        renderer.end();
    }
    EndPaint(p.window, &ps);
}
HBRUSH App::control_color(HDC dc, HWND child) {
    const int id = GetDlgCtrlID(child);
    const COLORREF bg = id == UserInput || id == PasswordInput || id == LogSearch || id == LogList ||
                       id == OldPasswordInput || id == NewPasswordInput || id == ConfirmPasswordInput ? visual::White : paper;
    SetTextColor(dc, ink);
    SetBkColor(dc, bg);
    SetDCBrushColor(dc, bg);
    return static_cast<HBRUSH>(GetStockObject(DC_BRUSH));
}
LRESULT CALLBACK App::button_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR data) {
    auto *app = reinterpret_cast<App *>(data);
    if (m == WM_MOUSEMOVE && app->hovered != h) {
        if (app->hovered)
            app->hover_control(app->hovered, false);
        app->hovered = h;
        app->hover_control(h, true);
        TRACKMOUSEEVENT tracking{sizeof(tracking), TME_LEAVE, h, 0};
        TrackMouseEvent(&tracking);
        InvalidateRect(h, nullptr, FALSE);
    } else if (m == WM_MOUSELEAVE) {
        if (app->hovered == h)
            app->hovered = nullptr;
        app->hover_control(h, false);
        InvalidateRect(h, nullptr, FALSE);
    } else if (m == WM_PAINT && ((GetWindowLongPtrW(h, GWL_STYLE) & BS_TYPEMASK) == BS_AUTOCHECKBOX)) {
        PAINTSTRUCT ps{};
        BeginPaint(h, &ps);
        app->draw_toggle(h, ps.hdc);
        EndPaint(h, &ps);
        return 0;
    } else if (m == WM_PRINTCLIENT && ((GetWindowLongPtrW(h, GWL_STYLE) & BS_TYPEMASK) == BS_AUTOCHECKBOX)) {
        app->draw_toggle(h, reinterpret_cast<HDC>(w));
        return 0;
    } else if (m == WM_ERASEBKGND) {
        return TRUE;
    } else if (m == WM_NCDESTROY)
        RemoveWindowSubclass(h, button_proc, 0);
    return DefSubclassProc(h, m, w, l);
}
LRESULT CALLBACK App::edit_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR) {
    if (m == WM_SETFOCUS || m == WM_KILLFOCUS)
        InvalidateRect(GetParent(h), nullptr, FALSE);
    if (m == WM_NCDESTROY)
        RemoveWindowSubclass(h, edit_proc, 0);
    return DefSubclassProc(h, m, w, l);
}
LRESULT CALLBACK App::account_list_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR data) {
    auto *app = reinterpret_cast<App *>(data);
    if (m == WM_PAINT || m == WM_PRINTCLIENT) {
        PAINTSTRUCT ps{};
        const auto dc = m == WM_PAINT ? BeginPaint(h, &ps) : reinterpret_cast<HDC>(w);
        app->paint_account_list(dc);
        if (m == WM_PAINT)
            EndPaint(h, &ps);
        return 0;
    }
    if (m == WM_ERASEBKGND)
        return TRUE;
    if (m == WM_RBUTTONDOWN) {
        app->account_pointer.cancel();
        const int selected = app->account_pointer.hit_test({GET_X_LPARAM(l), GET_Y_LPARAM(l)});
        if (selected < 0)
            app->account_pointer.clear_selection();
        else {
            SendMessageW(h, LB_SETCURSEL, selected, 0);
            SetFocus(h);
            app->select_account();
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    }
    if (m == WM_RBUTTONUP) {
        POINT point{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
        ClientToScreen(h, &point);
        app->account_menu(h, point);
        return 0;
    }
    if (m == WM_CONTEXTMENU) {
        app->account_menu(h, {GET_X_LPARAM(l), GET_Y_LPARAM(l)});
        return 0;
    }
    if (m == WM_SYSKEYDOWN && (w == VK_UP || w == VK_DOWN) && (GetKeyState(VK_MENU) & 0x8000)) {
        if (app->account_pointer.active())
            return 0;
        const int selected = int(SendMessageW(h, LB_GETCURSEL, 0, 0));
        app->move_account(selected, selected + (w == VK_UP ? -1 : 1));
        return 0;
    }
    if (m == WM_NCDESTROY)
        RemoveWindowSubclass(h, account_list_proc, 0);
    return DefSubclassProc(h, m, w, l);
}
LRESULT CALLBACK App::label_proc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR data) {
    if (m == WM_PAINT || m == WM_PRINTCLIENT) {
        auto *app = reinterpret_cast<App *>(data);
        PAINTSTRUCT ps{};
        DRAWITEMSTRUCT item{};
        item.CtlType = ODT_STATIC;
        item.CtlID = UINT(GetDlgCtrlID(h));
        item.hwndItem = h;
        GetClientRect(h, &item.rcItem);
        item.hDC = m == WM_PAINT ? BeginPaint(h, &ps) : reinterpret_cast<HDC>(w);
        app->draw_item(item);
        if (m == WM_PAINT)
            EndPaint(h, &ps);
        return 0;
    }
    if (m == WM_ERASEBKGND)
        return TRUE;
    if (m == WM_NCDESTROY)
        RemoveWindowSubclass(h, label_proc, 0);
    return DefSubclassProc(h, m, w, l);
}
LRESULT CALLBACK App::page_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    auto *page = reinterpret_cast<Page *>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        page = static_cast<Page *>(reinterpret_cast<CREATESTRUCTW *>(l)->lpCreateParams);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
        page->window = h;
    }
    if (!page)
        return DefWindowProcW(h, m, w, l);
    auto &app = *page->app;
    switch (m) {
    case WM_COMMAND:
        if (LOWORD(w) == AccountList && HIWORD(w) == LBN_SELCHANGE)
            app.select_account();
        else if (LOWORD(w) == LogSearch && HIWORD(w) == EN_CHANGE)
            app.request_logs(true);
        else if (HIWORD(w) == EN_CHANGE && (LOWORD(w) == OldPasswordInput || LOWORD(w) == NewPasswordInput || LOWORD(w) == ConfirmPasswordInput)) {
            if (app.password_view && !app.password_busy && !app.password_submitted) {
                app.password_confirming = false; app.password_message.clear(); app.update_page(Account);
            }
        }
        else if (HIWORD(w) == BN_CLICKED)
            app.command(LOWORD(w));
        return 0;
    case WM_DRAWITEM:
        app.draw_item(*reinterpret_cast<DRAWITEMSTRUCT *>(l));
        return TRUE;
    case WM_MEASUREITEM:
        reinterpret_cast<MEASUREITEMSTRUCT *>(l)->itemHeight =
            app.px(reinterpret_cast<MEASUREITEMSTRUCT *>(l)->CtlID == AccountList ? account_row_height : 68);
        return TRUE;
    case WM_LBUTTONDOWN:
        if (page->id == Logs) {
            RECT rect{};
            GetClientRect(h, &rect);
            const int width = MulDiv(rect.right, 96, int(app.dpi));
            const POINT point{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
            const RECT search{0, app.px(68), app.px(app.log_search_width(width)), app.px(108)};
            if (PtInRect(&search, point)) {
                SetFocus(app.ctrl(Logs, LogSearch));
                return 0;
            }
            SendMessageW(app.ctrl(Logs, LogList), LB_SETCURSEL, WPARAM(-1), 0);
            SetFocus(h);
        }
        if (page->id == Account && !app.settings.mini && !app.account_editor) {
            app.clear_account_selection();
            return 0;
        }
        if (page->id == Account && (app.settings.mini || app.account_editor)) {
            RECT rect{};
            GetClientRect(h, &rect);
            const int width = MulDiv(rect.right, 96, int(app.dpi));
            const auto form = app.account_form(width);
            const int inset = app.settings.mini ? 0 : 28, top = app.settings.mini ? 0 : 100;
            POINT point{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
            for (auto field : {std::pair{UserInput, 0}, std::pair{PasswordInput, 96}}) {
                RECT well{app.px(form.x + inset), app.px(top + 30 + field.second),
                          app.px(form.x + form.w - inset), app.px(top + 74 + field.second)};
                if (PtInRect(&well, point)) {
                    SetFocus(app.ctrl(Account, field.first));
                    return 0;
                }
            }
        }
        break;
    case WM_PAINT:
        app.paint_page(*page);
        return 0;
    case WM_ERASEBKGND:
        return TRUE;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(
            app.control_color(reinterpret_cast<HDC>(w), reinterpret_cast<HWND>(l)));
    case WM_CTLCOLOREDIT: {
        SetTextColor(reinterpret_cast<HDC>(w), ink);
        SetBkColor(reinterpret_cast<HDC>(w), visual::White);
        SetDCBrushColor(reinterpret_cast<HDC>(w), visual::White);
        return reinterpret_cast<LRESULT>(GetStockObject(DC_BRUSH));
    }
    case WM_CTLCOLORLISTBOX:
        return reinterpret_cast<LRESULT>(
            app.control_color(reinterpret_cast<HDC>(w), reinterpret_cast<HWND>(l)));
    }
    return DefWindowProcW(h, m, w, l);
}
LRESULT CALLBACK App::root_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    auto *app = reinterpret_cast<App *>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        app = static_cast<App *>(reinterpret_cast<CREATESTRUCTW *>(l)->lpCreateParams);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        app->window = h;
    }
    if (!app)
        return DefWindowProcW(h, m, w, l);
    if (app->taskbar_created && m == app->taskbar_created) {
        app->tray_added = false;
        app->update_tray(true);
        return 0;
    }
    switch (m) {
    case WM_NCCALCSIZE:
        if (w && IsZoomed(h)) {
            auto *frame = reinterpret_cast<NCCALCSIZE_PARAMS *>(l);
            const int x = GetSystemMetricsForDpi(SM_CXFRAME, app->dpi) +
                          GetSystemMetricsForDpi(SM_CXPADDEDBORDER, app->dpi);
            const int y = GetSystemMetricsForDpi(SM_CYFRAME, app->dpi) +
                          GetSystemMetricsForDpi(SM_CXPADDEDBORDER, app->dpi);
            InflateRect(&frame->rgrc[0], -x, -y);
        }
        return 0;
    case WM_NCHITTEST: {
        RECT bounds{};
        GetWindowRect(h, &bounds);
        const int x = GET_X_LPARAM(l) - bounds.left, y = GET_Y_LPARAM(l) - bounds.top;
        const int width = bounds.right - bounds.left, height = bounds.bottom - bounds.top,
                  border = app->px(6);
        if (!app->settings.mini && !IsZoomed(h)) {
            const bool left = x < border, right = x >= width - border, top = y < border,
                       bottom = y >= height - border;
            if (top && left)
                return HTTOPLEFT;
            if (top && right)
                return HTTOPRIGHT;
            if (bottom && left)
                return HTBOTTOMLEFT;
            if (bottom && right)
                return HTBOTTOMRIGHT;
            if (left)
                return HTLEFT;
            if (right)
                return HTRIGHT;
            if (top)
                return HTTOP;
            if (bottom)
                return HTBOTTOM;
        }
        if (y < app->px(app->settings.mini ? 52 : 44) && x < width - app->px(app->settings.mini ? 90 : 132))
            return HTCAPTION;
        return HTCLIENT;
    }
    case WM_NCACTIVATE:
        InvalidateRect(h, nullptr, FALSE);
        return TRUE;
    case WM_ACTIVATE: {
        if (LOWORD(w) == WA_INACTIVE)
            app->account_pointer.cancel();
        MARGINS margins{1, 1, 1, 1};
        DwmExtendFrameIntoClientArea(h, &margins);
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    }
    case WM_NCPAINT:
        return 0;
    case backend_message:
        app->received(std::unique_ptr<Event>(reinterpret_cast<Event *>(l)));
        return 0;
    case updates::changed_message:
        app->update_changed();
        return 0;
    case show_message:
        if (app->initialized && !app->settings.silent)
            app->show(Home);
        return 0;
    case tray_message: {
        const auto event = LOWORD(l);
        if (event == NIN_SELECT || event == NIN_KEYSELECT) {
            if (IsWindowVisible(h))
                app->hide();
            else
                app->show(Home);
        } else if (event == WM_CONTEXTMENU) {
            POINT point{GET_X_LPARAM(w), GET_Y_LPARAM(w)};
            if (point.x == -1)
                GetCursorPos(&point);
            app->tray_menu(point);
        }
        return 0;
    }
    case WM_CONTEXTMENU: {
        POINT point{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
        if (point.x == -1) {
            RECT bounds{};
            GetWindowRect(h, &bounds);
            point = {bounds.left + app->px(42), bounds.top + app->px(70)};
        }
        app->tray_menu(point);
        return 0;
    }
    case WM_LBUTTONDOWN:
        app->clear_account_selection();
        return 0;
    case WM_NCLBUTTONDOWN:
        if (w == HTCAPTION)
            app->clear_account_selection();
        break;
    case WM_COMMAND:
        if (HIWORD(w) == BN_CLICKED)
            app->command(LOWORD(w));
        return 0;
    case WM_DRAWITEM:
        app->draw_item(*reinterpret_cast<DRAWITEMSTRUCT *>(l));
        return TRUE;
    case WM_PAINT:
        app->paint_root();
        return 0;
    case WM_ERASEBKGND:
        return TRUE;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(
            app->control_color(reinterpret_cast<HDC>(w), reinterpret_cast<HWND>(l)));
    case WM_SIZE:
        if (w == SIZE_MINIMIZED) {
            app->hide();
            return 0;
        }
        app->layout();
        app->timers();
        return 0;
    case WM_TIMER:
        if (w == animation_timer)
            app->timer();
        else if (w == uptime_timer)
            app->update_uptime();
        else if (w == package_timer)
            app->request_visible_packages();
        else if (w == update_timer)
            app->update_tick();
        else if (w == exit_timer && !app->backend->running())
            DestroyWindow(h);
        else if (w == progress_timer) {
            if (auto progress = app->ctrl(app->current, Progress))
                InvalidateRect(progress, nullptr, FALSE);
        } else if (w == search_timer) {
            KillTimer(h, search_timer);
            app->backend->load_logs(app->log_query, app->log_request);
        }
        return 0;
    case WM_DPICHANGED: {
        app->dpi = HIWORD(w);
        app->remake_fonts();
        app->renderer.reset();
        app->log_scrollbar.configure(app->dpi, app->animations);
        const auto *r = reinterpret_cast<RECT *>(l);
        SetWindowPos(h, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        app->layout();
        return 0;
    }
    case WM_SETTINGCHANGE:
        app->motion_preference();
        return 0;
    case WM_ENTERSIZEMOVE:
        app->page_spring.snap(0);
        app->window_spring.snap(0);
        app->nav_spring.snap(double(app->current) * 44.);
        KillTimer(h, animation_timer);
        app->layout();
        return 0;
    case WM_GETMINMAXINFO: {
        auto *info = reinterpret_cast<MINMAXINFO *>(l);
        info->ptMinTrackSize = {app->px(app->settings.mini ? 360 : 860),
                                app->px(app->settings.mini ? 174 : 620)};
        return 0;
    }
    case WM_CLOSE:
        app->hide();
        return 0;
    case WM_QUERYENDSESSION:
        if (app->backend)
            app->backend->disconnect();
        return TRUE;
    case WM_ENDSESSION:
        if (w)
            DestroyWindow(h);
        return 0;
    case WM_DESTROY: {
        KillTimer(h, animation_timer);
        KillTimer(h, uptime_timer);
        KillTimer(h, exit_timer);
        KillTimer(h, progress_timer);
        KillTimer(h, search_timer);
        KillTimer(h, package_timer);
        KillTimer(h, update_timer);
        NOTIFYICONDATAW n{sizeof(n)};
        n.hWnd = h;
        n.uID = 1;
        Shell_NotifyIconW(NIM_DELETE, &n);
        app->tray_added = false;
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(h, m, w, l);
}
} // namespace
} // namespace scau::desktop

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    using namespace scau::desktop;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    App app;
    app.instance = instance;
    for (int i = 1; argv && i < argc; ++i) {
        const std::wstring_view argument = argv[i];
        if (argument == L"--demo")
            app.options.demo = true;
        else if (argument == L"--demo-first-run") {
            app.options.demo = true;
            app.options.demo_first_run = true;
        }
        else if (argument == L"--demo-web") {
            app.options.demo = true;
            app.options.demo_wireless = true;
        }
        else if (argument == L"--demo-network-only") {
            app.options.demo = app.options.demo_network_only = app.options.demo_wireless = true;
            app.options.demo_online = false;
        }
        else if (argument == L"--demo-web-portal") {
            app.options.demo = app.options.demo_wireless = app.options.demo_portal = true;
        }
        else if (argument == L"--demo-1x") {
            app.options.demo = app.options.demo_wireless_8021x = true;
        }
        else if (argument == L"--demo-package") {
            app.options.demo = true;
            app.options.demo_online = true;
            app.options.demo_packages = true;
        }
        else if (argument == L"--demo-online") {
            app.options.demo = true;
            app.options.demo_online = true;
        } else if (argument == L"--demo-failure") {
            app.options.demo = true;
            app.options.demo_failure = true;
        } else if (argument == L"--demo-failure-limit") {
            app.options.demo = true;
            app.options.demo_failure = true;
            app.options.demo_failure_reason = "已达到同时在线用户数量上限";
        } else if (argument == L"--demo-failover") {
            app.options.demo = true;
            app.options.demo_failover = true;
        } else if (argument == L"--demo-update") {
            app.options.demo=true;app.demo_update_available=true;
        } else if (argument == L"--demo-update-ready") {
            app.options.demo=true;app.demo_update_ready=true;
        } else if (argument == L"--demo-update-live") {
            app.options.demo=true;app.demo_update_live=true;
        } else if (argument == L"--mini")
            app.options.mini = true;
        else if (argument == L"--silent")
            app.force_silent = true;
        else if (argument == L"--startup") app.options.startup = true;
        else {
            LocalFree(argv);
            CoUninitialize();
            return 2;
        }
    }
    if (argv)
        LocalFree(argv);
    HANDLE single = nullptr;
    if (!app.options.demo) {
        single = CreateMutexW(nullptr, FALSE, L"Local\\SCAULink.Desktop.v1");
        if (!single || GetLastError() == ERROR_ALREADY_EXISTS) {
            if (!app.force_silent)
                if (auto existing = FindWindowW(root_class, L"SCAU Link"))
                    PostMessageW(existing, show_message, 0, 0);
            if (single)
                CloseHandle(single);
            CoUninitialize();
            return 0;
        }
    }
    int result = 1;
    try {
        result = app.run();
    } catch (const std::exception &) {
        if (app.window)
            DestroyWindow(app.window);
    }
    if (single)
        CloseHandle(single);
    CoUninitialize();
    return result;
}
