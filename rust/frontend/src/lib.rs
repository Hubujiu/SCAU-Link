use std::ffi::c_void;
use std::rc::Rc;

use nsh_core::element::{AnyValue, PropError, PropSpec, TsTypes};
use nsh_core::prelude::*;
use nsh_platform_windows::windows::{
    Win32::{
        Foundation::{HWND, LPARAM, WPARAM},
        UI::WindowsAndMessaging::{DestroyWindow, PostMessageW},
    },
    core::PCWSTR,
};
use nsh_platform_windows::{App, AppOptions, AppView, Root};
use tokio::sync::watch;

const PAPER: u32 = 0xfcfdfb;
const INK: u32 = 0x202b27;
const MUTED: u32 = 0x546459;
const GREEN: u32 = 0x24745c;
const SOFT: u32 = 0xedf5ef;
const LINE: u32 = 0xd3ddd1;

// Mirrors src/desktop/nsh_dashboard.hpp. All strings are borrowed for a
// single call and copied before the snapshot crosses to NSH's engine thread.
#[repr(C)]
pub struct DashboardInput {
    status: *const u16,
    message: *const u16,
    account: *const u16,
    action: *const u16,
    login: *const u16,
    balance: *const u16,
    expiry: *const u16,
    billing_status: *const u16,
    duration: *const u16,
    adapter: *const u16,
    devices: *const u16,
    mode: u32,
    flags: u32,
}

const MINI: u32 = 1 << 0;
const ONLINE: u32 = 1 << 1;
const DETAILS: u32 = 1 << 2;
const SELECT_MODE: u32 = 1 << 3;
const CAN_ACT: u32 = 1 << 4;
const CAN_APPROVE: u32 = 1 << 5;
const PORTAL: u32 = 1 << 6;

#[derive(Clone, Default, PartialEq)]
struct DashboardState {
    status: String,
    message: String,
    account: String,
    action: String,
    login: String,
    balance: String,
    expiry: String,
    billing_status: String,
    duration: String,
    adapter: String,
    devices: String,
    mode: u32,
    flags: u32,
}

impl DashboardState {
    fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }
}

#[repr(usize)]
#[derive(Clone, Copy)]
enum Command {
    Action = 1,
    Login,
    ApprovePortal,
    Details,
    Wired,
    WirelessWeb,
    Wireless8021x,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Host {
    hwnd: usize,
    command_message: u32,
}

impl Host {
    fn post(self, command: Command) {
        let hwnd = HWND(self.hwnd as *mut c_void);
        let _ = unsafe {
            PostMessageW(
                Some(hwnd),
                self.command_message,
                WPARAM(command as usize),
                LPARAM(0),
            )
        };
    }
}

#[derive(Clone)]
struct DashboardProps {
    host: Host,
    updates: watch::Receiver<DashboardState>,
}

// This root is loaded only by the Rust host and has no TSX prop surface.
impl Props for DashboardProps {
    fn spec(types: &mut TsTypes) -> Vec<PropSpec> {
        <() as Props>::spec(types)
    }
    fn initial() -> Self {
        Self {
            host: Host {
                hwnd: 0,
                command_message: 0,
            },
            updates: watch::channel(DashboardState::default()).1,
        }
    }
    fn set(&mut self, name: &str, value: Option<AnyValue>) -> Result<bool, PropError> {
        <() as Props>::set(&mut (), name, value)
    }
    fn set_slot(&mut self, _: &str, _: Option<Slot>) -> bool {
        false
    }
    fn set_children(&mut self, _: Children) -> bool {
        false
    }
}

impl PartialEq for DashboardProps {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host && self.updates.same_channel(&other.updates)
    }
}

fn label(value: impl IntoReactive<SharedString>, size: f32, color: u32) -> impl IntoElement {
    text(value).text_size(px(size)).text_color(rgb(color))
}

fn button(
    caption: impl IntoReactive<SharedString>,
    enabled: impl IntoReactive<bool>,
    primary: bool,
    on_press: impl Fn() + 'static,
) -> impl IntoElement {
    view()
        .role(AccessibilityRole::Button)
        .disabled(enabled.into_reactive().map(|enabled| !enabled))
        .cursor_pointer()
        .px_4()
        .min_h(px(35.0))
        .items_center()
        .justify_center()
        .rounded(px(7.0))
        .border_1()
        .border_color(rgb(if primary { GREEN } else { LINE }))
        .bg(rgb(if primary { GREEN } else { 0xffffff }))
        .hover(move |style| style.bg(rgb(if primary { 0x195f49 } else { SOFT })))
        .focus_visible(|style| style.border_color(rgb(0x163f8a)))
        .active(|style| style.opacity(0.8))
        .disabled_style(|style| style.opacity(0.55))
        .on_press(on_press)
        .child(label(caption, 13.0, if primary { 0xffffff } else { INK }))
}

struct Dashboard;
impl Component for Dashboard {
    type Props = DashboardProps;
    type Event = NoEvent;

    fn view(props: DashboardProps, _: Scope<NoEvent>) -> impl IntoElement {
        dashboard(props)
    }
}

fn dashboard(props: DashboardProps) -> impl IntoElement {
    let mut updates = props.updates;
    let state = signal(updates.borrow_and_update().clone());
    spawn(async move {
        while updates.changed().await.is_ok() {
            state.set(updates.borrow_and_update().clone());
        }
    });
    let host = props.host;
    view()
        .flex_1()
        .gap_3()
        .bg(rgb(PAPER))
        .child(when(
            move || !state.with(|s| s.has(MINI)),
            move || header(state, host),
        ))
        .child(status_card(state, host))
        .child(when(
            move || !state.with(|s| s.has(MINI)),
            move || details(state, host),
        ))
}

fn header(state: Signal<DashboardState>, host: Host) -> impl IntoElement {
    let modes = [
        ("有线 802.1X", Command::Wired),
        ("无线 Web", Command::WirelessWeb),
        ("无线 802.1X", Command::Wireless8021x),
    ];
    let mut tabs = view().flex_row().gap_2();
    for (index, (caption, command)) in modes.into_iter().enumerate() {
        let caption = move || {
            if state.with(|s| s.mode as usize == index) {
                format!("✓ {caption}")
            } else {
                caption.to_owned()
            }
        };
        tabs = tabs.child(button(
            caption,
            move || state.with(|s| s.has(SELECT_MODE)),
            false,
            move || host.post(command),
        ));
    }
    view()
        .flex_row()
        .flex_wrap()
        .justify_between()
        .items_center()
        .gap_2()
        .child(
            text("连接")
                .text_size(px(24.0))
                .text_color(rgb(INK))
                .font_weight(FontWeight::SEMIBOLD),
        )
        .child(tabs)
}

fn status_card(state: Signal<DashboardState>, host: Host) -> impl IntoElement {
    view()
        .p(move || {
            px(if state.with(|s| s.has(MINI)) {
                10.0
            } else {
                22.0
            })
        })
        .gap_2()
        .bg(rgb(SOFT))
        .border_1()
        .border_color(rgb(LINE))
        .rounded(px(12.0))
        .child(
            text(move || state.with(|s| s.status.clone()))
                .text_size(px(25.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(INK)),
        )
        .child(when(
            move || state.with(|s| !s.has(MINI) && !s.account.is_empty()),
            move || label(move || state.with(|s| s.account.clone()), 14.0, MUTED),
        ))
        .child(when(
            move || state.with(|s| !s.message.is_empty()),
            move || label(move || state.with(|s| s.message.clone()), 13.0, MUTED),
        ))
        .child(
            view()
                .flex_row()
                .flex_wrap()
                .gap_2()
                .child(when(
                    move || state.with(|s| s.has(PORTAL) && !s.has(MINI)),
                    move || {
                        button(
                            "使用此认证页面",
                            move || state.with(|s| s.has(CAN_APPROVE)),
                            true,
                            move || host.post(Command::ApprovePortal),
                        )
                    },
                ))
                .child(button(
                    move || state.with(|s| s.action.clone()),
                    move || state.with(|s| s.has(CAN_ACT)),
                    true,
                    move || host.post(Command::Action),
                ))
                .child(when(
                    move || state.with(|s| !s.login.is_empty()),
                    move || {
                        button(
                            move || state.with(|s| s.login.clone()),
                            true,
                            false,
                            move || host.post(Command::Login),
                        )
                    },
                )),
        )
        .child(when(
            move || state.with(|s| s.has(ONLINE) && !s.has(MINI)),
            move || {
                view()
                    .flex_row()
                    .flex_wrap()
                    .gap_3()
                    .child(label(
                        move || state.with(|s| s.balance.clone()),
                        14.0,
                        GREEN,
                    ))
                    .child(label(move || state.with(|s| s.expiry.clone()), 13.0, MUTED))
            },
        ))
}

fn details(state: Signal<DashboardState>, host: Host) -> impl IntoElement {
    view()
        .gap_2()
        .items_start()
        .child(button(
            move || {
                if state.with(|s| s.has(DETAILS)) {
                    "收起详情"
                } else {
                    "连接详情"
                }
            },
            true,
            false,
            move || host.post(Command::Details),
        ))
        .child(when(
            move || state.with(|s| s.has(DETAILS)),
            move || {
                view()
                    .w_full()
                    .p_3()
                    .gap_2()
                    .bg(rgb(0xffffff))
                    .rounded(px(8.0))
                    .border_1()
                    .border_color(rgb(LINE))
                    .child(
                        view()
                            .flex_row()
                            .flex_wrap()
                            .gap_4()
                            .child(label(
                                move || state.with(|s| format!("在线时长 {}", s.duration)),
                                13.0,
                                INK,
                            ))
                            .child(label(
                                move || state.with(|s| format!("网卡 {}", s.adapter)),
                                13.0,
                                INK,
                            ))
                            .child(label(
                                move || state.with(|s| format!("在线设备 {}", s.devices)),
                                13.0,
                                INK,
                            )),
                    )
                    .child(when(
                        move || state.with(|s| s.has(ONLINE) && !s.billing_status.is_empty()),
                        move || {
                            label(
                                move || state.with(|s| s.billing_status.clone()),
                                13.0,
                                MUTED,
                            )
                        },
                    ))
            },
        ))
}

pub struct DashboardView {
    view: Rc<AppView>,
    updates: watch::Sender<DashboardState>,
}

// Called on the host's Win32 message thread with live parent/command windows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scau_dashboard_create(
    parent: HWND,
    command_target: HWND,
    command_message: u32,
    hwnd: *mut HWND,
) -> *mut DashboardView {
    let Ok(view) = AppView::new(Some(parent), AppOptions::default()) else {
        return std::ptr::null_mut();
    };
    let (updates, receiver) = watch::channel(DashboardState {
        status: "正在加载".into(),
        ..DashboardState::default()
    });
    let host = Host {
        hwnd: command_target.0 as usize,
        command_message,
    };
    let root = Root::new::<Dashboard>(move || DashboardProps {
        host,
        updates: receiver.clone(),
    });
    view.load(App::Rust(root));
    unsafe { hwnd.write(view.hwnd()) };
    Box::into_raw(Box::new(DashboardView { view, updates }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scau_dashboard_update(
    handle: *const DashboardView,
    input: *const DashboardInput,
) {
    let handle = unsafe { &*handle };
    let input = unsafe { &*input };
    let wide = |value| {
        let value = PCWSTR(value);
        String::from_utf16_lossy(unsafe { value.as_wide() })
    };
    let snapshot = DashboardState {
        status: wide(input.status),
        message: wide(input.message),
        account: wide(input.account),
        action: wide(input.action),
        login: wide(input.login),
        balance: wide(input.balance),
        expiry: wide(input.expiry),
        billing_status: wide(input.billing_status),
        duration: wide(input.duration),
        adapter: wide(input.adapter),
        devices: wide(input.devices),
        mode: input.mode,
        flags: input.flags,
    };
    handle.updates.send_if_modified(move |current| {
        if *current == snapshot {
            return false;
        }
        *current = snapshot;
        true
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scau_dashboard_destroy(handle: *mut DashboardView) {
    let handle = unsafe { Box::from_raw(handle) };
    handle.view.stop();
    let _ = unsafe { DestroyWindow(handle.view.hwnd()) };
}
