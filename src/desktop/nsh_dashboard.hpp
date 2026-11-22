#pragma once
#include <cstdint>
#include <memory>
#include <windows.h>

namespace scau::desktop {
struct DashboardView;
struct DashboardInput {
    const wchar_t *status, *message, *account, *action, *login, *balance, *expiry, *billing_status;
    const wchar_t *duration, *adapter, *devices;
    std::uint32_t mode, flags;
};
enum DashboardFlag : std::uint32_t {
    DashboardMini = 1 << 0, DashboardOnline = 1 << 1, DashboardDetails = 1 << 2,
    DashboardSelectMode = 1 << 3, DashboardCanAct = 1 << 4, DashboardCanApprove = 1 << 5,
    DashboardPortal = 1 << 6
};
enum class DashboardCommand : WPARAM { Action = 1, Login, ApprovePortal, Details, Wired, WirelessWeb, Wireless8021x };

extern "C" DashboardView* scau_dashboard_create(HWND parent, HWND command_target, UINT message, HWND* child);
extern "C" void scau_dashboard_update(const DashboardView*, const DashboardInput*);
extern "C" void scau_dashboard_destroy(DashboardView*);

using DashboardHandle = std::unique_ptr<DashboardView, decltype(&scau_dashboard_destroy)>;
}
