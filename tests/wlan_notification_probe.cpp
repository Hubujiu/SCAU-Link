// Passive ACM/ONEX diagnostics. No profile, credentials, scan or connection APIs.
#include <windows.h>
#include <wlanapi.h>
#include <dot1x.h>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string_view>
#include <thread>

namespace {
struct Probe {
    std::ofstream output;
    std::mutex lock;
    std::mutex state_lock;
    bool own_context = false;
    GUID own_guid{};
    void write(const char* name, DWORD code, DWORD reason=0, DWORD error=0) {
        std::lock_guard guard(lock);
        SYSTEMTIME t{};GetSystemTime(&t);char stamp[40]{};
        sprintf_s(stamp,"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
        output << "{\"time\":\"" << stamp << "\",\"event\":\"" << name << "\",\"code\":" << code
               << ",\"reason\":" << reason << ",\"error\":" << error << "}\n" << std::flush;
    }
    static VOID WINAPI changed(WLAN_NOTIFICATION_DATA* data, void* context) noexcept {
        if(!data || !context)return;
        auto& self=*static_cast<Probe*>(context);
        try {
            std::lock_guard state_guard(self.state_lock);
            if(data->NotificationSource==WLAN_NOTIFICATION_SOURCE_ACM && data->pData &&
               data->dwDataSize>=offsetof(WLAN_CONNECTION_NOTIFICATION_DATA,strProfileXml) &&
               (data->NotificationCode==wlan_notification_acm_connection_start ||
                data->NotificationCode==wlan_notification_acm_connection_complete ||
                data->NotificationCode==wlan_notification_acm_connection_attempt_fail ||
                data->NotificationCode==wlan_notification_acm_disconnected)) {
                WLAN_CONNECTION_NOTIFICATION_DATA item{};
                std::memcpy(&item,data->pData,offsetof(WLAN_CONNECTION_NOTIFICATION_DATA,strProfileXml));
                const auto length=wcsnlen_s(item.strProfileName,WLAN_MAX_NAME_LENGTH);
                if(length==WLAN_MAX_NAME_LENGTH)return;
                const std::wstring_view profile(item.strProfileName,length);
                constexpr std::wstring_view prefix=L"SCAU-Link-SCAUNET_1x-";
                const bool own=profile.starts_with(prefix) && profile.size()==prefix.size()+32;
                if(data->NotificationCode==wlan_notification_acm_connection_start) {
                    self.own_context=own;self.own_guid=data->InterfaceGuid;
                }
                if(!own)return;
                self.write("acm_notification",data->NotificationCode,item.wlanReasonCode,item.bSecurityEnabled?0:ERROR_INVALID_DATA);
            } else if(data->NotificationSource==WLAN_NOTIFICATION_SOURCE_ONEX && self.own_context &&
                      IsEqualGUID(data->InterfaceGuid,self.own_guid)) {
                if(data->NotificationCode!=OneXNotificationTypeResultUpdate || !data->pData ||
                   data->dwDataSize<sizeof(ONEX_RESULT_UPDATE_DATA)) {
                    self.write("onex_notification",data->NotificationCode);return;
                }
                ONEX_RESULT_UPDATE_DATA item{};std::memcpy(&item,data->pData,sizeof(item));
                DWORD error=item.oneXStatus.dwError;
                if(item.fEapError && item.eapError.dwOffset>=sizeof(item) &&
                   item.eapError.dwOffset<=data->dwDataSize && item.eapError.dwSize>=sizeof(ONEX_EAP_ERROR) &&
                   item.eapError.dwSize<=data->dwDataSize-item.eapError.dwOffset) {
                    ONEX_EAP_ERROR detail{};
                    std::memcpy(&detail,static_cast<const unsigned char*>(data->pData)+item.eapError.dwOffset,sizeof(detail));
                    error=detail.dwWinError;
                }
                self.write("onex_status",static_cast<DWORD>(item.oneXStatus.authStatus),item.oneXStatus.dwReason,error);
            }
        } catch(...) {}
    }
};
}
int wmain(int argc,wchar_t** argv) {
    if(argc!=4)return 2;
    unsigned duration=0;
    try {duration=std::stoul(argv[2]);}catch(...){return 2;}
    if(std::wstring_view(argv[1])!=L"--seconds" || duration<10 || duration>3600)return 2;
    Probe probe;probe.output.open(std::filesystem::path(argv[3]),std::ios::app);
    if(!probe.output)return 3;
    HANDLE handle=nullptr;DWORD version=0;
    auto status=WlanOpenHandle(2,nullptr,&version,&handle);
    if(status){probe.write("open_failed",status);return 4;}
    status=WlanRegisterNotification(handle,WLAN_NOTIFICATION_SOURCE_ACM|WLAN_NOTIFICATION_SOURCE_ONEX,FALSE,
                                    Probe::changed,&probe,nullptr,nullptr);
    if(status){probe.write("subscribe_failed",status);WlanCloseHandle(handle,nullptr);return 4;}
    probe.write("passive_probe_ready",0);
    std::this_thread::sleep_for(std::chrono::seconds(duration));
    WlanRegisterNotification(handle,WLAN_NOTIFICATION_SOURCE_NONE,TRUE,nullptr,nullptr,nullptr,nullptr);
    WlanCloseHandle(handle,nullptr);
    return 0;
}
