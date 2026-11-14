#include <winsock2.h>
#include <ws2tcpip.h>
#include "campus_wifi.hpp"
#include "platform.hpp"
#include <wlanapi.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <objbase.h>
#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <stdexcept>

namespace scau::desktop {
namespace {
constexpr char owner[] = "SCAULink.WLAN8021X.v1";
bool cancelled(const std::atomic_bool* value) { return value && value->load(); }
class OpenWifi final : public CampusWifi {
    HANDLE handle_{}; GUID guid_{};
    unsigned index_{};
    std::mutex mutex_; std::condition_variable changed_;
    bool connected_=false, foreign_=false, requested_=false, own_started_=false;
    DWORD error_{};
    static VOID WINAPI notice(WLAN_NOTIFICATION_DATA* data,void* context) noexcept {
        if (!data || !context) return;
        auto& self=*static_cast<OpenWifi*>(context);
        if (!IsEqualGUID(data->InterfaceGuid,self.guid_) || data->NotificationSource!=WLAN_NOTIFICATION_SOURCE_ACM ||
            !data->pData || data->dwDataSize<offsetof(WLAN_CONNECTION_NOTIFICATION_DATA,strProfileXml)) return;
        if (data->NotificationCode!=wlan_notification_acm_connection_start &&
            data->NotificationCode!=wlan_notification_acm_connection_complete &&
            data->NotificationCode!=wlan_notification_acm_connection_attempt_fail && data->NotificationCode!=wlan_notification_acm_disconnected) return;
        WLAN_CONNECTION_NOTIFICATION_DATA record{};
        std::memcpy(&record,data->pData,offsetof(WLAN_CONNECTION_NOTIFICATION_DATA,strProfileXml));
        const bool ours=record.dot11Ssid.uSSIDLength==7 && std::memcmp(record.dot11Ssid.ucSSID,"SCAUNET",7)==0 &&
            wcsnlen_s(record.strProfileName,WLAN_MAX_NAME_LENGTH)==7 && std::wstring_view(record.strProfileName,7)==L"SCAUNET";
        std::lock_guard lock(self.mutex_);
        if(ours && data->NotificationCode==wlan_notification_acm_connection_start)self.own_started_=true;
        if (!ours && self.requested_ && self.own_started_ && data->NotificationCode==wlan_notification_acm_connection_start) self.foreign_=true;
        else if (ours && (data->NotificationCode==wlan_notification_acm_connection_complete ||
                         data->NotificationCode==wlan_notification_acm_connection_attempt_fail)) {
            self.connected_=record.wlanReasonCode==0 && !record.bSecurityEnabled;
            if(self.connected_)self.own_started_=true;
            self.error_=record.wlanReasonCode;
        } else if (ours && data->NotificationCode==wlan_notification_acm_disconnected) self.connected_=false;
        self.changed_.notify_all();
    }
  public:
    OpenWifi() {
        const auto adapters=connection_adapters(); const auto network=choose_wireless_network(adapters);
        const auto found=std::find_if(adapters.begin(),adapters.end(),[&](const auto& a){return a.index==network.index && a.mac==network.mac;});
        if (!network.found || found==adapters.end() || FAILED(CLSIDFromString(utf8_to_wide(found->id).c_str(),&guid_)))
            throw std::runtime_error("未找到无线网卡");
        index_=network.index;
        DWORD version{}; const auto opened=WlanOpenHandle(2,nullptr,&version,&handle_);
        if (opened) {handle_=nullptr;throw std::runtime_error("Windows WLAN 服务不可用");}
        const auto registered=WlanRegisterNotification(handle_,WLAN_NOTIFICATION_SOURCE_ACM,FALSE,notice,this,nullptr,nullptr);
        if (registered) {WlanCloseHandle(handle_,nullptr);handle_=nullptr;throw std::runtime_error("无法接收无线连接状态");}
        try {
        wchar_t* existing=nullptr; DWORD flags{},access{};
        const auto status=WlanGetProfile(handle_,&guid_,L"SCAUNET",nullptr,&existing,&flags,&access);
        bool acceptable=false;
        if (status==ERROR_SUCCESS && existing) {
            const std::wstring_view xml(existing);
            acceptable=xml.find(L"<authentication>open</authentication>")!=xml.npos &&
                xml.find(L"<encryption>none</encryption>")!=xml.npos &&
                (xml.find(L"<name>SCAUNET</name>")!=xml.npos || xml.find(L"534341554E4554")!=xml.npos);
        }
        if (existing) WlanFreeMemory(existing);
        if (status!=ERROR_SUCCESS && status!=ERROR_NOT_FOUND) throw std::runtime_error("无法读取 SCAUNET 配置");
        if (status==ERROR_SUCCESS && !acceptable) throw std::runtime_error("已有 SCAUNET 配置与学校开放网络不匹配");
        if (status==ERROR_NOT_FOUND) {
            constexpr wchar_t xml[]=LR"(<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>SCAUNET</name><SSIDConfig><SSID><hex>534341554E4554</hex><name>SCAUNET</name></SSID></SSIDConfig><connectionType>ESS</connectionType><connectionMode>manual</connectionMode><autoSwitch>false</autoSwitch><MSM><security><authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM><MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3"><enableRandomization>false</enableRandomization></MacRandomization></WLANProfile>)";
            DWORD reason{};
            auto tag=std::to_array(owner);
            // The all-user NETWORK store is also what Windows' normal Wi-Fi
            // picker creates. No account/password is stored in this profile.
            if (WlanSetProfile(handle_,&guid_,0,xml,nullptr,FALSE,nullptr,&reason)!=ERROR_SUCCESS ||
                WlanSetProfileCustomUserData(handle_,&guid_,L"SCAUNET",DWORD(tag.size()),reinterpret_cast<BYTE*>(tag.data()),nullptr)!=ERROR_SUCCESS)
                throw std::runtime_error("无法准备 SCAUNET 配置");
        }
        } catch (...) {
            WlanRegisterNotification(handle_,WLAN_NOTIFICATION_SOURCE_NONE,TRUE,nullptr,nullptr,nullptr,nullptr);
            WlanCloseHandle(handle_,nullptr);handle_=nullptr;throw;
        }
    }
    ~OpenWifi() override {
        if (handle_) {
            // Leave an existing unrelated Wi-Fi untouched after an external switch.
            bool own=false; {std::lock_guard lock(mutex_);own=requested_&&!foreign_;}
            if (own) WlanDisconnect(handle_,&guid_,nullptr);
            WlanRegisterNotification(handle_,WLAN_NOTIFICATION_SOURCE_NONE,TRUE,nullptr,nullptr,nullptr,nullptr);
            WlanCloseHandle(handle_,nullptr);
        }
    }
    unsigned interface_index() const noexcept override { return index_; }
    bool connect(const std::atomic_bool* cancel,std::string& reason) override {
        DWORD size=0;void* raw=nullptr;WLAN_OPCODE_VALUE_TYPE type{};
        const auto query=WlanQueryInterface(handle_,&guid_,wlan_intf_opcode_current_connection,nullptr,&size,&raw,&type);
        bool already=false;
        if(query==ERROR_SUCCESS && raw && size>=sizeof(WLAN_CONNECTION_ATTRIBUTES)) {
            const auto& current=*static_cast<const WLAN_CONNECTION_ATTRIBUTES*>(raw);
            already=current.isState==wlan_interface_state_connected && !current.wlanSecurityAttributes.bSecurityEnabled &&
                current.wlanAssociationAttributes.dot11Ssid.uSSIDLength==7 &&
                std::memcmp(current.wlanAssociationAttributes.dot11Ssid.ucSSID,"SCAUNET",7)==0 &&
                wcsnlen_s(current.strProfileName,WLAN_MAX_NAME_LENGTH)==7 &&
                std::wstring_view(current.strProfileName,7)==L"SCAUNET";
        }
        if(raw)WlanFreeMemory(raw);
        if(already){std::lock_guard lock(mutex_);if(!foreign_){connected_=true;requested_=true;own_started_=true;return true;}}
        const auto began=GetTickCount64();
        for (unsigned attempt=0; !cancelled(cancel);++attempt) {
            if(GetTickCount64()-began>=60000) {
                std::lock_guard lock(mutex_);
                reason="无法连接 SCAUNET（Windows "+std::to_string(error_)+"）";return false;
            }
            {std::lock_guard lock(mutex_);if(foreign_){reason="无线网络已被切换";return false;}if(connected_)return true;requested_=true;error_=0;}
            WLAN_CONNECTION_PARAMETERS request{}; request.wlanConnectionMode=wlan_connection_mode_profile;
            request.strProfile=L"SCAUNET";request.dot11BssType=dot11_BSS_type_infrastructure;
            const auto status=WlanConnect(handle_,&guid_,&request,nullptr);
            if (status && status!=ERROR_NOT_FOUND && status!=ERROR_INVALID_STATE && status!=ERROR_BUSY) {
                reason="无法连接 SCAUNET（Windows "+std::to_string(status)+"）";return false;
            }
            const auto deadline=GetTickCount64()+std::min<ULONGLONG>(30000,1000ull<<std::min(attempt,5u));
            while (!cancelled(cancel) && GetTickCount64()<deadline) {
                std::unique_lock lock(mutex_);
                if(foreign_){reason="无线网络已被切换";return false;}
                if(connected_)return true;
                changed_.wait_for(lock,std::chrono::milliseconds(100));
            }
        }
        return false;
    }
};
}
std::unique_ptr<CampusWifi> make_scau_web_wifi(){return std::make_unique<OpenWifi>();}
} // namespace scau::desktop
