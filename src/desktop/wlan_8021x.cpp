#include "wlan_8021x.hpp"
#include "auth_result.hpp"
#include <dot1x.h>
#include <objbase.h>
#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace scau::desktop {
namespace {
template<class T> struct Wipe { T& value; ~Wipe() {
    if (!value.empty()) SecureZeroMemory(value.data(),value.size()*sizeof(typename T::value_type));
} };
std::wstring escaped(std::wstring_view text) {
    if (text.empty() || text.size() > 256) throw std::invalid_argument("Invalid WLAN credential size");
    for (std::size_t i=0;i<text.size();++i) {
        const auto ch=text[i];
        if (ch<32 || ch==0xfffe || ch==0xffff || (ch>=0xdc00 && ch<=0xdfff))throw std::invalid_argument("Invalid WLAN XML character");
        if (ch>=0xd800 && ch<=0xdbff) {
            if (i+1==text.size() || text[i+1]<0xdc00 || text[i+1]>0xdfff)throw std::invalid_argument("Invalid WLAN Unicode");
            ++i;
        }
    }
    std::wstring out;
    out.reserve(text.size()*6);
    for (std::size_t i=0;i<text.size();++i) {
        const auto ch=text[i];
        if (ch<32 || ch==0xfffe || ch==0xffff || (ch>=0xdc00 && ch<=0xdfff))
            throw std::invalid_argument("Invalid WLAN XML character");
        if (ch>=0xd800 && ch<=0xdbff) {
            if (i+1==text.size() || text[i+1]<0xdc00 || text[i+1]>0xdfff)
                throw std::invalid_argument("Invalid WLAN Unicode");
            out+=ch;out+=text[++i];continue;
        }
        switch(ch) {
        case L'&':out+=L"&amp;";break; case L'<':out+=L"&lt;";break; case L'>':out+=L"&gt;";break;
        case L'\"':out+=L"&quot;";break; case L'\'':out+=L"&apos;";break; default:out+=ch;
        }
    }
    return out;
}
bool valid_profile(std::wstring_view name) {
    constexpr std::wstring_view prefix=L"SCAU-Link-SCAUNET_1x-";
    return name.starts_with(prefix) && name.size()==prefix.size()+32 &&
        std::all_of(name.begin()+prefix.size(),name.end(),[](wchar_t ch){return (ch>=L'0'&&ch<=L'9')||(ch>=L'a'&&ch<=L'f');});
}
bool target_ssid(const DOT11_SSID& ssid) {
    constexpr std::string_view expected="SCAUNET_1x";
    return ssid.uSSIDLength==expected.size() && std::memcmp(ssid.ucSSID,expected.data(),expected.size())==0;
}
bool transient(DWORD reason,DWORD error) {
    return reason==WLAN_REASON_CODE_NOT_VISIBLE || reason==WLAN_REASON_CODE_NETWORK_NOT_AVAILABLE ||
           error==ERROR_NOT_FOUND || error==ERROR_DEVICE_NOT_CONNECTED || error==ERROR_INVALID_STATE || error==ERROR_BUSY;
}
constexpr unsigned char owner_tag[]="SCAULink.WLAN8021X.v1";
class NativeWlanPort final : public Wlan8021xPort {
    HANDLE handle_{};
    GUID guid_{};
    Mac mac_{};
    std::wstring profile_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<WlanEvent> events_;
    bool own_context_=false,active_=false,requested_=false,profile_owned_=false,registered_=false,cleaned_=false;
    const Credential* credential_{};
    ULONGLONG last_presence_check_=0;
    bool foreign_connection_=false;
    bool stable_=false,prepared_=false;
    WLAN_INTERFACE_STATE interface_state_=wlan_interface_state_not_ready;
    DWORD profile_flags_=WLAN_PROFILE_USER;
    static VOID WINAPI notification(WLAN_NOTIFICATION_DATA* data,void* context) noexcept {
        if(!data || !context)return;
        auto& self=*static_cast<NativeWlanPort*>(context);
        try {
            std::lock_guard lock(self.mutex_);
            auto event=decode_wlan_8021x_notification(*data,self.guid_,self.profile_,self.own_context_);
            if(!event)return;
            if(event->type==WlanEventType::Connecting)self.own_context_=true;
            else if(event->type==WlanEventType::Connected)self.own_context_=self.active_=true;
            else if(event->type==WlanEventType::OtherConnection || event->type==WlanEventType::Removed)
                self.own_context_=self.active_=self.requested_=false;
            if(event->type==WlanEventType::OtherConnection)self.foreign_connection_=true;
            else if(event->type==WlanEventType::Disconnected || event->type==WlanEventType::Failed)self.active_=false;
            if(self.events_.size()>=64) {self.events_.clear();self.events_.push_back({WlanEventType::Overflow});}
            else self.events_.push_back(*event);
            self.cv_.notify_one();
        } catch (...) { /* No exceptions or API reentry from a WLAN callback. */ }
    }
    bool present() {
        WLAN_INTERFACE_INFO_LIST* raw=nullptr;
        const auto status=WlanEnumInterfaces(handle_,nullptr,&raw);
        struct Free {void* data;~Free(){if(data)WlanFreeMemory(data);}} free{raw};
        if(status!=ERROR_SUCCESS || !raw || raw->dwNumberOfItems>128)return false;
        for(DWORD i=0;i<raw->dwNumberOfItems;++i)
            if(IsEqualGUID(raw->InterfaceInfo[i].InterfaceGuid,guid_)){interface_state_=raw->InterfaceInfo[i].isState;return true;}
        return false;
    }
    bool tagged(std::wstring_view name={}) {
        const auto target=name.empty()?profile_:std::wstring(name);
        DWORD size=0;PBYTE raw=nullptr;
        const auto result=WlanGetProfileCustomUserData(handle_,&guid_,target.c_str(),nullptr,&size,&raw);
        const bool match=result==ERROR_SUCCESS && raw && size==sizeof(owner_tag) &&
                         std::memcmp(raw,owner_tag,sizeof(owner_tag))==0;
        if(raw)WlanFreeMemory(raw);
        return match;
    }
  public:
    explicit NativeWlanPort(const Wlan8021xOptions& options):
        profile_(options.stable_profile?std::wstring(scau_8021x_ssid):wlan_8021x_profile_name(options.profile_id)),
        stable_(options.stable_profile) {
        profile_flags_=options.per_user_profile?WLAN_PROFILE_USER:0;
        const auto adapters=connection_adapters();
        const auto selected=choose_wireless_network(adapters,options.preferred_mac);
        if(!selected.found || (options.preferred_mac!=Mac{} && selected.mac!=options.preferred_mac))
            throw std::runtime_error("未找到当前无线网卡");
        const auto found=std::find_if(adapters.begin(),adapters.end(),[&](const auto& a){return a.mac==selected.mac && a.index==selected.index;});
        if(found==adapters.end())throw std::runtime_error("无线网卡已变化");
        const auto id=utf8_to_wide(found->id);
        if(FAILED(CLSIDFromString(id.c_str(),&guid_)))throw std::runtime_error("无法识别无线网卡");
        mac_=selected.mac;
        DWORD version=0;
        const auto status=WlanOpenHandle(2,nullptr,&version,&handle_);
        if(status!=ERROR_SUCCESS) {
            handle_=nullptr;
            throw std::runtime_error(status==ERROR_SERVICE_NOT_ACTIVE?"Windows WLAN 服务未运行":"无法打开 Windows WLAN 服务");
        }
        const auto subscribed=WlanRegisterNotification(handle_,WLAN_NOTIFICATION_SOURCE_ACM|WLAN_NOTIFICATION_SOURCE_ONEX,
            FALSE,notification,this,nullptr,nullptr);
        if(subscribed!=ERROR_SUCCESS) {
            WlanCloseHandle(handle_,nullptr);handle_=nullptr;
            throw std::runtime_error("无法接收 Windows 无线认证状态");
        }
        registered_=true;
    }
    ~NativeWlanPort() override {cleanup();}
    WlanOperation prepare(const Credential& credential) override {
        credential_=&credential;
        auto user=wlan_8021x_credentials_xml(credential);Wipe wipe{user};
        if(!present())return {ERROR_DEVICE_NOT_CONNECTED};
        auto xml=wlan_8021x_profile_xml(profile_);
        WLAN_PROFILE_INFO_LIST* list=nullptr;
        auto status=WlanGetProfileList(handle_,&guid_,nullptr,&list);
        if(status!=ERROR_SUCCESS)return {status};
        bool exists=false,matching_store=false,policy=false;
        std::vector<std::wstring> dormant;
        if(list && list->dwNumberOfItems<=4096)for(DWORD i=0;i<list->dwNumberOfItems;++i) {
            const auto& entry=list->ProfileInfo[i];
            if(wcsnlen_s(entry.strProfileName,WLAN_MAX_NAME_LENGTH)==profile_.size() && entry.strProfileName==profile_) {
                exists=true;matching_store=(entry.dwFlags&WLAN_PROFILE_USER)==profile_flags_;
                policy=(entry.dwFlags&WLAN_PROFILE_GROUP_POLICY)!=0;
                if(stable_)profile_flags_=entry.dwFlags&WLAN_PROFILE_USER;
            } else if(interface_state_==wlan_interface_state_disconnected && dormant.size()<128 &&
                      (entry.dwFlags&WLAN_PROFILE_USER)==profile_flags_ && wcsnlen_s(entry.strProfileName,WLAN_MAX_NAME_LENGTH)<WLAN_MAX_NAME_LENGTH &&
                      valid_profile(entry.strProfileName)) {
                dormant.emplace_back(entry.strProfileName);
            }
        }
        if(list)WlanFreeMemory(list);
        if(policy)return {ERROR_ACCESS_DISABLED_BY_POLICY};
        const bool already_owned=exists && tagged();
        if(exists && !stable_ && (!matching_store || !already_owned))return {ERROR_ALREADY_EXISTS};
        if(exists && stable_ && !already_owned) {
            wchar_t* current=nullptr;DWORD flags=0,access=0;
            status=WlanGetProfile(handle_,&guid_,profile_.c_str(),nullptr,&current,&flags,&access);
            bool campus=false;
            if(status==ERROR_SUCCESS && current) {
                const std::wstring_view text(current);
                campus=(text.find(L"<name>SCAUNET_1x</name>")!=text.npos ||
                        text.find(L"<hex>534341554E45545F3178</hex>")!=text.npos) &&
                    text.find(L"<authentication>WPA2</authentication>")!=text.npos &&
                    text.find(L"<useOneX>true</useOneX>")!=text.npos;
            }
            if(current)WlanFreeMemory(current);
            if(!campus)return {status?status:ERROR_ALREADY_EXISTS};
        }
        // Bounded orphan cleanup after a process crash, only while this
        // adapter is disconnected and only for this user's tagged profiles in
        // the selected profile store. EAP data itself is never shared.
        for(const auto& name:dormant)if(tagged(name))WlanDeleteProfile(handle_,&guid_,name.c_str(),nullptr);
        DWORD reason=0;
        status=WlanSetProfile(handle_,&guid_,profile_flags_,xml.c_str(),nullptr,exists?TRUE:FALSE,nullptr,&reason);
        if(status!=ERROR_SUCCESS)return {status,reason};
        profile_owned_=!exists || already_owned;
        if(profile_owned_) {
            auto tag=std::to_array(owner_tag);
            status=WlanSetProfileCustomUserData(handle_,&guid_,profile_.c_str(),DWORD(tag.size()),tag.data(),nullptr);
            if(status!=ERROR_SUCCESS)return {status};
        }
        // Caller only; never WLAN_SET_EAPHOST_DATA_ALL_USERS.
        status=WlanSetProfileEapXmlUserData(handle_,&guid_,profile_.c_str(),0,user.c_str(),nullptr);
        prepared_=status==ERROR_SUCCESS;
        return {status};
    }
    WlanOperation connect() override {
        {std::lock_guard lock(mutex_);if(foreign_connection_)return {ERROR_CANCELLED};}
        if(!present())return {ERROR_DEVICE_NOT_CONNECTED};
        // A physical adapter replacement cannot silently take over this session.
        const auto adapters=connection_adapters();
        if(std::none_of(adapters.begin(),adapters.end(),[&](const auto& a){
            GUID current{};const auto id=utf8_to_wide(a.id);
            return a.physical && a.wireless && a.mac==mac_ && SUCCEEDED(CLSIDFromString(id.c_str(),&current)) && IsEqualGUID(current,guid_);
        }))return {ERROR_DEVICE_NOT_CONNECTED};
        if((!prepared_ || (!stable_ && !tagged())) && credential_) {
            const auto restored=prepare(*credential_);if(restored.error)return restored;
        }
        {std::lock_guard lock(mutex_);events_.clear();own_context_=false;active_=false;requested_=true;}
        WLAN_CONNECTION_PARAMETERS request{};
        request.wlanConnectionMode=wlan_connection_mode_profile;request.strProfile=profile_.c_str();
        request.dot11BssType=dot11_BSS_type_infrastructure;
        // The return value only accepts the request. It never means Online.
        const auto status=WlanConnect(handle_,&guid_,&request,nullptr);
        if(status!=ERROR_SUCCESS){std::lock_guard lock(mutex_);requested_=false;}
        return {status};
    }
    std::optional<WlanEvent> wait(std::chrono::milliseconds duration) override {
        std::unique_lock lock(mutex_);
        if(events_.empty())cv_.wait_for(lock,duration,[&]{return !events_.empty();});
        if(events_.empty()) {
            lock.unlock();
            const auto tick=GetTickCount64();
            if(tick-last_presence_check_>=1000){last_presence_check_=tick;if(!present())return WlanEvent{WlanEventType::Removed};}
            return {};
        }
        const auto event=events_.front();events_.pop_front();return event;
    }
    void cleanup() noexcept override {
        if(cleaned_)return;cleaned_=true;
        if(!handle_)return;
        bool disconnect=false;
        {std::lock_guard lock(mutex_);disconnect=!foreign_connection_ && (active_ || own_context_ || requested_);}
        if(disconnect)WlanDisconnect(handle_,&guid_,nullptr);
        // Stop callbacks before their context is destroyed. No callback calls
        // this function, so unregistering cannot deadlock with itself.
        if(registered_)WlanRegisterNotification(handle_,WLAN_NOTIFICATION_SOURCE_NONE,TRUE,nullptr,nullptr,nullptr,nullptr);
        registered_=false;
        // A random, tagged profile belongs exclusively to this supervisor run.
        // Deleting it cannot remove the user's existing SCAUNET_1x profile and
        // also removes Windows' per-profile copy of the EAP credentials.
        if(profile_owned_ && !stable_)WlanDeleteProfile(handle_,&guid_,profile_.c_str(),nullptr);
        WlanCloseHandle(handle_,nullptr);handle_=nullptr;
    }
};
} // namespace

std::wstring wlan_8021x_profile_name(std::string_view identifier) {
    if(identifier.size()!=32 || !std::all_of(identifier.begin(),identifier.end(),[](char ch){
        return (ch>='0'&&ch<='9')||(ch>='a'&&ch<='f');}))throw std::invalid_argument("Invalid WLAN profile identifier");
    return L"SCAU-Link-SCAUNET_1x-"+std::wstring(identifier.begin(),identifier.end());
}
std::wstring wlan_8021x_profile_xml(std::wstring_view name) {
    if(name!=scau_8021x_ssid && !valid_profile(name))throw std::invalid_argument("Invalid WLAN profile name");
    std::wstring xml=LR"(<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>)";
    xml+=name;
    xml+=LR"(</name><SSIDConfig><SSID><hex>534341554E45545F3178</hex><name>SCAUNET_1x</name></SSID><nonBroadcast>false</nonBroadcast></SSIDConfig><connectionType>ESS</connectionType><connectionMode>manual</connectionMode><autoSwitch>false</autoSwitch><MSM><security><authEncryption><authentication>WPA2</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption><OneX xmlns="http://www.microsoft.com/networking/OneX/v1"><cacheUserData>true</cacheUserData><authMode>user</authMode><EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod><Config><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>25</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1"><ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames/></ServerValidation><FastReconnect>true</FastReconnect><InnerEapOptional>false</InnerEapOptional><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap><EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>false</RequireCryptoBinding><PeapExtensions><PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</PerformServerValidation><AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</AcceptServerName></PeapExtensions></EapType></Eap></Config></EapHostConfig></EAPConfig></OneX></security></MSM><MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3"><enableRandomization>false</enableRandomization></MacRandomization></WLANProfile>)";
    return xml;
}
std::wstring wlan_8021x_credentials_xml(const Credential& credential) {
    auto username=escaped(credential.username);Wipe user_wipe{username};
    auto password=escaped(credential.password);Wipe password_wipe{password};
    std::wstring xml=LR"(<?xml version="1.0"?><EapHostUserCredentials xmlns="http://www.microsoft.com/provisioning/EapHostUserCredentials"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod><Credentials xmlns:base="http://www.microsoft.com/provisioning/BaseEapUserPropertiesV1" xmlns:peap="http://www.microsoft.com/provisioning/MsPeapUserPropertiesV1" xmlns:mschap="http://www.microsoft.com/provisioning/MsChapV2UserPropertiesV1"><base:Eap><base:Type>25</base:Type><peap:EapType><peap:RoutingIdentity>)";
    xml.reserve(8192);
    xml+=username;
    xml+=L"</peap:RoutingIdentity><base:Eap><base:Type>26</base:Type><mschap:EapType><mschap:Username>";
    xml+=username;xml+=L"</mschap:Username><mschap:Password>";xml+=password;
    xml+=L"</mschap:Password><mschap:LogonDomain/></mschap:EapType></base:Eap></peap:EapType></base:Eap></Credentials></EapHostUserCredentials>";
    return xml;
}
std::optional<WlanEvent> decode_wlan_8021x_notification(const WLAN_NOTIFICATION_DATA& data,
    const GUID& interface_id,std::wstring_view profile,bool own_context) {
    if(!IsEqualGUID(data.InterfaceGuid,interface_id))return {};
    if(data.NotificationSource==WLAN_NOTIFICATION_SOURCE_ACM) {
        if(data.NotificationCode==wlan_notification_acm_interface_removal)return WlanEvent{WlanEventType::Removed};
        if(data.NotificationCode!=wlan_notification_acm_connection_start &&
           data.NotificationCode!=wlan_notification_acm_connection_complete && data.NotificationCode!=wlan_notification_acm_disconnected)return {};
        if(!data.pData || data.dwDataSize<offsetof(WLAN_CONNECTION_NOTIFICATION_DATA,strProfileXml))return {};
        WLAN_CONNECTION_NOTIFICATION_DATA item{};
        std::memcpy(&item,data.pData,offsetof(WLAN_CONNECTION_NOTIFICATION_DATA,strProfileXml));
        const auto length=wcsnlen_s(item.strProfileName,WLAN_MAX_NAME_LENGTH);
        if(length==WLAN_MAX_NAME_LENGTH)return {};
        const bool own=std::wstring_view(item.strProfileName,length)==profile && target_ssid(item.dot11Ssid) &&
            item.dot11BssType==dot11_BSS_type_infrastructure && item.wlanConnectionMode==wlan_connection_mode_profile;
        if(!own) {
            if(data.NotificationCode==wlan_notification_acm_connection_start ||
               (data.NotificationCode==wlan_notification_acm_connection_complete && item.wlanReasonCode==0))
                return WlanEvent{WlanEventType::OtherConnection};
            return {};
        }
        if(data.NotificationCode==wlan_notification_acm_connection_start)return WlanEvent{WlanEventType::Connecting};
        if(data.NotificationCode==wlan_notification_acm_disconnected)return WlanEvent{WlanEventType::Disconnected,item.wlanReasonCode};
        if(item.wlanReasonCode!=0 || !item.bSecurityEnabled)
            return WlanEvent{WlanEventType::Failed,item.wlanReasonCode,item.bSecurityEnabled?0u:ERROR_INVALID_DATA};
        return WlanEvent{WlanEventType::Connected};
    }
    if(data.NotificationSource==WLAN_NOTIFICATION_SOURCE_ONEX && data.NotificationCode==OneXNotificationTypeResultUpdate &&
       own_context && data.pData && data.dwDataSize>=sizeof(ONEX_RESULT_UPDATE_DATA)) {
        ONEX_RESULT_UPDATE_DATA item{};std::memcpy(&item,data.pData,sizeof(item));
        if(item.oneXStatus.authStatus!=OneXAuthFailure)return {};
        DWORD error=item.oneXStatus.dwError;
        if(item.fEapError) {
            const auto blob=item.eapError;
            if(blob.dwOffset<sizeof(item) || blob.dwOffset>data.dwDataSize || blob.dwSize<sizeof(ONEX_EAP_ERROR) ||
               blob.dwSize>data.dwDataSize-blob.dwOffset)return {};
            ONEX_EAP_ERROR detail{};std::memcpy(&detail,static_cast<const unsigned char*>(data.pData)+blob.dwOffset,sizeof(detail));
            error=detail.dwWinError;
        }
        return WlanEvent{WlanEventType::EapFailure,item.oneXStatus.dwReason,error};
    }
    return {};
}
bool wlan_8021x_account_rejected(DWORD error) noexcept {
    // Generic EAP failure also covers TLS/provider errors and never implies a bad password.
    return error==ERROR_LOGON_FAILURE || error==ERROR_INVALID_PASSWORD || error==ERROR_ACCOUNT_DISABLED ||
           error==ERROR_ACCOUNT_RESTRICTION || error==ERROR_PASSWORD_EXPIRED || error==ERROR_ACCOUNT_EXPIRED ||
           error==ERROR_PASSWORD_MUST_CHANGE || error==ERROR_ACCOUNT_LOCKED_OUT || error==691; // RAS authentication failure.
}
std::string wlan_8021x_failure_text(DWORD reason,DWORD error) {
    if(wlan_8021x_account_rejected(error)) {
        if(error==ERROR_ACCOUNT_DISABLED)return "学校认证提示账号已停用";
        if(error==ERROR_ACCOUNT_LOCKED_OUT)return "学校认证提示账号已锁定";
        if(error==ERROR_ACCOUNT_EXPIRED)return "学校认证提示账号已到期";
        if(error==ERROR_PASSWORD_EXPIRED || error==ERROR_PASSWORD_MUST_CHANGE)return "学校认证提示密码已到期，请修改密码";
        return "学校拒绝了此账号的无线认证，请检查账号、密码或账号限制";
    }
    if(reason==WLAN_REASON_CODE_NOT_VISIBLE || reason==WLAN_REASON_CODE_NETWORK_NOT_AVAILABLE)return "等待 SCAUNET_1x 信号";
    if(error==ERROR_SERVICE_NOT_ACTIVE)return "Windows WLAN 服务未运行";
    if(error==ERROR_ACCESS_DENIED)return "Windows 无线认证权限不足";
    if(error==ERROR_ALREADY_EXISTS)return "无线认证配置名称冲突";
    if(error==ERROR_NOT_SUPPORTED)return "Windows 不支持当前无线认证配置";
    if(error==ERROR_CANCELLED)return "无线网络已由 Windows 或其他程序切换，自动重连已停止";
    if(reason==ONEX_UI_FAILURE || reason==ONEX_UI_DISABLED || reason==ONEX_UI_NOT_PERMITTED)return "Windows EAP 需要交互，请检查系统无线认证设置";
    if(reason==ONEX_EAP_FAILURE_RECEIVED)return "无线 EAP 认证失败，Windows 未确认具体账号原因";
    if(reason==WLAN_REASON_CODE_MSMSEC_AUTH_START_TIMEOUT || reason==WLAN_REASON_CODE_MSMSEC_AUTH_SUCCESS_TIMEOUT)
        return "学校无线认证超时";
    return "无线认证失败（Windows 原因码 "+std::to_string(reason)+"，错误码 "+std::to_string(error)+"）";
}
std::unique_ptr<Wlan8021xPort> make_native_wlan_8021x_port(const Wlan8021xOptions& options) {
    return std::make_unique<NativeWlanPort>(options);
}
int run_wlan_8021x_session(const Credential& credential,const Wlan8021xOptions& options,const WirelessCallbacks& callbacks,
                          std::string* failure,Wlan8021xFactory factory) {
    if(failure)failure->clear();
    const auto fail=[&](int code,std::string text){if(failure)*failure=std::move(text);return code;};
    const auto cancelled=[&]{return options.cancel && options.cancel->load();};
    const auto now=[&]{return options.now?options.now():GetTickCount64();};
    const auto event=[&](std::string_view name){if(callbacks.event)callbacks.event(name);};
    const auto pause=[&](std::chrono::milliseconds delay){
        if(options.pause){options.pause(delay);return;}
        while(delay.count()>0 && !cancelled()){const auto step=std::min(delay,std::chrono::milliseconds(50));std::this_thread::sleep_for(step);delay-=step;}
    };
    try {
        (void)wlan_8021x_profile_name(options.profile_id);
        if(options.connect_timeout<std::chrono::milliseconds(100) || options.connect_timeout>std::chrono::minutes(5))
            return fail(auth_environment_error,"无线认证等待时间无效");
        if(cancelled())return 0;
        if(options.environment_ready)options.environment_ready();
        std::unique_ptr<Wlan8021xPort> port;
        if(factory)port=factory(options);
        else for(unsigned attempt=0;!cancelled();++attempt) {
            try {port=make_native_wlan_8021x_port(options);break;}
            catch(const std::runtime_error&) {
                if(attempt>=20)throw;
                if(attempt==0)event("wlan_8021x_waiting_for_environment");
                pause(std::chrono::milliseconds(250));
            }
        }
        if(cancelled())return 0;
        if(!port)return fail(auth_environment_error,"无法创建无线认证会话");
        struct Cleanup{Wlan8021xPort& port;~Cleanup(){port.cleanup();}} cleanup{*port};
        if(cancelled())return 0;
        const auto prepared=port->prepare(credential);
        if(prepared.error!=ERROR_SUCCESS)return fail(auth_environment_error,wlan_8021x_failure_text(prepared.reason,prepared.error));
        bool connecting=false,online=false,recovering=false;
        unsigned backoff=1000;
        std::uint64_t deadline=0;
        WlanOperation detail{};
        const auto recover=[&]{if(!recovering){recovering=true;if(callbacks.recovering)callbacks.recovering();}};
        for(;;) {
            if(cancelled())return 0;
            if(options.environment_ready)options.environment_ready();
            if(!online && !connecting) {
                detail={};
                const auto accepted=port->connect();
                if(accepted.error!=ERROR_SUCCESS) {
                    if(transient(accepted.reason,accepted.error)){recover();pause(std::chrono::milliseconds(backoff));backoff=std::min(backoff*2,30000u);continue;}
                    return fail(auth_environment_error,wlan_8021x_failure_text(accepted.reason,accepted.error));
                }
                connecting=true;deadline=now()+std::uint64_t(options.connect_timeout.count());event("wlan_8021x_connect_requested");
            }
            const auto update=port->wait(std::chrono::milliseconds(100));
            if(cancelled())return 0;
            if(!update) {
                if(connecting && now()>=deadline)return fail(auth_environment_error,"无线认证结果未确认，请检查 SCAUNET_1x 连接");
                continue;
            }
            switch(update->type) {
            case WlanEventType::Connecting: detail={};break;
            case WlanEventType::EapFailure: detail={update->error,update->reason};break;
            case WlanEventType::Connected:
                connecting=false;recovering=false;backoff=1000;
                if(!online){online=true;event("wlan_8021x_authenticated");if(callbacks.online)callbacks.online();}break;
            case WlanEventType::Failed:
                if(!connecting && !online)break;
                connecting=online=false;
                if(transient(update->reason,update->error)){recover();pause(std::chrono::milliseconds(backoff));backoff=std::min(backoff*2,30000u);break;}
                if(wlan_8021x_account_rejected(detail.error))return fail(auth_rejected,wlan_8021x_failure_text(detail.reason,detail.error));
                return fail(auth_environment_error,wlan_8021x_failure_text(detail.reason?detail.reason:update->reason,detail.error?detail.error:update->error));
            case WlanEventType::Disconnected:
                if(connecting)break; // An attempt's preceding association can disconnect before completion.
                if(wlan_8021x_account_rejected(detail.error))return fail(auth_rejected,wlan_8021x_failure_text(detail.reason,detail.error));
                if(detail.reason==ONEX_EAP_FAILURE_RECEIVED)return fail(auth_environment_error,wlan_8021x_failure_text(detail.reason,detail.error));
                online=false;recover();pause(std::chrono::milliseconds(backoff));backoff=std::min(backoff*2,30000u);break;
            case WlanEventType::Removed:
                connecting=online=false;recover();pause(std::chrono::milliseconds(backoff));backoff=std::min(backoff*2,30000u);break;
            case WlanEventType::OtherConnection:
                return fail(auth_environment_error,"无线网络已由 Windows 或其他程序切换，自动重连已停止");
            case WlanEventType::Overflow:
                return fail(auth_environment_error,"无线状态事件过多，连接结果未确认");
            }
        }
    } catch(const std::invalid_argument&) {return fail(auth_environment_error,"账号、密码或无线配置格式不受支持");}
      catch(...) {return fail(auth_environment_error,"Windows 无线认证环境异常");}
}
} // namespace scau::desktop
