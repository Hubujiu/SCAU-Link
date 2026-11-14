#include "desktop/wlan_8021x.hpp"
#include "auth_result.hpp"
#include <dot1x.h>
#include <eaphostpeerconfigapis.h>
#include <wrl/client.h>
#include <deque>
#include <cstring>
#include <iostream>
#include <stdexcept>

using namespace scau;
using namespace scau::desktop;
using Microsoft::WRL::ComPtr;
namespace {
unsigned checks=0;
void require(bool condition,const char* message){++checks;if(!condition)throw std::runtime_error(message);}
template<class F> void invalid(F f){bool rejected=false;try{f();}catch(const std::invalid_argument&){rejected=true;}require(rejected,"Invalid XML input accepted");}
ComPtr<IXMLDOMDocument2> document(const std::wstring& text) {
    ComPtr<IXMLDOMDocument2> dom;
    require(SUCCEEDED(CoCreateInstance(__uuidof(DOMDocument60),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dom))),"Cannot create local XML validator");
    dom->put_async(VARIANT_FALSE);dom->put_resolveExternals(VARIANT_FALSE);dom->put_validateOnParse(VARIANT_FALSE);
    BSTR xml=SysAllocStringLen(text.data(),UINT(text.size()));VARIANT_BOOL parsed=VARIANT_FALSE;
    const auto result=dom->loadXML(xml,&parsed);SysFreeString(xml);
    require(SUCCEEDED(result) && parsed==VARIANT_TRUE,"Generated XML is not well formed");
    return dom;
}
void native_eap_xml_validation() {
    require(!Wlan8021xOptions{}.per_user_profile,
            "Use the Windows PEAP profile store verified by the live A/B test");
    const auto name=wlan_8021x_profile_name(std::string(32,'a'));
    const auto profile=wlan_8021x_profile_xml(name);
    auto dom=document(profile);
    require(profile.find(L"<authentication>WPA2</authentication>")!=profile.npos &&
            profile.find(L"<encryption>AES</encryption>")!=profile.npos && profile.find(L"<useOneX>true</useOneX>")!=profile.npos,
            "Wrong SSID security protocol");
    require(profile.find(L"<hex>534341554E45545F3178</hex>")!=profile.npos &&
            profile.find(L"<connectionMode>manual</connectionMode>")!=profile.npos &&
            profile.find(L"<authMode>user</authMode>")!=profile.npos &&
            profile.find(L"<UseWinLogonCredentials>false</UseWinLogonCredentials>")!=profile.npos,
            "Profile must use only the school's SSID, an explicit request and saved user credentials");
    require(profile.find(L"Password")==profile.npos,"Profile contains a credential field");
    require(profile.find(L"<enableRandomization>false</enableRandomization>")!=profile.npos,
        "Worker recovery must retain a stable device identity and DHCP lease");
    ComPtr<IXMLDOMNode> config;
    BSTR xpath=SysAllocString(L"//*[local-name()='EapHostConfig']");
    const auto selected=dom->selectSingleNode(xpath,&config);SysFreeString(xpath);
    require(SUCCEEDED(selected) && config,"Cannot extract generated EAP config");
    DWORD size=0;BYTE* blob=nullptr;EAP_METHOD_TYPE method{};EAP_ERROR* error=nullptr;
    const auto status=EapHostPeerConfigXml2Blob(0,config.Get(),&size,&blob,&method,&error);
    if(error)EapHostPeerFreeErrorMemory(error);
    struct Free {BYTE*& data;DWORD& size;~Free(){if(data){SecureZeroMemory(data,size);EapHostPeerFreeMemory(data);}}} free{blob,size};
    if(status!=ERROR_SUCCESS)std::cerr<<"Local EAP configuration parser returned "<<status<<'\n';
    require(status==ERROR_SUCCESS && size>0 && blob && method.eapType.type==25,
            "Windows PEAP provider rejected the generated configuration");
    Credential credential;credential.username=L"fixture<&\"'account";credential.password=L"synthetic<&\"'secret";
    auto credentials=wlan_8021x_credentials_xml(credential);
    require(credentials.find(L"fixture&lt;&amp;&quot;&apos;account")!=credentials.npos &&
            credentials.find(L"synthetic&lt;&amp;&quot;&apos;secret")!=credentials.npos,
            "Credentials are not XML-escaped");
    auto user=document(credentials);ComPtr<IXMLDOMElement> root;user->get_documentElement(&root);
    DWORD user_size=0;BYTE* user_blob=nullptr;EAP_METHOD_TYPE user_method{};error=nullptr;
    const auto user_status=EapHostPeerCredentialsXml2Blob(0,root.Get(),size,blob,&user_size,&user_blob,&user_method,&error);
    if(error)EapHostPeerFreeErrorMemory(error);
    if(user_blob){SecureZeroMemory(user_blob,user_size);EapHostPeerFreeMemory(user_blob);}
    SecureZeroMemory(credentials.data(),credentials.size()*sizeof(wchar_t));
    if(user_status!=ERROR_SUCCESS)std::cerr<<"Local EAP credentials parser returned "<<user_status<<'\n';
    require(user_status==ERROR_SUCCESS && user_size>0 && user_method.eapType.type==25,
            "Windows PEAP provider rejected synthetic user credentials");
    for(const auto id:{std::string{},std::string(31,'a'),std::string(33,'a'),std::string(32,'g'),std::string(32,'A')})
        invalid([&]{(void)wlan_8021x_profile_name(id);});
    require(Wlan8021xOptions{}.stable_profile,"Production must retain the school network name");
    const auto stable=wlan_8021x_profile_xml(L"SCAUNET_1x");
    require(stable.find(L"<name>SCAUNET_1x</name>")!=stable.npos &&
            stable.find(L"<singleSignOn>")==stable.npos,
            "Stable profile must use supplied credentials without Windows logon SSO");
    document(stable);
    invalid([&]{(void)wlan_8021x_profile_xml(L"unrelated-network");});
    for(const auto next:{std::wstring{},std::wstring(257,L'p'),std::wstring(L"a\nb"),std::wstring(1,wchar_t(0xd800)),std::wstring(1,wchar_t(0xdc00))}) {
        credential.password=next;invalid([&]{(void)wlan_8021x_credentials_xml(credential);});
    }
}
void notification_bounds() {
    const GUID own{0x12345678,0,0,{1,2,3,4,5,6,7,8}},other{};
    const auto name=wlan_8021x_profile_name(std::string(32,'b'));
    WLAN_CONNECTION_NOTIFICATION_DATA payload{};
    payload.wlanConnectionMode=wlan_connection_mode_profile;wcscpy_s(payload.strProfileName,name.c_str());
    constexpr char ssid[]="SCAUNET_1x";payload.dot11Ssid.uSSIDLength=sizeof(ssid)-1;
    std::memcpy(payload.dot11Ssid.ucSSID,ssid,sizeof(ssid)-1);payload.dot11BssType=dot11_BSS_type_infrastructure;
    payload.bSecurityEnabled=TRUE;
    WLAN_NOTIFICATION_DATA data{};data.InterfaceGuid=own;data.NotificationSource=WLAN_NOTIFICATION_SOURCE_ACM;
    data.NotificationCode=wlan_notification_acm_connection_complete;data.pData=&payload;data.dwDataSize=sizeof(payload);
    const auto parse=[&](bool context=true){return decode_wlan_8021x_notification(data,own,name,context);};
    require(parse() && parse()->type==WlanEventType::Connected,"Owned secured completion was lost");
    data.InterfaceGuid=other;require(!parse(),"Wrong interface was accepted");data.InterfaceGuid=own;
    for(DWORD size=0;size<offsetof(WLAN_CONNECTION_NOTIFICATION_DATA,strProfileXml);++size) {
        data.dwDataSize=size;require(!parse(),"Truncated notification was accepted");
    }
    data.dwDataSize=sizeof(payload);data.pData=nullptr;require(!parse(),"Null notification was accepted");data.pData=&payload;
    payload.dot11Ssid.uSSIDLength=33;require(parse()->type==WlanEventType::OtherConnection,"Invalid SSID length was accepted");payload.dot11Ssid.uSSIDLength=sizeof(ssid)-1;
    payload.bSecurityEnabled=FALSE;require(parse()->type==WlanEventType::Failed,"Unsecured connection became Online");payload.bSecurityEnabled=TRUE;
    payload.wlanReasonCode=ONEX_EAP_FAILURE_RECEIVED;require(parse()->type==WlanEventType::Failed,"Failure reason became success");payload.wlanReasonCode=0;
    payload.strProfileName[0]=L'X';require(parse()->type==WlanEventType::OtherConnection,"Other profile became Online");payload.strProfileName[0]=name[0];
    std::fill(std::begin(payload.strProfileName),std::end(payload.strProfileName),L'x');require(!parse(),"Unterminated profile name accepted");wcscpy_s(payload.strProfileName,name.c_str());
    data.NotificationCode=wlan_notification_acm_connection_attempt_fail;require(!parse(),"Intermediate BSSID failure must not cause account rotation");
    struct Detail {ONEX_RESULT_UPDATE_DATA result{};ONEX_EAP_ERROR error{};} detail;
    detail.result.oneXStatus.authStatus=OneXAuthFailure;detail.result.oneXStatus.dwReason=ONEX_EAP_FAILURE_RECEIVED;
    detail.result.fEapError=1;detail.result.eapError={sizeof(detail.error),offsetof(Detail,error)};detail.error.dwWinError=ERROR_LOGON_FAILURE;
    data.NotificationSource=WLAN_NOTIFICATION_SOURCE_ONEX;data.NotificationCode=OneXNotificationTypeResultUpdate;
    data.pData=&detail;data.dwDataSize=sizeof(detail);
    require(!parse(false),"Unattributed EAP error accepted");
    require(parse()->type==WlanEventType::EapFailure && parse()->error==ERROR_LOGON_FAILURE,"Explicit EAP error detail lost");
    detail.result.eapError.dwOffset=0;require(!parse(),"Overlapping EAP blob accepted");
    detail.result.eapError.dwOffset=MAXDWORD;require(!parse(),"Overflow EAP offset accepted");
    detail.result.eapError.dwOffset=offsetof(Detail,error);detail.result.eapError.dwSize=MAXDWORD;require(!parse(),"Overflow EAP size accepted");
    detail.result.eapError.dwSize=sizeof(detail.error);detail.result.oneXStatus.authStatus=OneXAuthSuccess;
    require(!parse(),"EAP success alone must not bypass secure connection completion");
    require(!wlan_8021x_account_rejected(0) && !wlan_8021x_account_rejected(ERROR_TIMEOUT) &&
            !wlan_8021x_account_rejected(0x80090325),"Infrastructure/TLS error treated as account rejection");
    require(wlan_8021x_account_rejected(ERROR_LOGON_FAILURE) && wlan_8021x_account_rejected(ERROR_ACCOUNT_LOCKED_OUT),"Explicit credential rejection unrecognized");
}
struct Fixture {
    std::atomic_bool cancel=false;
    std::uint64_t time=0,cancel_at=5000;
    unsigned prepared=0,connected=0,cleaned=0,online=0,recovering=0,factories=0;
    WlanOperation prepare_result{};
    std::deque<WlanOperation> connect_results;
    std::deque<WlanEvent> events;
    struct Port:Wlan8021xPort {
        Fixture& f;explicit Port(Fixture& fixture):f(fixture){}
        WlanOperation prepare(const Credential&) override{++f.prepared;return f.prepare_result;}
        WlanOperation connect() override {++f.connected;if(f.connect_results.empty())return {};auto r=f.connect_results.front();f.connect_results.pop_front();return r;}
        std::optional<WlanEvent> wait(std::chrono::milliseconds d) override{
            f.time+=d.count();if(f.time>=f.cancel_at){f.cancel=true;return {};}
            if(f.events.empty())return {};auto e=f.events.front();f.events.pop_front();return e;
        }
        void cleanup() noexcept override{++f.cleaned;}
    };
    int run(std::string& reason,std::function<void()> guard={}) {
        Credential c;c.username=L"fixture";c.password=L"synthetic-only";
        Wlan8021xOptions o;o.profile_id=std::string(32,'c');o.cancel=&cancel;o.connect_timeout=std::chrono::milliseconds(1000);
        o.now=[&]{return time;};o.pause=[&](auto d){time+=d.count();if(time>=cancel_at)cancel=true;};o.environment_ready=std::move(guard);
        WirelessCallbacks callbacks;callbacks.online=[&]{++online;};callbacks.recovering=[&]{++recovering;};
        return run_wlan_8021x_session(c,o,callbacks,&reason,[&](const auto&){++factories;return std::make_unique<Port>(*this);});
    }
};
void session_behaviour() {
    std::string reason;
    {Fixture f;f.cancel=true;require(f.run(reason)==0 && !f.factories && !f.prepared,"Precancelled session touched Windows");}
    {Fixture f;require(f.run(reason)==auth_environment_error && f.connected==1 && !f.online && f.cleaned==1,
        "Accepted WlanConnect/timeout cannot mean authenticated or trigger another login");}
    {Fixture f;f.events={{WlanEventType::Connected}};require(f.run(reason)==0 && f.online==1 && f.connected==1 && f.cleaned==1,
        "Secure completion/stop lifecycle");}
    {Fixture f;f.events={{WlanEventType::Connecting},{WlanEventType::EapFailure,ONEX_EAP_FAILURE_RECEIVED,ERROR_LOGON_FAILURE},
        {WlanEventType::Failed,ONEX_EAP_FAILURE_RECEIVED}};
        require(f.run(reason)==auth_rejected && f.connected==1 && !f.online && f.cleaned==1,"Explicit account rejection must permit desktop retry");}
    {Fixture f;f.events={{WlanEventType::EapFailure,ONEX_EAP_FAILURE_RECEIVED,0x80090325},{WlanEventType::Failed,ONEX_EAP_FAILURE_RECEIVED}};
        require(f.run(reason)==auth_environment_error && !f.online && f.connected==1,"Certificate/provider failure must not rotate accounts");}
    {Fixture f;f.events={{WlanEventType::Failed,WLAN_REASON_CODE_NOT_VISIBLE},{WlanEventType::Connected}};
        require(f.run(reason)==0 && f.connected==2 && f.online==1 && f.recovering==1,"Missing signal must wait and recover the same account");}
    {Fixture f;f.events={{WlanEventType::Connected},{WlanEventType::Disconnected},{WlanEventType::Connected}};
        require(f.run(reason)==0 && f.connected==2 && f.online==2 && f.recovering==1,"Lost link must reconnect same identity");}
    {Fixture f;f.events={{WlanEventType::Connected},{WlanEventType::Removed},{WlanEventType::Connected}};
        f.connect_results={{},{ERROR_DEVICE_NOT_CONNECTED},{}};
        require(f.run(reason)==0 && f.connected==3 && f.online==2 && f.recovering==1,"Adapter unplug must wait for its own interface");}
    {Fixture f;f.events={{WlanEventType::Connected},{WlanEventType::OtherConnection}};
        require(f.run(reason)==auth_environment_error && f.connected==1 && f.online==1 && f.cleaned==1,"Manual network switch must stop reconnection");}
    {Fixture f;f.events={{WlanEventType::Overflow}};
        require(f.run(reason)==auth_environment_error && !f.online,"Queue overflow cannot produce success");}
    {Fixture f;f.prepare_result.error=ERROR_ACCESS_DENIED;
        require(f.run(reason)==auth_environment_error && f.connected==0 && f.cleaned==1,"Profile/credential setup failure must stop before connect");}
    {Fixture f;unsigned guards=0;require(f.run(reason,[&]{if(++guards==2)throw std::runtime_error("fixture-conflict");})==auth_environment_error &&
        f.cleaned==1 && f.connected==0,"Client conflict must prevent connection and clean up");}
    {Fixture f;f.events={{WlanEventType::EapFailure,ONEX_EAP_FAILURE_RECEIVED,ERROR_LOGON_FAILURE}};
        require(f.run(reason)==auth_environment_error && !f.online && f.connected==1,
        "Uncompleted attempt with EAP detail alone must not trigger account rotation");}
}
} // namespace
int wmain() {
    const auto com=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    try {
        require(SUCCEEDED(com),"Cannot initialize offline COM parser");
        native_eap_xml_validation();notification_bounds();session_behaviour();
        std::cout<<"wlan_8021x_tests: "<<checks<<" checks passed; native Windows PEAP XML parsing and injected sessions only; no WLAN mutations or campus authentication\n";
        CoUninitialize();return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';if(SUCCEEDED(com))CoUninitialize();return 1;}
}
