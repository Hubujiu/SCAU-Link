#include "startup.hpp"
#include <windows.h>
#include <taskschd.h>
#include <sddl.h>
#include <wrl/client.h>
#include <stdexcept>
#include <vector>

namespace scau::desktop {
namespace {
using Microsoft::WRL::ComPtr;
void check(HRESULT result) { if (FAILED(result)) throw std::runtime_error("Cannot update logon startup task"); }
struct Apartment {
    HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    Apartment() { if (result != RPC_E_CHANGED_MODE) check(result); }
    ~Apartment() { if (SUCCEEDED(result)) CoUninitialize(); }
};
struct Bstr {
    BSTR value;
    explicit Bstr(const std::wstring& text):value(SysAllocString(text.c_str())) { if (!value) throw std::bad_alloc(); }
    ~Bstr() { SysFreeString(value); }
    operator BSTR() const { return value; }
};
std::wstring current_user() {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw std::runtime_error("Cannot read startup identity");
    struct Close { HANDLE value; ~Close(){CloseHandle(value);} } close{token};
    DWORD size=0; GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> data(size);
    if (!GetTokenInformation(token,TokenUser,data.data(),size,&size)) throw std::runtime_error("Cannot read startup identity");
    LPWSTR sid{};
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,&sid)) throw std::runtime_error("Cannot read startup identity");
    std::wstring result(sid); LocalFree(sid); return result;
}
std::wstring xml(std::wstring_view text) {
    std::wstring out;
    for (auto ch:text) switch(ch) {
    case L'&':out+=L"&amp;";break; case L'<':out+=L"&lt;";break;
    case L'>':out+=L"&gt;";break; case L'\"':out+=L"&quot;";break;
    case L'\'':out+=L"&apos;";break; default:out+=ch;
    }
    return out;
}
ComPtr<ITaskFolder> folder() {
    ComPtr<ITaskService> service;
    check(CoCreateInstance(CLSID_TaskScheduler,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&service)));
    VARIANT empty{}; check(service->Connect(empty,empty,empty,empty));
    ComPtr<ITaskFolder> root; check(service->GetFolder(Bstr(L"\\"),&root)); return root;
}
bool missing(HRESULT result) { return result==HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || result==HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND); }
}
std::wstring startup_task_name() { return L"SCAULink-Logon-"+current_user(); }
std::wstring startup_task_xml(const std::filesystem::path& executable, const std::wstring& user) {
    const auto path=std::filesystem::absolute(executable);
    return L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
        L"<RegistrationInfo><Description>SCAU Link logon connection</Description></RegistrationInfo>"
        L"<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>"+xml(user)+L"</UserId><Delay>PT0S</Delay></LogonTrigger></Triggers>"
        L"<Principals><Principal id=\"User\"><UserId>"+xml(user)+L"</UserId><LogonType>InteractiveToken</LogonType>"
        L"<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>"
        L"<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        L"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>false</StartWhenAvailable>"
        L"<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><Enabled>true</Enabled>"
        L"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>4</Priority></Settings>"
        L"<Actions Context=\"User\"><Exec><Command>"+xml(path.wstring())+L"</Command><Arguments>--startup</Arguments>"
        L"<WorkingDirectory>"+xml(path.parent_path().wstring())+L"</WorkingDirectory></Exec></Actions></Task>";
}
bool startup_task_enabled(const std::wstring& name) {
    Apartment apartment;
    ComPtr<IRegisteredTask> task;
    auto result=folder()->GetTask(Bstr(name),&task);
    if (missing(result)) return false;
    check(result); VARIANT_BOOL enabled{}; check(task->get_Enabled(&enabled)); return enabled==VARIANT_TRUE;
}
void configure_startup_task(bool enabled, const std::filesystem::path& executable, const std::wstring& name) {
    Apartment apartment; auto root=folder();
    if (!enabled) { const auto result=root->DeleteTask(Bstr(name),0); if (!missing(result)) check(result); return; }
    VARIANT empty{}; ComPtr<IRegisteredTask> task;
    check(root->RegisterTask(Bstr(name),Bstr(startup_task_xml(executable,current_user())),TASK_CREATE_OR_UPDATE,
        empty,empty,TASK_LOGON_INTERACTIVE_TOKEN,empty,&task));
}
void remove_owned_startup_task(const std::filesystem::path& executable, const std::wstring& requested_name) {
    Apartment apartment; auto root=folder(); ComPtr<IRegisteredTask> task;
    const auto name=requested_name.empty()?startup_task_name():requested_name;
    const auto result=root->GetTask(Bstr(name),&task);
    if (missing(result)) return; check(result);
    ComPtr<ITaskDefinition> definition; check(task->get_Definition(&definition));
    ComPtr<IActionCollection> actions; check(definition->get_Actions(&actions));
    LONG count{}; check(actions->get_Count(&count)); if (count!=1) return;
    ComPtr<IAction> action; check(actions->get_Item(1,&action)); ComPtr<IExecAction> exec;
    if (FAILED(action.As(&exec))) return;
    BSTR path{},arguments{}; check(exec->get_Path(&path));
    const std::wstring target=path?path:L""; SysFreeString(path);
    check(exec->get_Arguments(&arguments)); const std::wstring args=arguments?arguments:L""; SysFreeString(arguments);
    if (_wcsicmp(target.c_str(),std::filesystem::absolute(executable).c_str())==0 && args==L"--startup")
        check(root->DeleteTask(Bstr(name),0));
}
}
