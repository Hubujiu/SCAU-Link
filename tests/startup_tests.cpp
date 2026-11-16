#include "desktop/startup.hpp"
#include <windows.h>
#include <taskschd.h>
#include <wrl/client.h>
#include <iostream>
#include <stdexcept>

using namespace scau::desktop;
using Microsoft::WRL::ComPtr;
void require(bool value,const char* message){if(!value)throw std::runtime_error(message);}
void check(HRESULT result){require(SUCCEEDED(result),"Task Scheduler integration failed");}
int main(){
    CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    try {
        const auto name=L"SCAULink-Test-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
        const auto executable=std::filesystem::temp_directory_path()/L"SCAU & test"/L"SCAU-Link.exe";
        struct Cleanup {std::wstring name;~Cleanup(){try{configure_startup_task(false,{},name);}catch(...){}}} cleanup{name};
        require(!startup_task_enabled(name),"Fresh test task must be absent");
        configure_startup_task(true,executable,name);
        require(startup_task_enabled(name),"Registered logon task must be enabled");
        ComPtr<ITaskService> service; check(CoCreateInstance(CLSID_TaskScheduler,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&service)));
        VARIANT empty{}; check(service->Connect(empty,empty,empty,empty));
        ComPtr<ITaskFolder> root; BSTR root_name=SysAllocString(L"\\"); check(service->GetFolder(root_name,&root));SysFreeString(root_name);
        ComPtr<IRegisteredTask> task;BSTR task_name=SysAllocString(name.c_str());check(root->GetTask(task_name,&task));SysFreeString(task_name);
        ComPtr<ITaskDefinition> definition;check(task->get_Definition(&definition));
        ComPtr<ITaskSettings> settings;check(definition->get_Settings(&settings));
        VARIANT_BOOL flag{};check(settings->get_RunOnlyIfNetworkAvailable(&flag));require(flag==VARIANT_FALSE,"Authentication cannot wait for Internet connectivity");
        check(settings->get_DisallowStartIfOnBatteries(&flag));require(flag==VARIANT_FALSE,"Battery operation must allow startup");
        check(settings->get_StopIfGoingOnBatteries(&flag));require(flag==VARIANT_FALSE,"Battery transition cannot stop authentication");
        int priority{};check(settings->get_Priority(&priority));require(priority==4,"Use normal scheduling priority, not background priority");
        BSTR limit{};check(settings->get_ExecutionTimeLimit(&limit));require(std::wstring(limit)==L"PT0S","Long sessions must not be killed by Task Scheduler");SysFreeString(limit);
        ComPtr<ITriggerCollection> triggers;check(definition->get_Triggers(&triggers));LONG count{};check(triggers->get_Count(&count));require(count==1,"Exactly one logon trigger");
        ComPtr<ITrigger> trigger;check(triggers->get_Item(1,&trigger));ComPtr<ILogonTrigger> logon;check(trigger.As(&logon));
        BSTR delay{};check(logon->get_Delay(&delay));require(!delay || !*delay || std::wstring(delay)==L"PT0S","No logon startup delay");SysFreeString(delay);
        ComPtr<IPrincipal> principal;check(definition->get_Principal(&principal));TASK_LOGON_TYPE logon_type{};check(principal->get_LogonType(&logon_type));require(logon_type==TASK_LOGON_INTERACTIVE_TOKEN,"No stored user password or service account");
        TASK_RUNLEVEL_TYPE level{};check(principal->get_RunLevel(&level));require(level==TASK_RUNLEVEL_LUA,"No elevation for desktop startup");
        ComPtr<IActionCollection> actions;check(definition->get_Actions(&actions));ComPtr<IAction> action;check(actions->get_Item(1,&action));ComPtr<IExecAction> exec;check(action.As(&exec));
        BSTR path{},args{};check(exec->get_Path(&path));check(exec->get_Arguments(&args));
        require(std::wstring(path)==executable.wstring() && std::wstring(args)==L"--startup","XML escaping must preserve executable path and arguments");SysFreeString(path);SysFreeString(args);
        check(task->put_Enabled(VARIANT_FALSE));require(!startup_task_enabled(name),"A user-disabled task must stay disabled");
        configure_startup_task(true,executable,name);require(startup_task_enabled(name),"Explicit enabling restores the task");
        remove_owned_startup_task(executable.parent_path()/L"another-copy.exe",name);
        require(startup_task_enabled(name),"Uninstall must not remove another portable copy's startup");
        remove_owned_startup_task(executable,name);require(!startup_task_enabled(name),"Uninstall removes the matching executable only");
        configure_startup_task(true,executable,name);
        configure_startup_task(false,executable,name);require(!startup_task_enabled(name),"Disabling deletes only the test task");
        configure_startup_task(false,executable,name);
        std::cout<<"PASS: isolated logon registration, no delay, battery, no network prerequisite, priority, escaping, disable and cleanup\n";
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';CoUninitialize();return 1;}
    CoUninitialize();return 0;
}
