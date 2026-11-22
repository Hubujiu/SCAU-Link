[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -ReferencedAssemblies UIAutomationClient,UIAutomationTypes,WindowsBase -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Automation;
public static class PackageUiFixture {
    delegate bool Visitor(IntPtr window, IntPtr state);
    [DllImport("user32.dll")] static extern bool EnumWindows(Visitor visitor, IntPtr state);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, Visitor visitor, IntPtr state);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr window);
    [DllImport("user32.dll")] static extern IntPtr GetParent(IntPtr window);
    [DllImport("user32.dll")] static extern bool PostMessage(IntPtr window, uint message, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr SendMessage(IntPtr window, uint message, IntPtr wp, string text);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int capacity);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window, StringBuilder text, int capacity);
    static AutomationElement Dashboard(int pid) {
        IntPtr found=IntPtr.Zero;
        EnumWindows((window,state)=>{
            uint owner; GetWindowThreadProcessId(window,out owner);
            if(owner==(uint)pid) EnumChildWindows(window,(child,unused)=>{
                var kind=new StringBuilder(32);
                GetClassName(child,kind,kind.Capacity);
                if(kind.ToString()!="NshWindow" || !IsWindowVisible(child)) return true;
                found=child; return false;
            },IntPtr.Zero);
            return found==IntPtr.Zero;
        },IntPtr.Zero);
        return found==IntPtr.Zero ? null : AutomationElement.FromHandle(found);
    }
    public static string[] DashboardTexts(int pid) {
        var texts=new List<string>();
        try {
            var root=Dashboard(pid);
            if(root!=null) {
                foreach(AutomationElement element in root.FindAll(TreeScope.Descendants,Condition.TrueCondition)) {
                    texts.Add(element.Current.Name);
                }
            }
        } catch(ElementNotAvailableException) { }
        return texts.ToArray();
    }
    public static bool DashboardClick(int pid, string name) {
        try {
            var root=Dashboard(pid);
            if(root==null) return false;
            var condition=new AndCondition(new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.Button),
                                           new PropertyCondition(AutomationElement.NameProperty,name));
            var button=root.FindFirst(TreeScope.Descendants,condition);
            if(button==null || !button.Current.IsEnabled) return false;
            object pattern;
            if(!button.TryGetCurrentPattern(InvokePattern.Pattern,out pattern)) return false;
            ((InvokePattern)pattern).Invoke();
            return true;
        } catch(ElementNotAvailableException) { return false; }
    }
    public static string[] Texts(int pid) {
        var texts=new List<string>();
        Visitor child=(window,state)=>{
            var text=new StringBuilder(1024); GetWindowText(window,text,text.Capacity);
            texts.Add(text.ToString()); return true;
        };
        EnumWindows((window,state)=>{
            uint owner; GetWindowThreadProcessId(window,out owner);
            if(owner==(uint)pid) EnumChildWindows(window,child,IntPtr.Zero);
            return true;
        },IntPtr.Zero);
        return texts.ToArray();
    }
    public static IntPtr Control(int pid, int id) {
        IntPtr found=IntPtr.Zero;
        EnumWindows((window,state)=>{
            uint owner; GetWindowThreadProcessId(window,out owner);
            if(owner==(uint)pid) EnumChildWindows(window,(child,unused)=>{
                if(GetDlgCtrlID(child)!=id || !IsWindowVisible(child)) return true;
                found=child; return false;
            },IntPtr.Zero);
            return found==IntPtr.Zero;
        },IntPtr.Zero);
        return found;
    }
    public static bool Click(IntPtr handle) {
        return handle!=IntPtr.Zero && PostMessage(GetParent(handle),0x0111,(IntPtr)GetDlgCtrlID(handle),handle);
    }
    public static bool Input(IntPtr handle, string text) {
        return handle!=IntPtr.Zero && SendMessage(handle,0x000c,IntPtr.Zero,text)!=IntPtr.Zero;
    }
    public static bool EndDemoSession(int pid) {
        bool posted=false;
        EnumWindows((window,state)=>{
            uint owner; GetWindowThreadProcessId(window,out owner);
            var title=new StringBuilder(64); GetWindowText(window,title,title.Capacity);
            if(owner!=(uint)pid || !title.ToString().StartsWith("SCAU Link")) return true;
            posted=PostMessage(window,0x0016,(IntPtr)1,IntPtr.Zero);
            return !posted;
        },IntPtr.Zero);
        return posted;
    }
}
'@
function Wait-UiCondition([scriptblock]$Condition) {
    $limit=[DateTime]::UtcNow.AddSeconds(5)
    while([DateTime]::UtcNow -lt $limit -and -not $taskProcess.HasExited) {
        if(& $Condition){return}
        Start-Sleep -Milliseconds 75
    }
    throw 'The native account test did not reach the expected control state.'
}
$rejected=-join (@(0x672A,0x901A,0x8FC7) | ForEach-Object {[char]$_})
$accepted=-join (@(0x6D4B,0x8BD5,0x901A,0x8FC7) | ForEach-Object {[char]$_})
$login=-join (@(0x767B,0x5F55) | ForEach-Object {[char]$_})
foreach($layout in @('regular','mini')) {
    $taskArgs=@('--demo-first-run')
    if($layout -eq 'mini'){$taskArgs+='--mini'}
    $taskProcess=Start-Process -FilePath $Executable -ArgumentList $taskArgs -WindowStyle Hidden -PassThru
    try {
        Wait-UiCondition { [PackageUiFixture]::DashboardClick($taskProcess.Id,$login) }
        Wait-UiCondition { [PackageUiFixture]::Control($taskProcess.Id,252) -ne [IntPtr]::Zero }
        $account=[PackageUiFixture]::Control($taskProcess.Id,131)
        $network=[PackageUiFixture]::Control($taskProcess.Id,133)
        $portal=[PackageUiFixture]::Control($taskProcess.Id,251)
        $test=[PackageUiFixture]::Control($taskProcess.Id,252)
        if(-not ([PackageUiFixture]::Input($account,'20260099') -and [PackageUiFixture]::Input($network,'demo-only') -and
                 [PackageUiFixture]::Input($portal,'demo-only') -and [PackageUiFixture]::Click($test))) {
            throw "Could not fill the native $layout account editor."
        }
        Wait-UiCondition { [PackageUiFixture]::Texts($taskProcess.Id) -like "*$rejected*" }
        if(-not ([PackageUiFixture]::Input($portal,'demo-portal') -and [PackageUiFixture]::Click($test))) {
            throw "Could not test the independent portal password in the $layout editor."
        }
        Wait-UiCondition { [PackageUiFixture]::Texts($taskProcess.Id) -like "$accepted*" }
        Write-Output "PASS: native portal password test $layout"
    } finally {
        if(-not $taskProcess.HasExited){Stop-Process -Id $taskProcess.Id -Force}
        $taskProcess.Dispose()
    }
}
$taskUnknown=-join (@(0x8D26,0x53F7,0x672A,0x786E,0x8BA4) | ForEach-Object {[char]$_})
foreach($taskMode in @('--demo-network-only','--demo-1x')) {
    $taskProcess=Start-Process -FilePath $Executable -ArgumentList @('--demo-package',$taskMode) -WindowStyle Hidden -PassThru
    try {
        $taskDeadline=[DateTime]::UtcNow.AddSeconds(12)
        $taskReady=$false
        while([DateTime]::UtcNow -lt $taskDeadline -and -not $taskProcess.HasExited) {
            $taskTexts=[PackageUiFixture]::DashboardTexts($taskProcess.Id)
            $taskBalance=@($taskTexts | Where-Object {$_ -like '*136.50*'}).Count -gt 0
            $taskUnconfirmed=@($taskTexts | Where-Object {$_ -like "*$taskUnknown*20260088*"}).Count -gt 0
            if($taskBalance -and ($taskMode -ne '--demo-network-only' -or $taskUnconfirmed)) {$taskReady=$true;break}
            Start-Sleep -Milliseconds 100
        }
        if(-not $taskReady){throw "Billing never appeared in the native application: $taskMode"}
        Write-Output "PASS: native billing display $taskMode"
    } finally {
        if(-not $taskProcess.HasExited){Stop-Process -Id $taskProcess.Id -Force}
        $taskProcess.Dispose()
    }
}
$connect=-join (@(0x8FDE,0x63A5) | ForEach-Object {[char]$_})
$disconnect=(-join (@(0x65AD,0x5F00) | ForEach-Object {[char]$_}))+$connect
$online=([char]0x5DF2)+$connect
$offline=([char]0x672A)+$connect
$web=(-join (@(0x65E0,0x7EBF) | ForEach-Object {[char]$_}))+' Web'
$selected=([char]0x2713)+' '+$web
$taskProcess=Start-Process -FilePath $Executable -ArgumentList '--demo' -WindowStyle Hidden -PassThru
try {
    Wait-UiCondition { [PackageUiFixture]::DashboardClick($taskProcess.Id,$web) }
    Wait-UiCondition { [PackageUiFixture]::DashboardTexts($taskProcess.Id) -contains $selected }
    Wait-UiCondition { [PackageUiFixture]::DashboardClick($taskProcess.Id,$connect) }
    Wait-UiCondition { [PackageUiFixture]::DashboardTexts($taskProcess.Id) -contains $online }
    Wait-UiCondition { [PackageUiFixture]::DashboardClick($taskProcess.Id,$disconnect) }
    Wait-UiCondition { [PackageUiFixture]::DashboardTexts($taskProcess.Id) -contains $offline }
    if (-not [PackageUiFixture]::EndDemoSession($taskProcess.Id)) { throw 'The demo window did not accept shutdown.' }
    if (-not $taskProcess.WaitForExit(5000)) { throw 'The NSH demo did not exit after shutdown.' }
    if ($taskProcess.ExitCode -ne 0) { throw "The NSH demo exited with code $($taskProcess.ExitCode)." }
    Write-Output 'PASS: NSH connection mode, connect, disconnect and shutdown'
} finally {
    if(-not $taskProcess.HasExited){Stop-Process -Id $taskProcess.Id -Force}
    $taskProcess.Dispose()
}
