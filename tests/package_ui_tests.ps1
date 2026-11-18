[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
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
foreach($layout in @('regular','mini')) {
    $taskArgs=@('--demo-first-run')
    if($layout -eq 'mini'){$taskArgs+='--mini'}
    $taskProcess=Start-Process -FilePath $Executable -ArgumentList $taskArgs -WindowStyle Hidden -PassThru
    try {
        Wait-UiCondition { [PackageUiFixture]::Click([PackageUiFixture]::Control($taskProcess.Id,104)) }
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
            $taskTexts=[PackageUiFixture]::Texts($taskProcess.Id)
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
