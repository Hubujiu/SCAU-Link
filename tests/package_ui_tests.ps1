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
}
'@
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
