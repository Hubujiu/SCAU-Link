#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RunDirectory,
    [ValidateRange(10,86400)][int]$DurationSeconds=1800,
    [string]$ProfilePath
)
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskRunDirectory=[IO.Path]::GetFullPath($RunDirectory)
if(Test-Path -LiteralPath $taskRunDirectory){
    if(@(Get-ChildItem -LiteralPath $taskRunDirectory -Force).Count -gt 0){
        throw 'RunDirectory must be empty. Use a new directory for each authentication test.'
    }
}
New-Item -ItemType Directory -Path $taskRunDirectory -Force | Out-Null
$taskOriginalRoot='D:\Apps\Network\Ruijie Networks\Ruijie Supplicant'
$taskExecutable=Join-Path $taskRoot 'build\Release\scau-auth.exe'
if(-not (Test-Path -LiteralPath $taskExecutable)){$taskExecutable=Join-Path $taskRoot 'scau-auth.exe'}
if(-not (Test-Path -LiteralPath $taskExecutable)){throw 'Build scau-auth or use the packaged executable.'}
$taskProfile=if($ProfilePath){[IO.Path]::GetFullPath($ProfilePath)}else{Join-Path $taskRoot 'captures\20261112-164221\eapol-only.pcapng'}
if(-not (Test-Path -LiteralPath $taskProfile)){throw 'The private EAPOL profile was not found. Specify -ProfilePath.'}
$taskEvents=Join-Path $taskRunDirectory 'events.jsonl'
$taskSupervisorEvents=$taskEvents+'.supervisor.jsonl'
$taskGateName='Local\ScauNativeGo-'+[Guid]::NewGuid().ToString('N')
$taskStopName='Local\ScauNativeStop-'+[Guid]::NewGuid().ToString('N')
$taskProcess=$null
$taskOriginalProcesses=@()
$taskServiceWasRunning=$false
$taskSwitched=$false
$taskServiceStopped=$false
$taskSuspendedThreads=New-Object 'System.Collections.Generic.List[System.IntPtr]'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ScauThreadControl {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenThread(uint access, bool inherit, uint threadId);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint SuspendThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
'@
function Suspend-TaskService {
    $taskServiceInfo=Get-CimInstance Win32_Service -Filter "Name='RJSuService'"
    if(-not $taskServiceInfo -or $taskServiceInfo.ProcessId -eq 0){throw 'Original supervisor process was not found.'}
    $taskSupervisor=Get-Process -Id $taskServiceInfo.ProcessId
    foreach($taskThread in $taskSupervisor.Threads){
        $taskThreadHandle=[ScauThreadControl]::OpenThread(2,$false,[uint32]$taskThread.Id)
        if($taskThreadHandle -eq [IntPtr]::Zero){throw 'Cannot open an original supervisor thread.'}
        if([ScauThreadControl]::SuspendThread($taskThreadHandle) -eq [uint32]::MaxValue){[ScauThreadControl]::CloseHandle($taskThreadHandle)|Out-Null;throw 'Cannot suspend an original supervisor thread.'}
        $taskSuspendedThreads.Add($taskThreadHandle)
    }
}
function Resume-TaskService {
    foreach($taskThreadHandle in $taskSuspendedThreads){
        [ScauThreadControl]::ResumeThread($taskThreadHandle)|Out-Null
        [ScauThreadControl]::CloseHandle($taskThreadHandle)|Out-Null
    }
    $taskSuspendedThreads.Clear()
}
$taskResult=[ordered]@{started_at=(Get-Date).ToString('o');duration_seconds=$DurationSeconds;phase='starting';native_state=$null;native_connected=$false;native_process_id=$null;stop_event=$taskStopName;observation_passed=$null;observation_delayed=$false;native_exit_code=$null;original_process_started=$null;original_authentication_verified=$null;original_authenticated_at=$null;original_restored=$null;error=$null;ended_at=$null}
function Save-TaskStatus {
    $taskResult | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskRunDirectory 'status.json') -Encoding utf8
}
function Read-TaskNativeState([string]$EventsPath,[string]$SupervisorPath) {
    $taskWorkerState=$null;$taskSupervisorState=$null
    if(Test-Path -LiteralPath $EventsPath){
        $taskWorkerState=Get-Content -LiteralPath $EventsPath -Tail 64 | ForEach-Object {try{$_ | ConvertFrom-Json}catch{}} | Where-Object event -eq 'connection_state' | Select-Object -Last 1
    }
    $taskSupervisorStates=@{
        worker_started='worker-starting';worker_crashed='worker-restarting';worker_restart_scheduled='worker-restarting'
        worker_authenticated='connected';worker_unauthenticated='worker-recovering';worker_terminal='worker-exited'
        supervisor_stopped='stopped';supervisor_retry_exhausted='failed';supervisor_protocol_error='failed';supervisor_error='failed'
    }
    if(Test-Path -LiteralPath $SupervisorPath){
        $taskSupervisorState=Get-Content -LiteralPath $SupervisorPath -Tail 64 | ForEach-Object {try{$_ | ConvertFrom-Json}catch{}} | Where-Object {$taskSupervisorStates.ContainsKey([string]$_.event)} | Select-Object -Last 1
    }
    if($taskSupervisorState -and (-not $taskWorkerState -or [datetimeoffset]$taskSupervisorState.time -ge [datetimeoffset]$taskWorkerState.time)){
        return [pscustomobject]@{time=$taskSupervisorState.time;detail=$taskSupervisorStates[[string]$taskSupervisorState.event];value=[int]($taskSupervisorState.event -eq 'worker_authenticated')}
    }
    return $taskWorkerState
}
function Read-TaskAuthSuccess([string]$LogPath,[long]$Offset,[datetime]$After) {
    if(-not (Test-Path -LiteralPath $LogPath)){return $null}
    $taskStream=[IO.File]::Open($LogPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try{
        if($taskStream.Length -lt $Offset){$Offset=0}
        [void]$taskStream.Seek($Offset,[IO.SeekOrigin]::Begin)
        $taskReader=New-Object IO.StreamReader($taskStream,[Text.Encoding]::GetEncoding(936))
        try{$taskNewLog=$taskReader.ReadToEnd()}finally{$taskReader.Dispose()}
    }finally{$taskStream.Dispose()}
    foreach($taskLine in ($taskNewLog -split "`n")){
        if($taskLine -notmatch 'AUTH_SUCCESS'){continue}
        $taskMatch=[regex]::Match($taskLine,'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
        if($taskMatch.Success){
            $taskAuthTime=[datetime]::ParseExact($taskMatch.Value,'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture)
            if($taskAuthTime -ge $After.AddSeconds(-1)){return $taskAuthTime.ToString('o')}
        }
    }
    return $null
}
try {
    $taskService=Get-Service -Name 'RJSuService' -ErrorAction SilentlyContinue
    $taskServiceWasRunning=$taskService -and $taskService.Status -eq 'Running'
    $taskOriginalProcesses=@(Get-CimInstance Win32_Process -Filter "Name='8021x.exe'" | Where-Object {$_.ExecutablePath -eq (Join-Path $taskOriginalRoot '8021x.exe')})
    $taskResult.original_process_ids=@($taskOriginalProcesses | ForEach-Object {$_.ProcessId})
    if($taskServiceWasRunning){
        try{Suspend-TaskService}finally{Resume-TaskService}
    }
    $taskArgs=@('--profile',$taskProfile,'--connect','--duration',[string]$DurationSeconds,'--log',$taskEvents,'--capture',(Join-Path $taskRunDirectory 'authentication.pcapng'),'--gate-event',$taskGateName,'--stop-event',$taskStopName)
    $taskArgumentLine=($taskArgs | ForEach-Object {'"'+$_+'"'}) -join ' '
    $taskProcess=Start-Process -FilePath $taskExecutable -ArgumentList $taskArgumentLine -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $taskRunDirectory 'stdout.log') -RedirectStandardError (Join-Path $taskRunDirectory 'stderr.log')
    $taskProcessHandle=$taskProcess.Handle
    $taskResult.native_process_id=$taskProcess.Id
    $taskResult.phase='waiting_for_local_credentials';Save-TaskStatus
    $taskDeadline=(Get-Date).AddMinutes(5)
    $taskReady=$false
    while((Get-Date) -lt $taskDeadline -and -not $taskProcess.HasExited) {
        if((Test-Path -LiteralPath $taskEvents) -and (Select-String -LiteralPath $taskEvents -SimpleMatch '"event":"credentials_ready"' -Quiet)) {$taskReady=$true;break}
        Start-Sleep -Seconds 1
    }
    if(-not $taskReady){throw 'Native client did not receive local credentials; original connection was kept.'}
    $taskResult.phase='switching_to_native_core';Save-TaskStatus
    $taskSwitched=$true
    if($taskServiceWasRunning){
        if($taskService.CanStop){
            try{Stop-Service -Name 'RJSuService' -ErrorAction Stop;$taskServiceStopped=$true}catch{Suspend-TaskService}
        }else{Suspend-TaskService}
    }
    foreach($taskOriginalProcess in $taskOriginalProcesses){
        if(Get-Process -Id $taskOriginalProcess.ProcessId -ErrorAction SilentlyContinue){
            Stop-Process -Id $taskOriginalProcess.ProcessId -Force -ErrorAction Stop
            Wait-Process -Id $taskOriginalProcess.ProcessId -Timeout 15 -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500
    $taskRemaining=@(Get-CimInstance Win32_Process -Filter "Name='8021x.exe'")
    if($taskRemaining.Count -gt 0){throw 'An original authentication process is still running after the controlled switch.'}
    $taskGate=[Threading.EventWaitHandle]::OpenExisting($taskGateName)
    try{$taskGate.Set()|Out-Null}finally{$taskGate.Dispose()}
    $taskResult.phase='authenticating_and_monitoring';Save-TaskStatus
    $taskDeadline=(Get-Date).AddSeconds($DurationSeconds+90)
    $taskObservationReported=$false
    while(-not $taskProcess.HasExited){
        $taskStateEvent=Read-TaskNativeState $taskEvents $taskSupervisorEvents
        if($taskStateEvent -and $taskStateEvent.detail -ne $taskResult.native_state){
            $taskResult.native_state=$taskStateEvent.detail
            $taskResult.native_connected=($taskStateEvent.value -eq 1);Save-TaskStatus
        }
        if(-not $taskObservationReported -and (Select-String -LiteralPath $taskEvents -SimpleMatch '"event":"online_test_holding_connection"' -Quiet)){
            $taskRecordedEvents=@(Get-Content -LiteralPath $taskEvents | ConvertFrom-Json)
            $taskProbeCount=($taskRecordedEvents | Where-Object event -eq 'probe_count' | Select-Object -Last 1).value
            $taskProbeFailures=($taskRecordedEvents | Where-Object event -eq 'probe_failure_count' | Select-Object -Last 1).value
            $taskMaintenanceSupported=($taskRecordedEvents | Where-Object event -eq 'maintenance_supported' | Select-Object -Last 1).value
            $taskResult.observation_passed=($taskProbeCount -gt 0 -and $taskProbeFailures -eq 0 -and $taskMaintenanceSupported -eq 1)
            $taskResult.phase=if($taskResult.observation_passed){'online_test_passed_connection_held'}else{'online_test_failed_connection_held'}
            $taskObservationReported=$true;Save-TaskStatus
        }
        if(-not $taskObservationReported -and -not $taskResult.observation_delayed -and (Get-Date) -gt $taskDeadline){
            # Link recovery can restart the observation window. A reporting
            # deadline must never turn into an unsolicited network disconnect.
            $taskResult.observation_delayed=$true
            $taskResult.phase='observation_delayed_connection_retained';Save-TaskStatus
        }
        Start-Sleep -Seconds 2
    }
    $taskProcess.WaitForExit()
    $taskResult.native_exit_code=$taskProcess.ExitCode
    if($taskProcess.ExitCode -eq 2){$taskResult.phase='cancelled'}
    elseif($taskProcess.ExitCode -ne 0){throw "Native authentication test exited with code $($taskProcess.ExitCode)."}
    else{$taskResult.phase='disconnected'}
}catch{
    $taskResult.error=$_.Exception.Message
    $taskResult.phase='failed'
}finally{
    if($taskProcess -and -not $taskProcess.HasExited){Stop-Process -Id $taskProcess.Id -Force -ErrorAction SilentlyContinue}
    if($taskSwitched){
        try{
            $taskOriginalUiLog=Join-Path $taskOriginalRoot 'logs\ui.log'
            $taskRestoreOffset=if(Test-Path -LiteralPath $taskOriginalUiLog){(Get-Item -LiteralPath $taskOriginalUiLog).Length}else{0}
            $taskRestoreStarted=Get-Date
            Resume-TaskService
            if($taskServiceStopped){Start-Service -Name 'RJSuService' -ErrorAction Stop}
            Start-Sleep -Seconds 2
            if($taskOriginalProcesses.Count -gt 0 -and -not (Get-Process -Name '8021x' -ErrorAction SilentlyContinue)){
                Start-Process -FilePath (Join-Path $taskOriginalRoot '8021x.exe') -WindowStyle Hidden
            }
            $taskResult.original_process_started=[bool](Get-Process -Name '8021x' -ErrorAction SilentlyContinue)
            if($taskOriginalProcesses.Count -gt 0){
                $taskResult.original_authentication_verified=$false
                $taskResult.original_restored=$false
                $taskResult.phase='awaiting_original_authentication';Save-TaskStatus
                $taskRestoreDeadline=(Get-Date).AddSeconds(20)
                while((Get-Date) -lt $taskRestoreDeadline){
                    $taskAuthTime=Read-TaskAuthSuccess $taskOriginalUiLog $taskRestoreOffset $taskRestoreStarted
                    if($taskAuthTime){
                        $taskResult.original_authentication_verified=$true
                        $taskResult.original_authenticated_at=$taskAuthTime
                        $taskResult.original_restored=$true
                        $taskResult.phase='original_connection_restored'
                        break
                    }
                    Start-Sleep -Seconds 1
                }
                if(-not $taskResult.original_authentication_verified){
                    $taskResult.phase='original_authentication_required'
                    $taskResult.error=([string]$taskResult.error)+' Original client started, but a new AUTH_SUCCESS was not observed. Connect it manually.'
                    Start-Process -FilePath (Join-Path $taskOriginalRoot '8021x.exe') -WindowStyle Normal
                }
            }else{$taskResult.original_restored=$true}
        }catch{
            $taskResult.original_restored=$false
            $taskResult.error=([string]$taskResult.error)+' Restore failed: '+$_.Exception.Message
        }
    }else{Resume-TaskService;$taskResult.original_restored=$true}
    $taskResult.ended_at=(Get-Date).ToString('o');Save-TaskStatus
}
if($taskResult.error){exit 1}
exit 0
