#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RunDirectory,
    [Parameter(Mandatory=$true)][string]$ExpectedUserSid,
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [Parameter(Mandatory=$true)][int]$ExistingDesktopId,
    [ValidateRange(60,86400)][int]$ObservationSeconds=600
)

# Run independently of the terminal. A successful observation never closes the
# working connection. The controller remains as the original-client restorer.
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskRun=[IO.Path]::GetFullPath($RunDirectory)
$taskDesktop=Join-Path $taskRoot 'out\scau-link-0.6.5-win-x64\SCAU-Link.exe'
$taskCore=Join-Path (Split-Path $taskDesktop) 'scau-auth.exe'
$taskOriginalRoot='D:\Apps\Network\Ruijie Networks\Ruijie Supplicant'
$taskOriginal=Join-Path $taskOriginalRoot '8021x.exe'
$taskData=Join-Path $env:LOCALAPPDATA 'ScauLink'
$taskDesktopLog=Join-Path $taskData 'logs\desktop.jsonl'
$taskEvents=Join-Path $taskRun 'controller-events.jsonl'
$taskStatus=Join-Path $taskRun 'status.json'
$taskDesktopProcess=$null
$taskSwitched=$false
$taskSuspended=New-Object 'System.Collections.Generic.List[System.IntPtr]'
$taskInitialLogs=@{}
$taskDesktopOffset=0L
$taskDesktopEvents=@()
$taskResult=[ordered]@{
    started_at=[DateTimeOffset]::UtcNow.ToString('o');controller_process_id=$PID
    phase='preflight';desktop_process_id=$null;observation_seconds=$ObservationSeconds
    initial_authenticated_at=$null;crash_injected_at=$null;crashed_worker_id=$null
    recovered_authenticated_at=$null;recovered_worker_id=$null;recovery_milliseconds=$null
    observation_started_at=$null;observation_completed_at=$null
    probe_successes=0;probe_failures=0;observation_probe_successes=0;observation_probe_failures=0
    initial_authentication_passed=$false;crash_recovery_passed=$false;observation_passed=$false
    connection_held=$false;sam=$null;worker_event_counts=$null;desktop_event_counts=$null
    original_supervisor_suspended=$false;original_authentication_verified=$null
    original_restored=$null;release_event='Local\ScauDesktopRestore-'+[Guid]::NewGuid().ToString('N')
    error=$null;ended_at=$null
}
function Save-TaskStatus {
    [IO.File]::WriteAllText($taskStatus,($taskResult|ConvertTo-Json -Depth 7),(New-Object Text.UTF8Encoding($false)))
}
function Write-TaskEvent([string]$Name,[object]$Value=$null) {
    $taskEntry=[ordered]@{time=[DateTimeOffset]::UtcNow.ToString('o');event=$Name}
    if($null -ne $Value){$taskEntry.value=$Value}
    [IO.File]::AppendAllText($taskEvents,(($taskEntry|ConvertTo-Json -Compress)+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
}
function Read-TaskJson([string]$Path,[long]$Offset=0) {
    if(-not (Test-Path -LiteralPath $Path)){return}
    $taskStream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        if($taskStream.Length -lt $Offset){$Offset=0}
        [void]$taskStream.Seek($Offset,[IO.SeekOrigin]::Begin)
        $taskReader=New-Object IO.StreamReader($taskStream,[Text.Encoding]::UTF8)
        try{$taskText=$taskReader.ReadToEnd()}finally{$taskReader.Dispose()}
    }finally{$taskStream.Dispose()}
    foreach($taskLine in ($taskText -split "`n")){
        if($taskLine.Trim()){try{$taskLine|ConvertFrom-Json}catch{}}
    }
}
function Read-TaskDesktopEvents {
    @(Read-TaskJson $taskDesktopLog $taskDesktopOffset)
}
function Get-TaskExactProcess([int]$ProcessId,[string]$Path) {
    $taskCandidate=Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId"
    if($taskCandidate -and [string]::Equals($taskCandidate.ExecutablePath,$Path,[StringComparison]::OrdinalIgnoreCase)){
        return $taskCandidate
    }
    return $null
}
function Stop-TaskExactProcess([int]$ProcessId,[string]$Path) {
    if(-not (Get-TaskExactProcess $ProcessId $Path)){throw 'Process identity changed; refusing to terminate it.'}
    Stop-Process -Id $ProcessId -Force -ErrorAction Stop
    Wait-Process -Id $ProcessId -Timeout 15 -ErrorAction SilentlyContinue
}
function Get-TaskWorker {
    $taskWorkers=@(Get-CimInstance Win32_Process -Filter "Name='scau-auth.exe'" | Where-Object {
        $_.ParentProcessId -eq $taskDesktopProcess.Id -and
        [string]::Equals($_.ExecutablePath,$taskCore,[StringComparison]::OrdinalIgnoreCase) -and
        $_.CommandLine -match '--worker-input' -and $_.CommandLine -match '--worker-output'
    })
    if($taskWorkers.Count -ne 1){throw 'Expected exactly one private authentication worker belonging to this desktop.'}
    return $taskWorkers[0]
}
function Invoke-TaskProbe([string]$Phase) {
    $taskOutput=Join-Path $taskRun 'last-probe.jsonl'
    $taskProbeArgs='"'+(Join-Path $PSScriptRoot 'probe_ethernet.py')+'" --count 1'
    $taskProbe=Start-Process -FilePath $PythonPath -ArgumentList $taskProbeArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $taskOutput -RedirectStandardError (Join-Path $taskRun 'probe-stderr.log')
    if(-not $taskProbe.WaitForExit(35000)){
        $taskProbe.Kill();$taskProbe.WaitForExit()
        $taskProbeEvent=[pscustomobject]@{time=[DateTimeOffset]::UtcNow.ToString('o');event='ethernet_direct_probe_failed';failed_stage='probe_timeout'}
    }else{
        $taskProbe.WaitForExit()
        $taskProbeEvent=Read-TaskJson $taskOutput | Select-Object -Last 1
        if(-not $taskProbeEvent){
            $taskProbeEvent=[pscustomobject]@{time=[DateTimeOffset]::UtcNow.ToString('o');event='ethernet_direct_probe_failed';failed_stage='probe_process'}
        }
    }
    $taskProbeEvent|Add-Member -NotePropertyName phase -NotePropertyValue $Phase -Force
    [IO.File]::AppendAllText((Join-Path $taskRun 'connectivity.jsonl'),(($taskProbeEvent|ConvertTo-Json -Compress)+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
    return $taskProbeEvent
}
function Update-TaskEvidence {
    $taskCounts=[ordered]@{}
    foreach($taskGroup in (@(Read-TaskDesktopEvents)|Group-Object event)){$taskCounts[$taskGroup.Name]=$taskGroup.Count}
    $taskResult.desktop_event_counts=$taskCounts
    $taskWorkerEvents=@(Get-ChildItem -LiteralPath (Join-Path $taskData 'logs') -Filter 'session-*.jsonl' -File | Where-Object {-not $taskInitialLogs.ContainsKey($_.FullName)} | ForEach-Object {Read-TaskJson $_.FullName})
    $taskWorkerCounts=[ordered]@{}
    foreach($taskGroup in ($taskWorkerEvents|Group-Object event)){$taskWorkerCounts[$taskGroup.Name]=$taskGroup.Count}
    $taskResult.worker_event_counts=$taskWorkerCounts
    $taskResult.sam=[ordered]@{
        channel_configured=@($taskWorkerEvents|Where-Object event -eq 'sam_channel_configured').Count
        transport_ready=@($taskWorkerEvents|Where-Object event -eq 'sam_transport_ready').Count
        hello_intervals=@($taskWorkerEvents|Where-Object event -eq 'sam_hello_interval_seconds'|ForEach-Object value)
        send_confirmed=@($taskWorkerEvents|Where-Object event -eq 'sam_send_confirmed').Count
        verified_server_messages=@($taskWorkerEvents|Where-Object event -eq 'sam_verified_server_message').Count
        send_failed=@($taskWorkerEvents|Where-Object event -eq 'sam_send_failed').Count
        packet_expired=@($taskWorkerEvents|Where-Object event -eq 'sam_packet_expired').Count
    }
}
function Read-TaskOriginalSuccess([long]$Offset,[datetime]$After) {
    $taskUiLog=Join-Path $taskOriginalRoot 'logs\ui.log'
    if(-not (Test-Path -LiteralPath $taskUiLog)){return $null}
    $taskStream=[IO.File]::Open($taskUiLog,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try{
        if($taskStream.Length -lt $Offset){$Offset=0}
        [void]$taskStream.Seek($Offset,[IO.SeekOrigin]::Begin)
        $taskReader=New-Object IO.StreamReader($taskStream,[Text.Encoding]::GetEncoding(936))
        try{$taskText=$taskReader.ReadToEnd()}finally{$taskReader.Dispose()}
    }finally{$taskStream.Dispose()}
    foreach($taskLine in ($taskText -split "`n")){
        if($taskLine -notmatch 'AUTH_SUCCESS'){continue}
        $taskMatch=[regex]::Match($taskLine,'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
        if($taskMatch.Success -and [datetime]::ParseExact($taskMatch.Value,'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture) -ge $After.AddSeconds(-1)){return $true}
    }
    return $false
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ScauDesktopTestThread {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenThread(uint access, bool inherit, uint threadId);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint SuspendThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
'@
function Resume-TaskOriginalSupervisor {
    foreach($taskHandle in $taskSuspended){
        [ScauDesktopTestThread]::ResumeThread($taskHandle)|Out-Null
        [ScauDesktopTestThread]::CloseHandle($taskHandle)|Out-Null
    }
    $taskSuspended.Clear();$taskResult.original_supervisor_suspended=$false
}
$taskRelease=$null
try {
    if(-not (Test-Path -LiteralPath $taskRun -PathType Container)){throw 'Preflight run directory is missing.'}
    Save-TaskStatus
    if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $ExpectedUserSid){throw 'Elevation changed Windows identity; original connection was kept.'}
    if((Get-FileHash -LiteralPath $taskDesktop -Algorithm SHA256).Hash -ne '054CF4ACFD36DE1D7138E64C75BB5DB2CC50010A6DF5243E22527BAE44659FCE'){throw 'Desktop release hash mismatch.'}
    if((Get-FileHash -LiteralPath $taskCore -Algorithm SHA256).Hash -ne '957C078472390749E7FDF5A3FDC2FDED172F31E14BAD9AC299CA563C0F5F9A7C'){throw 'Authentication core hash mismatch.'}
    $taskCatalog=[IO.File]::ReadAllBytes((Join-Path $taskData 'accounts.dat'))
    if($taskCatalog.Length -lt 12 -or [Text.Encoding]::ASCII.GetString($taskCatalog,0,8) -ne 'SCAUAC02' -or [BitConverter]::ToUInt32($taskCatalog,8) -lt 1){throw 'No saved account catalog was found.'}
    [Array]::Clear($taskCatalog,0,$taskCatalog.Length);$taskCatalog=$null
    if(-not (Test-Path -LiteralPath (Join-Path $taskData 'profile.scau'))){throw 'Private local network profile is missing.'}
    if(@(Get-CimInstance Win32_Process -Filter "Name='scau-auth.exe'").Count -ne 0){throw 'An existing authentication worker is active; original connection was kept.'}
    $taskOldDesktop=Get-TaskExactProcess $ExistingDesktopId $taskDesktop
    if(-not $taskOldDesktop -or $taskOldDesktop.CommandLine -match '--demo'){throw 'The expected real desktop process was not found.'}
    $taskOriginals=@(Get-CimInstance Win32_Process -Filter "Name='8021x.exe'")
    if($taskOriginals.Count -lt 1 -or @($taskOriginals|Where-Object {-not [string]::Equals($_.ExecutablePath,$taskOriginal,[StringComparison]::OrdinalIgnoreCase)}).Count){throw 'Original client process identity could not be verified.'}
    $taskService=Get-CimInstance Win32_Service -Filter "Name='RJSuService'"
    $taskSupervisor=Get-TaskExactProcess ([int]$taskService.ProcessId) (Join-Path $taskOriginalRoot 'SuService.exe')
    if(-not $taskSupervisor -or $taskService.State -ne 'Running'){throw 'Original supervisor identity could not be verified.'}
    $taskBaseline=Invoke-TaskProbe 'before_switch'
    if($taskBaseline.event -ne 'ethernet_direct_probe_ok' -or -not $taskBaseline.original_client_present){throw 'Original physical Ethernet baseline failed.'}
    Get-ChildItem -LiteralPath (Join-Path $taskData 'logs') -Filter 'session-*.jsonl' -File|ForEach-Object {$taskInitialLogs[$_.FullName]=$true}
    $taskRelease=New-Object Threading.EventWaitHandle($false,[Threading.EventResetMode]::ManualReset,$taskResult.release_event)
    Write-TaskEvent 'preflight_passed'
    Stop-TaskExactProcess $ExistingDesktopId $taskDesktop
    $taskDesktopOffset=if(Test-Path -LiteralPath $taskDesktopLog){(Get-Item -LiteralPath $taskDesktopLog).Length}else{0L}
    $taskResult.phase='switching';Save-TaskStatus
    $taskSwitched=$true
    foreach($taskThread in (Get-Process -Id $taskSupervisor.ProcessId).Threads){
        $taskHandle=[ScauDesktopTestThread]::OpenThread(2,$false,[uint32]$taskThread.Id)
        if($taskHandle -eq [IntPtr]::Zero){throw 'Cannot open original supervisor thread.'}
        if([ScauDesktopTestThread]::SuspendThread($taskHandle) -eq [uint32]::MaxValue){[ScauDesktopTestThread]::CloseHandle($taskHandle)|Out-Null;throw 'Cannot pause original supervisor thread.'}
        $taskSuspended.Add($taskHandle)
    }
    if($taskSuspended.Count -lt 1){throw 'No original supervisor threads were paused.'}
    $taskResult.original_supervisor_suspended=$true
    foreach($taskOriginalProcess in $taskOriginals){Stop-TaskExactProcess $taskOriginalProcess.ProcessId $taskOriginal}
    if(@(Get-CimInstance Win32_Process -Filter "Name='8021x.exe'").Count){throw 'An original authentication process remained after handoff.'}
    Write-TaskEvent 'original_handoff_complete'
    $taskDesktopProcess=Start-Process -FilePath $taskDesktop -WorkingDirectory (Split-Path $taskDesktop) -PassThru
    $taskDesktopHandle=$taskDesktopProcess.Handle
    $taskResult.desktop_process_id=$taskDesktopProcess.Id
    $taskResult.phase='awaiting_initial_authentication';Save-TaskStatus
    $taskDeadline=[DateTimeOffset]::UtcNow.AddSeconds(90)
    while([DateTimeOffset]::UtcNow -lt $taskDeadline){
        if($taskDesktopProcess.HasExited){throw 'Desktop exited before authenticating.'}
        $taskDesktopEvents=@(Read-TaskDesktopEvents)
        $taskAuth=$taskDesktopEvents|Where-Object event -eq 'worker_authenticated'|Select-Object -First 1
        if($taskAuth){$taskResult.initial_authenticated_at=$taskAuth.time;break}
        if(@($taskDesktopEvents|Where-Object {$_.event -in @('worker_terminal','accounts_exhausted','desktop_authentication_error','original_client_conflict')}).Count){throw 'Initial authentication failed; see sanitized event counts.'}
        Start-Sleep -Milliseconds 500
    }
    if(-not $taskResult.initial_authenticated_at){throw 'Initial authentication timed out.'}
    $taskResult.phase='checking_initial_ethernet';Save-TaskStatus
    for($taskIndex=0;$taskIndex -lt 2;$taskIndex++){
        $taskProbeEvent=Invoke-TaskProbe 'initial_authenticated'
        if($taskProbeEvent.event -ne 'ethernet_direct_probe_ok' -or $taskProbeEvent.original_client_present){throw 'Initial authentication did not provide independent physical Ethernet access.'}
        $taskResult.probe_successes++
        if($taskIndex -eq 0){Start-Sleep -Seconds 7}
    }
    $taskResult.initial_authentication_passed=$true
    $taskWorker=Get-TaskWorker
    $taskResult.crash_injected_at=[DateTimeOffset]::UtcNow.ToString('o')
    $taskResult.crashed_worker_id=$taskWorker.ProcessId
    $taskResult.phase='awaiting_worker_crash_recovery';Save-TaskStatus
    Write-TaskEvent 'worker_crash_injected' $taskWorker.ProcessId
    Stop-TaskExactProcess $taskWorker.ProcessId $taskCore
    $taskDeadline=[DateTimeOffset]::UtcNow.AddSeconds(90)
    while([DateTimeOffset]::UtcNow -lt $taskDeadline){
        if($taskDesktopProcess.HasExited){throw 'Desktop exited during worker recovery.'}
        $taskDesktopEvents=@(Read-TaskDesktopEvents)
        $taskAuth=$taskDesktopEvents|Where-Object {$_.event -eq 'worker_authenticated' -and [DateTimeOffset]$_.time -gt [DateTimeOffset]$taskResult.crash_injected_at}|Select-Object -First 1
        if($taskAuth){$taskResult.recovered_authenticated_at=$taskAuth.time;break}
        Start-Sleep -Milliseconds 250
    }
    if(-not $taskResult.recovered_authenticated_at){throw 'Worker crash did not recover within 90 seconds.'}
    $taskRecovered=Get-TaskWorker
    if($taskRecovered.ProcessId -eq $taskResult.crashed_worker_id){throw 'Recovery did not create a replacement authentication worker.'}
    $taskResult.recovered_worker_id=$taskRecovered.ProcessId
    $taskResult.recovery_milliseconds=[math]::Round(([DateTimeOffset]$taskResult.recovered_authenticated_at-[DateTimeOffset]$taskResult.crash_injected_at).TotalMilliseconds)
    $taskResult.crash_recovery_passed=$true
    $taskResult.phase='observing_recovered_connection'
    $taskResult.observation_started_at=[DateTimeOffset]::UtcNow.ToString('o')
    $taskObservationEnd=[DateTimeOffset]::UtcNow.AddSeconds($ObservationSeconds)
    Save-TaskStatus
    while([DateTimeOffset]::UtcNow -lt $taskObservationEnd){
        if($taskDesktopProcess.HasExited){throw 'Desktop exited during online observation.'}
        $taskDesktopEvents=@(Read-TaskDesktopEvents)
        $taskUnexpected=@($taskDesktopEvents|Where-Object {
            [DateTimeOffset]$_.time -gt [DateTimeOffset]$taskResult.recovered_authenticated_at -and
            $_.event -in @('worker_unauthenticated','worker_crashed','worker_restart_scheduled','worker_terminal','accounts_exhausted','desktop_authentication_error','original_client_conflict')
        })
        if($taskUnexpected.Count){throw 'Connection state changed unexpectedly during observation.'}
        $taskProbeEvent=Invoke-TaskProbe 'observation'
        if($taskProbeEvent.event -eq 'ethernet_direct_probe_ok' -and -not $taskProbeEvent.original_client_present){
            $taskResult.probe_successes++;$taskResult.observation_probe_successes++
        }else{
            $taskResult.probe_failures++;$taskResult.observation_probe_failures++
        }
        Update-TaskEvidence;Save-TaskStatus
        Start-Sleep -Seconds 7
    }
    $taskResult.observation_completed_at=[DateTimeOffset]::UtcNow.ToString('o')
    $taskResult.observation_passed=($taskResult.observation_probe_successes -gt 0 -and $taskResult.observation_probe_failures -eq 0)
    $taskResult.connection_held=$true
    $taskResult.phase=if($taskResult.observation_passed){'passed_connection_held'}else{'observation_failed_connection_held'}
    Update-TaskEvidence;Save-TaskStatus
    Write-TaskEvent 'observation_completed_connection_held' $taskResult.observation_passed
    # The paused original supervisor would relaunch a conflicting authenticator.
    # Keep this small restorer alive until the desktop exits or release is asked.
    while(-not $taskDesktopProcess.HasExited -and -not $taskRelease.WaitOne(5000)){}
    $taskResult.connection_held=$false
    $taskResult.phase='restoring_original';Save-TaskStatus
}catch{
    $taskResult.error=$_.Exception.Message
    $taskResult.phase='failed';Write-TaskEvent 'test_failed';Save-TaskStatus
}finally{
    if($taskSwitched){
        try{
            if($taskDesktopProcess -and -not $taskDesktopProcess.HasExited){Stop-TaskExactProcess $taskDesktopProcess.Id $taskDesktop}
            $taskUiLog=Join-Path $taskOriginalRoot 'logs\ui.log'
            $taskRestoreOffset=if(Test-Path -LiteralPath $taskUiLog){(Get-Item -LiteralPath $taskUiLog).Length}else{0L}
            $taskRestoreStarted=Get-Date
            Resume-TaskOriginalSupervisor
            Start-Sleep -Seconds 2
            if(-not @(Get-CimInstance Win32_Process -Filter "Name='8021x.exe'").Count){Start-Process -FilePath $taskOriginal -WindowStyle Hidden}
            $taskResult.original_authentication_verified=$false;$taskResult.original_restored=$false
            $taskResult.phase='awaiting_original_authentication';Save-TaskStatus
            $taskRestoreDeadline=(Get-Date).AddSeconds(20)
            while((Get-Date) -lt $taskRestoreDeadline){
                if(Read-TaskOriginalSuccess $taskRestoreOffset $taskRestoreStarted){
                    $taskResult.original_authentication_verified=$true
                    $taskProbeEvent=Invoke-TaskProbe 'original_restore'
                    if($taskProbeEvent.event -eq 'ethernet_direct_probe_ok' -and $taskProbeEvent.original_client_present){$taskResult.original_restored=$true;$taskResult.phase='original_connection_restored';break}
                }
                Start-Sleep -Seconds 1
            }
            if(-not $taskResult.original_restored){
                $taskResult.phase='original_authentication_required'
                Start-Process -FilePath $taskOriginal -WindowStyle Normal
            }
        }catch{
            $taskResult.original_restored=$false
            $taskResult.error=([string]$taskResult.error)+' Restore failed: '+$_.Exception.Message
        }
    }else{Resume-TaskOriginalSupervisor;$taskResult.original_restored=$true}
    if($taskRelease){$taskRelease.Dispose()}
    Update-TaskEvidence
    $taskResult.ended_at=[DateTimeOffset]::UtcNow.ToString('o');Save-TaskStatus
}
if($taskResult.error){exit 1}
