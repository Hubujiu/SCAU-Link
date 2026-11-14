[CmdletBinding()]
param(
    [ValidateSet('Run','Status','Stop','Restore','SelfTest')][string]$Action='Status',
    [string]$RunDirectory,
    [ValidateRange(30,1800)][int]$ObservationSeconds=120,
    [ValidateSet('All','Wired','Wireless8021x','CurrentUserProbe','AllUserProbe','WebDiscovery','NativeWeb','NativeStable1x','BackendWeb','Backend1x')][string]$Mode='All',
    [switch]$CaptureEapMetadata,
    [switch]$TemporaryWlanDhcp,
    [switch]$FreshWirelessIdentity,
    [string]$PythonPath='C:\Users\Hubujiu\AppData\Local\Google\Cloud SDK\google-cloud-sdk\platform\bundledpython\python.exe'
)
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskPython=[IO.Path]::GetFullPath($PythonPath)
if(-not (Test-Path -LiteralPath $taskPython -PathType Leaf)){throw 'A local Python 3 interpreter is required. Pass -PythonPath; no download is performed.'}
if($Action -eq 'SelfTest'){
    & $taskPython (Join-Path $taskRoot 'tests\network_lab_tests.py')
    exit $LASTEXITCODE
}
if(-not $RunDirectory){
    if($Action -ne 'Run'){throw 'Pass -RunDirectory for Status, Stop or Restore.'}
    $RunDirectory=Join-Path $taskRoot ('captures\delivery-lab-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$taskRun=[IO.Path]::GetFullPath($RunDirectory)
$taskScript=Join-Path $PSScriptRoot 'network_lab.py'
if($Action -eq 'Run'){
    if(Test-Path -LiteralPath $taskRun){throw 'Use a new experiment directory to prevent stale evidence.'}
    New-Item -ItemType Directory -Path $taskRun|Out-Null
    $taskRuntime=Join-Path $taskRun 'runtime'
    New-Item -ItemType Directory -Path $taskRuntime|Out-Null
    foreach($taskSource in @('network_lab.py','network_lab_windows.py','probe_ethernet.py','passive_eap_probe.py','web_discovery_probe.py')){
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $taskSource) -Destination (Join-Path $taskRuntime $taskSource)
    }
    $taskScript=Join-Path $taskRuntime 'network_lab.py'
    $taskData=Join-Path ([Environment]::GetFolderPath('UserProfile')) 'AppData\Local\ScauLink'
    $taskOriginal='D:\Apps\Network\SCAU Link'
    $taskTest=Join-Path $taskRoot 'out\scau-link-0.12.0-win-x64-preview'
    $taskConfig=[ordered]@{
        schema=1;expectedSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        passiveEapCapture=[bool]$CaptureEapMetadata
        temporaryDhcp=[bool]$TemporaryWlanDhcp
        freshWirelessIdentity=[bool]$FreshWirelessIdentity
        preserveOriginal=($Mode -in @('WebDiscovery','NativeWeb','NativeStable1x','BackendWeb','Backend1x'))
        dataDirectory=$taskData;originalApp=(Join-Path $taskOriginal 'SCAU-Link.exe');originalCore=(Join-Path $taskOriginal 'scau-auth.exe')
        testApp=(Join-Path $taskTest 'SCAU-Link.exe');testCore=(Join-Path $taskTest 'scau-auth.exe')
        modes=@(if($Mode -eq 'Wired'){0}elseif($Mode -eq 'Wireless8021x'){2}else{0;2});observationSeconds=$ObservationSeconds;deadlineSeconds=(660+2*$ObservationSeconds);heartbeatSeconds=15
        binaries=@(
            @{path=(Join-Path $taskTest 'SCAU-Link.exe');sha256='085e69a7d5da5651617f18197fd7c738193517ae7b08b4c857d6fb8144a3a0b8'},
            @{path=(Join-Path $taskTest 'scau-auth.exe');sha256='615df8d16fb23c4815846fa13312694e59043fb966bf19b81693bc9d5f769245'},
            @{path=(Join-Path $taskOriginal 'SCAU-Link.exe');sha256='4b8ae91fffb904ef968f9cf790c4a71f4d5f9bb6b9accac6aba826bb975c9db3'},
            @{path=(Join-Path $taskOriginal 'scau-auth.exe');sha256='f23853b2fb68e3a14870dc31083a718899341aee094d16f12f22e6fb0fc55c02'}
        )
    }
    if($Mode -eq 'WebDiscovery'){$taskConfig['probeKind']='web-discovery'}
    if($Mode -in @('NativeWeb','NativeStable1x','BackendWeb','Backend1x')){
        $taskProbeName=if($Mode -in @('BackendWeb','Backend1x')){'network-backend-probe.exe'}else{'network-delivery-probe.exe'}
        $taskProbe=Join-Path $taskRoot ('build\Release\'+$taskProbeName)
        if(-not (Test-Path -LiteralPath $taskProbe)){throw 'Build network-delivery-probe first.'}
        $taskProbeDirectory=Join-Path $taskRun 'bin'
        New-Item -ItemType Directory -Path $taskProbeDirectory|Out-Null
        Copy-Item -LiteralPath $taskProbe -Destination (Join-Path $taskProbeDirectory $taskProbeName)
        $taskProbe=Join-Path $taskProbeDirectory $taskProbeName
        $taskConfig['credentialProbe']=$taskProbe
        $taskConfig['probeKind']=if($Mode -eq 'BackendWeb'){'backend-web'}elseif($Mode -eq 'Backend1x'){'backend-1x'}elseif($Mode -eq 'NativeWeb' -and $FreshWirelessIdentity){'fresh-wireless-web'}elseif($Mode -eq 'NativeWeb'){'wireless-web'}else{'wireless-8021x'}
        $taskConfig.binaries+=@{path=$taskProbe;sha256=(Get-FileHash -LiteralPath $taskProbe -Algorithm SHA256).Hash.ToLowerInvariant()}
        if($Mode -in @('BackendWeb','Backend1x')) {
            $taskCore=Join-Path $taskProbeDirectory 'scau-auth.exe'
            Copy-Item -LiteralPath (Join-Path $taskRoot 'build\Release\scau-auth.exe') -Destination $taskCore
            $taskConfig['testCore']=$taskCore
            $taskConfig.binaries+=@{path=$taskCore;sha256=(Get-FileHash -LiteralPath $taskCore -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
    }
    $taskObserver=Join-Path $taskRoot 'build\Release\wlan-notification-probe.exe'
    if(Test-Path -LiteralPath $taskObserver){$taskConfig['observer']=$taskObserver;$taskConfig.binaries+=@{path=$taskObserver;sha256=(Get-FileHash -LiteralPath $taskObserver -Algorithm SHA256).Hash.ToLowerInvariant()}}
    if($Mode -in @('CurrentUserProbe','AllUserProbe')){
        $taskProbe=Join-Path $taskRoot 'build\Release\wlan-credential-probe.exe'
        if(-not (Test-Path -LiteralPath $taskProbe)){throw 'Build wlan-credential-probe before this diagnostic experiment.'}
        $taskConfig['credentialProbe']=$taskProbe
        $taskConfig['probeKind']=if($Mode -eq 'CurrentUserProbe'){'current-user'}else{'all-user'}
        $taskConfig.binaries+=@{path=$taskProbe;sha256=(Get-FileHash -LiteralPath $taskProbe -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
    [IO.File]::WriteAllText((Join-Path $taskRun 'config.json'),($taskConfig|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
    # Launch outside Codex's packaged filesystem/registry context. Selecting the
    # existing Explorer desktop is essential; a new generic Shell instance is not.
    $taskShell=New-Object -ComObject Shell.Application
    $taskDesktopHwnd=0
    $taskDesktop=$taskShell.Windows().FindWindowSW(0,0,8,[ref]$taskDesktopHwnd,1)
    if(-not $taskDesktop){throw 'The Explorer desktop is required for the real user credential context.'}
    $taskArguments='"'+$taskScript+'" run --run "'+$taskRun+'"'
    $taskVerb=if($TemporaryWlanDhcp){'runas'}else{'open'}
    $taskDesktop.Document.Application.ShellExecute($taskPython,$taskArguments,$taskRoot,$taskVerb,0)
    Write-Output "Started independent local watchdog: $taskRun"
    Write-Output "Status: .\scripts\Test-NetworkDelivery.ps1 -Action Status -RunDirectory '$taskRun'"
    Write-Output "Stop and restore: .\scripts\Test-NetworkDelivery.ps1 -Action Stop -RunDirectory '$taskRun'"
}elseif($Action -eq 'Status'){
    foreach($taskName in @('preflight.json','wired.json','wireless_8021x.json','restored.json','result.json')){
        $taskFile=Join-Path $taskRun $taskName
        if(Test-Path -LiteralPath $taskFile){Write-Output $taskName;Get-Content -LiteralPath $taskFile}
    }
}elseif($Action -eq 'Stop'){
    [IO.File]::WriteAllText((Join-Path $taskRun 'STOP'),'stop',[Text.UTF8Encoding]::new($false))
    Write-Output 'Local watchdog notified; it will stop testing and restore the original client.'
}else{
    # Use Explorer again so manual recovery sees the same real account/config.
    $taskShell=New-Object -ComObject Shell.Application
    $taskDesktopHwnd=0
    $taskDesktop=$taskShell.Windows().FindWindowSW(0,0,8,[ref]$taskDesktopHwnd,1)
    if(-not $taskDesktop){throw 'The Explorer desktop is required for recovery.'}
    $taskScript=Join-Path $taskRun 'runtime\network_lab.py'
    $taskSavedConfig=Get-Content -LiteralPath (Join-Path $taskRun 'config.json') -Raw|ConvertFrom-Json
    $taskVerb=if($taskSavedConfig.temporaryDhcp){'runas'}else{'open'}
    $taskDesktop.Document.Application.ShellExecute($taskPython,('"'+$taskScript+'" restore --run "'+$taskRun+'"'),$taskRoot,$taskVerb,0)
    Write-Output 'Independent local recovery started.'
}
