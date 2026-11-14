#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunDirectory)
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskStatusPath=Join-Path ([IO.Path]::GetFullPath($RunDirectory)) 'status.json'
$taskStatus=Get-Content -LiteralPath $taskStatusPath -Raw | ConvertFrom-Json
if(-not $taskStatus.native_process_id -or -not $taskStatus.stop_event){throw 'This test does not expose a native session stop control.'}
$taskNativeProcess=Get-Process -Id $taskStatus.native_process_id -ErrorAction Stop
$taskExpectedExecutables=@((Join-Path $taskRoot 'build\Release\scau-auth.exe'),(Join-Path $taskRoot 'scau-auth.exe'))
if($taskNativeProcess.Path -notin $taskExpectedExecutables){throw 'The recorded process is not this workspace authentication core.'}
$taskStop=[Threading.EventWaitHandle]::OpenExisting($taskStatus.stop_event)
try{$taskStop.Set()|Out-Null}finally{$taskStop.Dispose()}
Write-Output 'Disconnect requested. The controller will restore the original client and verify a new AUTH_SUCCESS.'
