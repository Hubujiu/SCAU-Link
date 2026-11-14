$ErrorActionPreference='Stop'
$taskScript=Join-Path $PSScriptRoot '..\scripts\Test-NativeAuth.ps1'
$taskTokens=$null;$taskErrors=$null
$taskAst=[Management.Automation.Language.Parser]::ParseFile($taskScript,[ref]$taskTokens,[ref]$taskErrors)
if($taskErrors.Count){throw 'The controller does not parse.'}
$taskObservationDeadline=$taskAst.FindAll({param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
    $node.Clauses[0].Item1.Extent.Text -match '\$taskObservationReported' -and
    $node.Clauses[0].Item1.Extent.Text -match '\$taskDeadline'
},$true)
if($taskObservationDeadline.Count -ne 1){throw 'The observation reporting deadline was not found.'}
$taskDeadlineMutations=$taskObservationDeadline[0].Clauses[0].Item2.FindAll({param($node)
    ($node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -in @('Stop-Process','Stop-Service','Start-Service')) -or
    ($node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -in @('Set','WaitForExit','Kill'))
},$true)
if($taskDeadlineMutations.Count){throw 'An observation reporting deadline must not signal a stop or terminate a process.'}
$taskFunction=$taskAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-TaskAuthSuccess'},$true)
if(-not $taskFunction){throw 'The restoration verifier was not found.'}
. ([scriptblock]::Create($taskFunction.Extent.Text))
$taskFixture=Join-Path ([IO.Path]::GetTempPath()) ('scau-restoration-'+[Guid]::NewGuid().ToString('N')+'.log')
try{
    $taskAfter=[datetime]'2026-11-12T18:12:17'
    [IO.File]::WriteAllText($taskFixture,"2026-11-12 16:49:19 AUTH_SUCCESS`n",[Text.Encoding]::ASCII)
    $taskOffset=(Get-Item -LiteralPath $taskFixture).Length
    if(Read-TaskAuthSuccess $taskFixture $taskOffset $taskAfter){throw 'A running process and stale success must not count as restored authentication.'}
    [IO.File]::AppendAllText($taskFixture,"2026-11-12 18:12:18 AUTH_FAILED`n",[Text.Encoding]::ASCII)
    if(Read-TaskAuthSuccess $taskFixture $taskOffset $taskAfter){throw 'A new authentication failure must not count as restored authentication.'}
    [IO.File]::AppendAllText($taskFixture,"2026-11-12 16:49:19 AUTH_SUCCESS`n",[Text.Encoding]::ASCII)
    if(Read-TaskAuthSuccess $taskFixture $taskOffset $taskAfter){throw 'A stale timestamp appended later must still be rejected.'}
    [IO.File]::AppendAllText($taskFixture,"2026-11-12 18:12:20 AUTH_SUCCESS`n",[Text.Encoding]::ASCII)
    $taskVerified=Read-TaskAuthSuccess $taskFixture $taskOffset $taskAfter
    if(-not $taskVerified -or [datetime]$taskVerified -ne [datetime]'2026-11-12T18:12:20'){throw 'A fresh authentication success must be verified.'}
    $taskStateFunction=$taskAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-TaskNativeState'},$true)
    if(-not $taskStateFunction){throw 'The worker/supervisor state merger was not found.'}
    . ([scriptblock]::Create($taskStateFunction.Extent.Text))
    $taskWorkerFixture=$taskFixture+'.worker';$taskSupervisorFixture=$taskFixture+'.supervisor'
    [IO.File]::WriteAllText($taskWorkerFixture,'{"time":"2026-11-12T10:00:01.000Z","event":"connection_state","detail":"connected","value":1}'+"`n",[Text.Encoding]::UTF8)
    [IO.File]::WriteAllText($taskSupervisorFixture,'{"time":"2026-11-12T10:00:02.000Z","event":"worker_crashed","value":1}'+"`n",[Text.Encoding]::UTF8)
    $taskMerged=Read-TaskNativeState $taskWorkerFixture $taskSupervisorFixture
    if($taskMerged.detail -ne 'worker-restarting' -or $taskMerged.value -ne 0){throw 'A crashed worker must not leave the status connected.'}
    [IO.File]::AppendAllText($taskWorkerFixture,'{"time":"2026-11-12T10:00:03.000Z","event":"connection_state","detail":"connected","value":1}'+"`n",[Text.Encoding]::UTF8)
    if((Read-TaskNativeState $taskWorkerFixture $taskSupervisorFixture).value -ne 1){throw 'Fresh authentication must replace the old crash state.'}
    [IO.File]::AppendAllText($taskSupervisorFixture,'{"time":"2026-11-12T10:00:04.000Z","event":"worker_terminal","value":1}'+"`n",[Text.Encoding]::UTF8)
    if((Read-TaskNativeState $taskWorkerFixture $taskSupervisorFixture).value -ne 0){throw 'A terminal worker must not retain connected status.'}
    Write-Output 'PASS: observation deadline retains the connection; process-only/stale/failed restoration rejected; fresh success verified.'
}finally{
    if($taskWorkerFixture -and (Test-Path -LiteralPath $taskWorkerFixture)){Remove-Item -LiteralPath $taskWorkerFixture -Force}
    if($taskSupervisorFixture -and (Test-Path -LiteralPath $taskSupervisorFixture)){Remove-Item -LiteralPath $taskSupervisorFixture -Force}
    if(Test-Path -LiteralPath $taskFixture){Remove-Item -LiteralPath $taskFixture -Force}
}
