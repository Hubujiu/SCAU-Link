[CmdletBinding()]
param([ValidateRange(1,999)][int]$FirstRun=38)
$ErrorActionPreference='Stop'
$acceptanceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$acceptanceCases=@(
    @{Name='fresh-web';Mode='NativeWeb';Fresh=$true},
    @{Name='startup-1x-recovery';Mode='Backend1x';Fresh=$false},
    @{Name='startup-web-recovery';Mode='BackendWeb';Fresh=$false},
    @{Name='fresh-web-repeat';Mode='NativeWeb';Fresh=$true}
)
$acceptanceResults=@()
for($acceptanceIndex=0;$acceptanceIndex -lt $acceptanceCases.Count;$acceptanceIndex++){
    $acceptanceCase=$acceptanceCases[$acceptanceIndex]
    $acceptanceDirectory=Join-Path $acceptanceRoot ('captures\delivery-lab-20261114-'+($FirstRun+$acceptanceIndex))
    if(Test-Path -LiteralPath $acceptanceDirectory){throw 'Use unused run numbers; historical evidence is never overwritten.'}
    $acceptanceArguments=@{Action='Run';RunDirectory=$acceptanceDirectory;Mode=$acceptanceCase.Mode;ObservationSeconds=30;TemporaryWlanDhcp=$true}
    if($acceptanceCase.Fresh){$acceptanceArguments.FreshWirelessIdentity=$true}
    & (Join-Path $PSScriptRoot 'Test-NetworkDelivery.ps1') @acceptanceArguments
    $acceptanceDeadline=[DateTime]::UtcNow.AddMinutes(14)
    $acceptanceResultFile=Join-Path $acceptanceDirectory 'result.json'
    while(-not (Test-Path -LiteralPath $acceptanceResultFile)){
        if([DateTime]::UtcNow -gt $acceptanceDeadline){throw 'Independent experiment has not returned; inspect its watchdog before starting another case.'}
        Start-Sleep -Milliseconds 500
    }
    $acceptanceResult=Get-Content -LiteralPath $acceptanceResultFile -Raw|ConvertFrom-Json
    $acceptanceResults+=@{name=$acceptanceCase.Name;directory=$acceptanceDirectory;passed=[bool]$acceptanceResult.test_passed;restored=[bool]$acceptanceResult.restored}
    [IO.File]::WriteAllText((Join-Path $acceptanceRoot 'captures\acceptance-0.12.0.json'),($acceptanceResults|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    if(-not $acceptanceResult.test_passed -or -not $acceptanceResult.restored){throw 'Case failed; subsequent network tests were not started.'}
}
'All four independently supervised wireless cases passed and restored.'
