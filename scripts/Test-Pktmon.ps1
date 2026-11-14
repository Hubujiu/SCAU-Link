#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CaptureDirectory,

    [ValidateRange(1, 30)]
    [int]$Seconds = 5
)

$ErrorActionPreference = 'Stop'
$taskPktmon = Join-Path $env:WINDIR 'System32\pktmon.exe'
$taskCaptureDirectory = [IO.Path]::GetFullPath($CaptureDirectory)
New-Item -ItemType Directory -Path $taskCaptureDirectory -Force | Out-Null
$taskLogPath = Join-Path $taskCaptureDirectory 'commands.log'
$taskResultPath = Join-Path $taskCaptureDirectory 'result.json'
$taskStarted = $false
$taskResult = [ordered]@{
    started_at = (Get-Date).ToString('o')
    duration_seconds = $Seconds
    capture_directory = $taskCaptureDirectory
    start_exit_code = $null
    stop_exit_code = $null
    conversions = @()
    error = $null
    ended_at = $null
}

try {
    try {
        $taskCapturePath = Join-Path $taskCaptureDirectory 'scau.etl'
        & $taskPktmon start --capture --comp nics --pkt-size 0 --file-name $taskCapturePath --file-size 128 --log-mode multi-file 2>&1 |
            Out-File -LiteralPath $taskLogPath -Encoding utf8 -Append
        $taskResult.start_exit_code = $LASTEXITCODE
        if ($LASTEXITCODE -ne 0) {
            throw "PktMon start failed with exit code $LASTEXITCODE."
        }
        $taskStarted = $true
        & $taskPktmon status 2>&1 | Out-File -LiteralPath $taskLogPath -Encoding utf8 -Append
        & $taskPktmon list 2>&1 |
            Out-File -LiteralPath (Join-Path $taskCaptureDirectory 'components.txt') -Encoding utf8
        Start-Sleep -Seconds $Seconds
    }
    finally {
        if ($taskStarted) {
            & $taskPktmon stop 2>&1 | Out-File -LiteralPath $taskLogPath -Encoding utf8 -Append
            $taskResult.stop_exit_code = $LASTEXITCODE
            if ($LASTEXITCODE -ne 0) {
                throw "PktMon stop failed with exit code $LASTEXITCODE."
            }
        }
    }

    $taskEtlFiles = @(Get-ChildItem -LiteralPath $taskCaptureDirectory -Filter '*.etl' -File)
    if ($taskEtlFiles.Count -eq 0) {
        throw 'PktMon did not create an ETL file.'
    }
    foreach ($taskEtlFile in $taskEtlFiles) {
        $taskPcapPath = [IO.Path]::ChangeExtension($taskEtlFile.FullName, '.pcapng')
        & $taskPktmon etl2pcap $taskEtlFile.FullName --out $taskPcapPath 2>&1 |
            Out-File -LiteralPath $taskLogPath -Encoding utf8 -Append
        $taskConversionExitCode = $LASTEXITCODE
        $taskResult.conversions += [ordered]@{
            input = $taskEtlFile.FullName
            output = $taskPcapPath
            exit_code = $taskConversionExitCode
        }
        if ($taskConversionExitCode -ne 0) {
            throw "PktMon conversion failed with exit code $taskConversionExitCode."
        }
    }
    & $taskPktmon status 2>&1 | Out-File -LiteralPath $taskLogPath -Encoding utf8 -Append
}
catch {
    $taskResult.error = $_.Exception.Message
}
finally {
    $taskResult.ended_at = (Get-Date).ToString('o')
    $taskResult | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskResultPath -Encoding utf8
}

if ($taskResult.error) {
    exit 1
}
exit 0
