[CmdletBinding()]
param([ValidateSet('Debug','Release')][string]$Configuration='Release')
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskCmake=(Get-Command cmake -ErrorAction SilentlyContinue).Source
if(-not $taskCmake){
    $taskCmake='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
}
if(-not (Test-Path -LiteralPath $taskCmake)){throw 'CMake is unavailable.'}
& python -X utf8 (Join-Path $PSScriptRoot 'build_openssl.py')
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
& $taskCmake -S $taskRoot -B (Join-Path $taskRoot 'build') -G 'Visual Studio 17 2022' -A x64
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
& $taskCmake --build (Join-Path $taskRoot 'build') --config $Configuration
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
$taskCTest=Join-Path (Split-Path -Parent $taskCmake) 'ctest.exe'
& $taskCTest --test-dir (Join-Path $taskRoot 'build') -C $Configuration --output-on-failure
exit $LASTEXITCODE
