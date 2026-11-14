param([Parameter(Mandatory=$true)][string]$Path,
      [Parameter(Mandatory=$true)][string]$Publisher)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
$taskSignature=Get-AuthenticodeSignature -LiteralPath $Path
if($taskSignature.Status -ne 'Valid' -or $taskSignature.SignerCertificate.Subject -notlike ('*'+$Publisher+'*')){
    throw 'Unverified build dependency signature'
}
[pscustomobject]@{status=[string]$taskSignature.Status;publisher=$taskSignature.SignerCertificate.Subject} |
    ConvertTo-Json -Compress
