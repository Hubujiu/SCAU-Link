[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Baseline,
    [Parameter(Mandatory)][string]$Candidate,
    [Parameter(Mandatory)][string]$BaselineCore,
    [Parameter(Mandatory)][string]$CandidateCore,
    [ValidateRange(5,30)][int]$Runs = 10
)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class MigrationMemory {
    [StructLayout(LayoutKind.Sequential)]
    struct Counters {
        public uint Size, Faults;
        public UIntPtr PeakWorkingSet, WorkingSet, PeakPagedPool, PagedPool, PeakNonPagedPool, NonPagedPool;
        public UIntPtr Pagefile, PeakPagefile, PrivateCommit, PrivateWorkingSet;
        public ulong SharedCommit;
    }
    [DllImport("psapi.dll", SetLastError=true)]
    static extern bool GetProcessMemoryInfo(IntPtr process, ref Counters counters, uint size);
    public static ulong[] Read(Process process) {
        var counters = new Counters();
        counters.Size = (uint)Marshal.SizeOf(typeof(Counters));
        if (!GetProcessMemoryInfo(process.Handle, ref counters, counters.Size))
            throw new Win32Exception();
        return new [] {counters.WorkingSet.ToUInt64(), counters.PrivateWorkingSet.ToUInt64(), counters.PrivateCommit.ToUInt64()};
    }
}
'@

function Measure-Desktop([string]$Path, [string]$Demo) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new($Path, $Demo)
    $startInfo.UseShellExecute = $false
    $startInfo.WorkingDirectory = Split-Path -Parent $Path
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $process = [Diagnostics.Process]::Start($startInfo)
    try {
        do {
            if ($process.HasExited -or $timer.Elapsed.TotalSeconds -ge 10) { throw 'Demo window could not be opened.' }
            $process.Refresh()
            if ($process.MainWindowHandle -ne [IntPtr]::Zero) { break }
            [Threading.Thread]::Sleep(2)
        } while ($true)
        $visible = $timer.Elapsed.TotalMilliseconds
        Start-Sleep -Milliseconds 1800
        $cpuBefore = $process.TotalProcessorTime.TotalMilliseconds
        $idle = [Diagnostics.Stopwatch]::StartNew()
        Start-Sleep -Milliseconds 1300
        $process.Refresh()
        $cpu = ($process.TotalProcessorTime.TotalMilliseconds - $cpuBefore) / $idle.Elapsed.TotalSeconds
        $memory = [MigrationMemory]::Read($process)
        [ordered]@{
            visibleMs = $visible
            idleCpuMsPerSecond = $cpu
            workingSetBytes = $memory[0]
            privateWorkingSetBytes = $memory[1]
            privateCommitBytes = $memory[2]
        }
    } finally {
        if (!$process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $process.Dispose()
    }
}

function Measure-Core([string]$Path, [string]$Mode) {
    $raw = & $Path $Mode
    if ($LASTEXITCODE) { throw "Core benchmark exited with $LASTEXITCODE" }
    $raw | ConvertFrom-Json
}

$desktops = @((Resolve-Path -LiteralPath $Baseline).Path,(Resolve-Path -LiteralPath $Candidate).Path)
$cores = @((Resolve-Path -LiteralPath $BaselineCore).Path,(Resolve-Path -LiteralPath $CandidateCore).Path)
$rows = @()
foreach ($demo in '--demo','--demo-package') {
    foreach ($path in $desktops) { $null = Measure-Desktop $path $demo }
    for ($round = 0; $round -lt $Runs; $round++) {
        foreach ($index in ($round % 2),(1 - $round % 2)) {
            $rows += [ordered]@{ workload = $demo; version = $index; result = Measure-Desktop $desktops[$index] $demo }
        }
    }
}
foreach ($mode in 'parse','recovery') {
    foreach ($path in $cores) { $null = Measure-Core $path $mode }
    for ($round = 0; $round -lt $Runs; $round++) {
        $pair = @{}
        foreach ($index in ($round % 2),(1 - $round % 2)) {
            $pair[$index] = Measure-Core $cores[$index] $mode
            $rows += [ordered]@{ workload = $mode; version = $index; result = $pair[$index] }
        }
        if ($pair[0].checksum -ne $pair[1].checksum) { throw "Core checksum differs for $mode" }
    }
}

[ordered]@{
    windows = [Environment]::OSVersion.Version.ToString()
    processor = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)
    desktopSha256 = @($desktops | ForEach-Object { (Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant() })
    desktopBytes = @($desktops | ForEach-Object { (Get-Item -LiteralPath $_).Length })
    runs = $Runs
    samples = $rows
} | ConvertTo-Json -Depth 6
