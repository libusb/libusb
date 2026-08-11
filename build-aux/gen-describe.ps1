#requires -Version 3.0
<#
.SYNOPSIS
    Windows launcher for build-aux/gen-describe.sh.

.DESCRIPTION
    The MSVC PreBuildEvent invokes this script. It locates a `bash.exe`
    bundled with Git for Windows or MSYS2, then delegates the actual
    logic to gen-describe.sh, so the .sh remains the single source of
    truth across all supported build systems.

    The launcher must pick a *consistent* bash + cygpath pair from one
    install: cygpath converts Windows paths to MSYS form
    (`D:\foo` -> `/d/foo`), and bash must understand that mount table.
    Mixing e.g. MSYS2's cygpath with Windows' WSL `bash.exe` produces
    `/d/...` paths that the chosen bash cannot resolve (see #1815).

    Search order:
      1. Git for Windows: locate `git.exe` and look for sibling
         `bash.exe` + `cygpath.exe` under `bin\` or `usr\bin\`.
      2. Any non-WSL `bash.exe` on PATH whose install dir contains a
         sibling `cygpath.exe`.
      3. Any non-WSL `bash.exe` on PATH (without cygpath) - falls back
         to passing raw Windows paths, the pre-#1815 behaviour.
      4. Git for Windows bash without cygpath - same fallback.

    `C:\Windows\System32\bash.exe` (the WSL launcher) is always
    skipped because its `/d/...` namespace is the WSL rootfs, not the
    Windows D: drive.
#>
param(
    [Parameter(Mandatory = $true, Position = 0)] [string] $SrcDir,
    [Parameter(Mandatory = $true, Position = 1)] [string] $Out
)

$ErrorActionPreference = 'Stop'

$WslBash = Join-Path $env:WINDIR 'System32\bash.exe'

function Pair-If-Exists {
    param([string] $Bash)
    if (-not $Bash) { return $null }
    if (-not (Test-Path -LiteralPath $Bash)) { return $null }
    if ($Bash -ieq $WslBash) { return $null }
    $bashDir = Split-Path -Parent $Bash
    $parent  = Split-Path -Parent $bashDir
    foreach ($c in @(
        (Join-Path $bashDir 'cygpath.exe'),
        (Join-Path $parent  'bin\cygpath.exe'),
        (Join-Path $parent  'usr\bin\cygpath.exe'))) {
        if (Test-Path -LiteralPath $c) {
            return @{ Bash = $Bash; Cygpath = $c }
        }
    }
    return @{ Bash = $Bash; Cygpath = $null }
}

function Find-BashAndCygpath {
    # Priority 1: Git for Windows next to git.exe (prefer paired).
    $git = Get-Command -Name 'git.exe' -ErrorAction SilentlyContinue
    $gitBashCandidates = @()
    if ($git) {
        $gitDir = Split-Path -Parent $git.Path
        $parent = Split-Path -Parent $gitDir
        $gitBashCandidates = @(
            (Join-Path $gitDir 'bash.exe'),
            (Join-Path $parent  'bin\bash.exe'),
            (Join-Path $parent  'usr\bin\bash.exe')
        )
        foreach ($b in $gitBashCandidates) {
            $p = Pair-If-Exists $b
            if ($p -and $p.Cygpath) { return $p }
        }
    }

    # Priority 2: any non-WSL bash on PATH whose install has cygpath.
    $pathBashes = @(
        Get-Command -Name 'bash.exe' -All -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Path }
    )
    foreach ($b in $pathBashes) {
        $p = Pair-If-Exists $b
        if ($p -and $p.Cygpath) { return $p }
    }

    # Priority 3: non-WSL bash on PATH without cygpath (raw-path fallback).
    foreach ($b in $pathBashes) {
        $p = Pair-If-Exists $b
        if ($p) { return $p }
    }

    # Priority 4: Git for Windows bash without cygpath sibling.
    foreach ($b in $gitBashCandidates) {
        $p = Pair-If-Exists $b
        if ($p) { return $p }
    }

    return $null
}

$found = Find-BashAndCygpath
if (-not $found) {
    Write-Error @"
gen-describe.ps1: could not locate a usable bash.exe.
Looked next to git.exe (Git for Windows) and on PATH (excluding the
WSL launcher at $WslBash). Install Git for Windows
(https://gitforwindows.org/) or put a non-WSL bash.exe on PATH.
"@
}
$bash    = $found.Bash
$cygpath = $found.Cygpath

Write-Host "gen-describe.ps1: using bash $bash"

$scriptDir = Split-Path -Parent $PSCommandPath
$shScript  = Join-Path $scriptDir 'gen-describe.sh'

if ($cygpath) {
    Write-Host "gen-describe.ps1: using cygpath $cygpath to convert paths to MSYS form"
    # `cygpath -u path1 path2 path3` emits one MSYS path per line.
    $bashArgs = @(& $cygpath -u $shScript $SrcDir $Out)
    Write-Host ("gen-describe.ps1:   script  : {0} -> {1}" -f $shScript, $bashArgs[0])
    Write-Host ("gen-describe.ps1:   srcdir  : {0} -> {1}" -f $SrcDir,   $bashArgs[1])
    Write-Host ("gen-describe.ps1:   out     : {0} -> {1}" -f $Out,      $bashArgs[2])
} else {
    Write-Host "gen-describe.ps1: no cygpath sibling found for $bash; passing raw paths"
    $bashArgs = @($shScript, $SrcDir, $Out)
}

# Cross-process serialization: when msbuild runs projects in parallel
# (`/m`), libusb_dll and libusb_static both fire this PreBuildEvent at
# roughly the same time and would otherwise race on the output file.
# Use a named system mutex so only one writer is active at a time.
$mutex = New-Object System.Threading.Mutex($false, "Global\libusb-gen-describe")
try {
    [void] $mutex.WaitOne()
    & $bash $bashArgs[0] $bashArgs[1] $bashArgs[2]
    $rc = $LASTEXITCODE
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
exit $rc
