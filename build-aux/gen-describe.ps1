#requires -Version 3.0
<#
.SYNOPSIS
    Windows launcher for build-aux/gen-describe.sh.

.DESCRIPTION
    The MSVC PreBuildEvent invokes this script. It locates a `bash.exe`
    bundled with Git for Windows (the de-facto git distribution on
    Windows), then delegates the actual logic to gen-describe.sh, so the
    .sh remains the single source of truth across all supported build
    systems.

    Search order for bash:
      1. bash.exe on PATH (covers users who explicitly added Git's bin
         directory; PowerShell, MSYS2, Cygwin, etc.).
      2. `bash.exe` next to the resolved git.exe (Git for Windows
         installed with the "Git Bash Here" option puts both in the
         same `bin\` directory).
      3. `bin\bash.exe` and `usr\bin\bash.exe` relative to the parent
         of git.exe's directory (covers the default Git for Windows
         layout where git.exe lives in `cmd\` and bash.exe in `bin\`
         or `usr\bin\`).
#>
param(
    [Parameter(Mandatory = $true, Position = 0)] [string] $SrcDir,
    [Parameter(Mandatory = $true, Position = 1)] [string] $Out
)

$ErrorActionPreference = 'Stop'

function Find-Bash {
    $cmd = Get-Command -Name 'bash.exe' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }

    $git = Get-Command -Name 'git.exe' -ErrorAction SilentlyContinue
    if (-not $git) {
        return $null
    }
    $gitDir = Split-Path -Parent $git.Path
    $parent = Split-Path -Parent $gitDir
    $candidates = @(
        (Join-Path $gitDir 'bash.exe'),
        (Join-Path $parent  'bin\bash.exe'),
        (Join-Path $parent  'usr\bin\bash.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    return $null
}

$bash = Find-Bash
if (-not $bash) {
    Write-Error @"
gen-describe.ps1: could not locate bash.exe.
Looked on PATH and next to git.exe (Git for Windows). Install Git for
Windows (https://gitforwindows.org/) or put bash.exe on PATH.
"@
}

$scriptDir = Split-Path -Parent $PSCommandPath
$shScript  = Join-Path $scriptDir 'gen-describe.sh'

# Cross-process serialization: when msbuild runs projects in parallel
# (`/m`), libusb_dll and libusb_static both fire this PreBuildEvent at
# roughly the same time and would otherwise race on the output file.
# Use a named system mutex so only one writer is active at a time.
$mutex = New-Object System.Threading.Mutex($false, "Global\libusb-gen-describe")
try {
    [void] $mutex.WaitOne()
    & $bash $shScript $SrcDir $Out
    $rc = $LASTEXITCODE
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
exit $rc
