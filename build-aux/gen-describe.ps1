#requires -Version 3.0
<#
.SYNOPSIS
    Prepare version_describe.h for MSVC builds.
.DESCRIPTION
    Release tarballs contain a frozen header. Other archives use a shared
    unknown-source header. Git checkouts run gen-describe.sh through Git's
    POSIX shell; version generation stays in that script.

    LIBUSB_GIT and LIBUSB_SH can select explicit executable paths. Otherwise,
    search PATH and SourceTree's embedded Git installation. Prefer Git's
    GIT_SHELL_PATH query, with installation-layout fallbacks for older Git.
#>
param(
    [Parameter(Mandatory = $true, Position = 0)] [string] $SrcDir,
    [Parameter(Mandatory = $true, Position = 1)] [string] $Out
)

$ErrorActionPreference = 'Stop'
$SrcDir = [IO.Path]::GetFullPath($SrcDir)
$Out = [IO.Path]::GetFullPath($Out)
$originalPath = $env:PATH
$attempted = New-Object 'System.Collections.Generic.List[string]'

function Get-InstallRoot([string] $Executable) {
    $dir = Split-Path -Parent $Executable
    if ((Split-Path -Leaf $dir) -eq 'git-core') {
        $dir = Split-Path -Parent $dir
    }
    if ((Split-Path -Leaf $dir) -in @('cmd', 'bin', 'libexec')) {
        $dir = Split-Path -Parent $dir
    }
    if ((Split-Path -Leaf $dir) -in @('usr', 'mingw32', 'mingw64', 'ucrt64', 'clang64', 'clangarm64')) {
        $dir = Split-Path -Parent $dir
    }
    return $dir
}

function Get-GitCandidates {
    if ($env:LIBUSB_GIT) {
        if (-not (Test-Path -LiteralPath $env:LIBUSB_GIT -PathType Leaf)) {
            throw "LIBUSB_GIT does not name an executable: $env:LIBUSB_GIT"
        }
        [IO.Path]::GetFullPath($env:LIBUSB_GIT)
        return
    }
    Get-Command git.exe -All -CommandType Application -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Path }
    if ($env:LOCALAPPDATA) {
        $root = Join-Path $env:LOCALAPPDATA 'Atlassian\SourceTree\git_local'
        foreach ($subdir in @('cmd', 'bin', 'mingw32\bin', 'mingw64\bin', 'ucrt64\bin')) {
            $candidate = Join-Path $root "$subdir\git.exe"
            $attempted.Add($candidate)
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $candidate }
        }
    }
}

function Get-ShellCandidates([string] $Git) {
    if ($env:LIBUSB_SH) {
        if (-not (Test-Path -LiteralPath $env:LIBUSB_SH -PathType Leaf)) {
            throw "LIBUSB_SH does not name an executable: $env:LIBUSB_SH"
        }
        [IO.Path]::GetFullPath($env:LIBUSB_SH)
        return
    }
    if ($Git) {
        # Older Git can reject the query or return a non-Windows /bin/sh path.
        $ErrorActionPreference = 'Continue'
        $reported = @(& $Git var GIT_SHELL_PATH 2>$null)
        $queryResult = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($queryResult -eq 0) {
            $reported | Where-Object { $_ -match '^([A-Za-z]:[/\\]|[/\\]{2})' }
        }
        $root = Get-InstallRoot $Git
        foreach ($name in @('usr\bin\sh.exe', 'bin\sh.exe', 'usr\bin\bash.exe', 'bin\bash.exe')) {
            Join-Path $root $name
        }
    }
    Get-Command sh.exe,bash.exe -All -CommandType Application -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Path }
}

function Find-Tools {
    $gits = @(Get-GitCandidates | Select-Object -Unique)
    if ($gits.Count -eq 0) {
        if (Test-Path -LiteralPath (Join-Path $SrcDir '.git')) {
            throw 'Git checkout: git.exe was not found on PATH or in SourceTree. Set LIBUSB_GIT.'
        }
        $gits = @($null)
    }
    foreach ($git in $gits) {
        foreach ($candidate in @(Get-ShellCandidates $git | Select-Object -Unique)) {
            $attempted.Add($candidate)
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
            $shell = [IO.Path]::GetFullPath($candidate)
            # WSL uses a different path namespace from the Windows tools.
            if ($shell -ieq (Join-Path $env:WINDIR 'System32\bash.exe')) { continue }
            $root = Get-InstallRoot $shell
            $helperDirs = @((Split-Path -Parent $shell), (Join-Path $root 'usr\bin'), (Join-Path $root 'bin')) |
                Select-Object -Unique
            $complete = $true
            foreach ($tool in @('sed.exe', 'tr.exe', 'cat.exe', 'dirname.exe', 'mkdir.exe', 'mv.exe')) {
                $matches = @($helperDirs | ForEach-Object { Join-Path $_ $tool } |
                    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
                if ($matches.Count -eq 0) { $complete = $false; break }
            }
            if (-not $complete) { continue }
            $cygpath = $helperDirs | ForEach-Object { Join-Path $_ 'cygpath.exe' } |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            $pathDirs = @()
            if ($git) {
                $pathDirs += Split-Path -Parent $git
                # Git's shell maps Git/bin to /bin, which has no git.exe.
                $gitCmd = Join-Path (Get-InstallRoot $git) 'cmd'
                if (Test-Path -LiteralPath (Join-Path $gitCmd 'git.exe') -PathType Leaf) {
                    $pathDirs += $gitCmd
                }
            }
            $pathDirs += $helperDirs
            $pathDirs += (Join-Path $env:WINDIR 'System32'), $env:WINDIR
            return @{ Git = $git; Shell = $shell; Cygpath = $cygpath; Path = ($pathDirs -join ';') }
        }
    }
    throw @"
No usable POSIX shell and helper tools were found. Set LIBUSB_GIT and/or LIBUSB_SH,
or use a prepared release tarball for a build without a shell.
Searched: $($attempted -join ', ')
"@
}

function Copy-Header([string] $Source) {
    $bytes = [IO.File]::ReadAllBytes($Source)
    if ((Test-Path -LiteralPath $Out -PathType Leaf) -and
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($Out)) -eq [Convert]::ToBase64String($bytes)) {
        return
    }
    [void] [IO.Directory]::CreateDirectory((Split-Path -Parent $Out))
    $temp = "$Out.tmp"
    try {
        [IO.File]::WriteAllBytes($temp, $bytes)
        if (Test-Path -LiteralPath $Out) {
            # $null becomes an empty string in this .NET overload.
            [IO.File]::Replace($temp, $Out, [NullString]::Value)
        } else {
            [IO.File]::Move($temp, $Out)
        }
    } finally {
        if (Test-Path -LiteralPath $temp) { [IO.File]::Delete($temp) }
    }
}

# Both library projects can write the same header during a parallel build.
$mutex = New-Object System.Threading.Mutex($false, 'Global\libusb-gen-describe')
$locked = $false
$rc = 0
try {
    try { $locked = $mutex.WaitOne(60000) }
    catch [System.Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Timed out waiting for version header generation.' }

    $prepared = Join-Path $SrcDir 'build-aux\version-describe-dist.h'
    if (-not (Test-Path -LiteralPath (Join-Path $SrcDir '.git')) -and
        (Test-Path -LiteralPath $prepared -PathType Leaf)) {
        Copy-Header $prepared
    } elseif (-not (Test-Path -LiteralPath (Join-Path $SrcDir '.git')) -and
              -not (Test-Path -LiteralPath (Join-Path $SrcDir '.tarball-version'))) {
        Write-Warning 'Source is neither a Git checkout nor a release tarball; using the Unknown source version header.'
        Copy-Header (Join-Path $SrcDir 'build-aux\version-describe-unknown.h')
    } else {
        $tools = Find-Tools
        Write-Host "gen-describe.ps1: using git $($tools.Git)"
        Write-Host "gen-describe.ps1: using shell $($tools.Shell)"
        $env:PATH = $tools.Path
        $paths = @((Join-Path $PSScriptRoot 'gen-describe.sh'), $SrcDir, $Out)
        if ($tools.Cygpath) {
            $paths = @(& $tools.Cygpath -u @paths)
            if ($LASTEXITCODE -ne 0 -or $paths.Count -ne 3) { throw 'cygpath failed to convert build paths.' }
        } else {
            $paths = @($paths | ForEach-Object { $_.Replace('\', '/') })
        }
        & $tools.Shell @paths
        $rc = $LASTEXITCODE
    }
} finally {
    $env:PATH = $originalPath
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
exit $rc
