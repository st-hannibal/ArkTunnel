# ArkTunnel client — Windows installer (PowerShell).
#
# Usage (run in an elevated or regular PowerShell prompt):
#   irm https://github.com/arktunnel/arktunnel/releases/latest/download/install-client-windows.ps1 | iex
#
# Downloads the latest ark-client-windows-amd64.exe, verifies SHA256, installs
# to %LOCALAPPDATA%\arktunnel\ark-client.exe, and adds the directory to the
# current user's PATH if not already present.

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo      = 'arktunnel/arktunnel'
$Artifact  = 'ark-client-windows-amd64.exe'
$BinaryName = 'ark-client.exe'
$InstallDir = Join-Path $env:LOCALAPPDATA 'arktunnel'

# Pinned upstream tun2socks (https://github.com/xjasonlyu/tun2socks) used by `ark-client tun`.
$Tun2SocksVersion = 'v2.5.2'

function Write-Info  { param($Msg) Write-Host "[ark-client] $Msg" -ForegroundColor Cyan }
function Write-Err   { param($Msg) Write-Host "[ark-client] ERROR: $Msg" -ForegroundColor Red; exit 1 }

# ── architecture check ────────────────────────────────────────────────────────
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    Write-Err "Only x86_64 (AMD64) Windows is supported. Got: $env:PROCESSOR_ARCHITECTURE"
}

# ── fetch latest release tag ─────────────────────────────────────────────────
Write-Info 'Fetching latest release from GitHub...'
try {
    $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
} catch {
    Write-Err "Failed to reach GitHub API: $_"
}
$Tag = $Release.tag_name
if (-not $Tag) { Write-Err 'Could not determine latest release tag.' }
Write-Info "Latest release: $Tag"

$BaseUrl = "https://github.com/$Repo/releases/download/$Tag"

# ── download to temp directory ────────────────────────────────────────────────
$TmpDir = Join-Path $env:TEMP "arktunnel-install-$([System.IO.Path]::GetRandomFileName())"
New-Item -ItemType Directory -Path $TmpDir | Out-Null

try {
    Write-Info "Downloading $Artifact..."
    Invoke-WebRequest -Uri "$BaseUrl/$Artifact"  -OutFile (Join-Path $TmpDir $Artifact)  -UseBasicParsing

    Write-Info 'Downloading SHA256SUMS...'
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile (Join-Path $TmpDir 'SHA256SUMS') -UseBasicParsing

    # ── verify SHA256 ─────────────────────────────────────────────────────────
    Write-Info 'Verifying checksum...'
    $SumsFile = Get-Content (Join-Path $TmpDir 'SHA256SUMS')
    $ExpectedLine = $SumsFile | Where-Object { $_ -match [regex]::Escape($Artifact) }
    if (-not $ExpectedLine) { Write-Err "No checksum entry found for $Artifact in SHA256SUMS." }

    $ExpectedHash = ($ExpectedLine -split '\s+')[0].ToUpper()
    $ActualHash   = (Get-FileHash -Algorithm SHA256 (Join-Path $TmpDir $Artifact)).Hash.ToUpper()

    if ($ActualHash -ne $ExpectedHash) {
        Write-Err "Checksum mismatch!`n  Expected: $ExpectedHash`n  Got:      $ActualHash"
    }
    Write-Info 'Checksum OK.'

    # ── install ───────────────────────────────────────────────────────────────
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
    }

    $Dest = Join-Path $InstallDir $BinaryName
    Copy-Item (Join-Path $TmpDir $Artifact) -Destination $Dest -Force
    Write-Info "Installed to $Dest"

    # ── tun2socks (full-device mode) ────────────────────────────────────────
    if ($env:NO_TUN2SOCKS -ne '1') {
        $T_Asset = 'tun2socks-windows-amd64.zip'
        $T_Url   = "https://github.com/xjasonlyu/tun2socks/releases/download/$Tun2SocksVersion/$T_Asset"
        Write-Info "Downloading tun2socks $Tun2SocksVersion ..."
        Invoke-WebRequest -Uri $T_Url -OutFile (Join-Path $TmpDir $T_Asset) -UseBasicParsing
        Expand-Archive -Path (Join-Path $TmpDir $T_Asset) -DestinationPath $TmpDir -Force
        Copy-Item (Join-Path $TmpDir 'tun2socks-windows-amd64.exe') `
            -Destination (Join-Path $InstallDir 'tun2socks.exe') -Force
        Write-Info "tun2socks installed at $(Join-Path $InstallDir 'tun2socks.exe')"
        Write-Info "Note: Wintun driver is required — see https://www.wintun.net/"
    }

    # ── add to user PATH if not already present ───────────────────────────────
    $UserPath = [System.Environment]::GetEnvironmentVariable('PATH', 'User')
    if ($UserPath -notlike "*$InstallDir*") {
        [System.Environment]::SetEnvironmentVariable(
            'PATH',
            "$InstallDir;$UserPath",
            'User'
        )
        Write-Info "Added $InstallDir to your user PATH."
        Write-Info "(Restart your terminal for the PATH change to take effect.)"
    }

} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}

Write-Info ''
Write-Info "ark-client $Tag installed successfully."
Write-Info ''
Write-Info "Usage:"
Write-Info "  ark-client run --uri 'arktunnel://<uuid>@<server>:<port>?transport=bip324'"
Write-Info ''
Write-Info "Point your app's proxy settings to:"
Write-Info "  SOCKS5    127.0.0.1:1080"
Write-Info "  HTTP      127.0.0.1:8118"
Write-Info ''
Write-Info "For full-device mode (route everything through ArkTunnel):"
Write-Info "  Open an elevated terminal and run:"
Write-Info "    ark-client tun --uri 'arktunnel://...'"
