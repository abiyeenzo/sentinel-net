# Script d'installation rapide de Sentinel Net pour Windows (PowerShell).
# Usage : irm https://raw.githubusercontent.com/abiyeenzo/sentinel-net/main/scripts/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = if ($env:SENTINEL_NET_REPO) { $env:SENTINEL_NET_REPO } else { "abiyeenzo/sentinel-net" }
$Version = if ($env:SENTINEL_NET_VERSION) { $env:SENTINEL_NET_VERSION } else { "latest" }

$ArchRaw = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
switch ($ArchRaw) {
    "x64"   { $Arch = "amd64" }
    "arm64" { $Arch = "arm64" }
    default { throw "Architecture Windows non supportee : $ArchRaw" }
}

$Asset = "sentinel-net-windows-$Arch.exe"
if ($Version -eq "latest") {
    $BaseUrl = "https://github.com/$Repo/releases/latest/download"
} else {
    $Tag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $BaseUrl = "https://github.com/$Repo/releases/download/$Tag"
}

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\SentinelNet"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("sentinel-net-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

try {
    $TmpExe = Join-Path $TempDir $Asset
    $TmpSums = Join-Path $TempDir "SHA256SUMS.txt"

    Write-Host "Telechargement de $Asset depuis GitHub Releases..."
    Invoke-WebRequest -Uri "$BaseUrl/$Asset" -OutFile $TmpExe -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $TmpSums -UseBasicParsing

    $ExpectedLine = Get-Content $TmpSums | Where-Object { $_ -match "\s+\*?$([regex]::Escape($Asset))$" } | Select-Object -First 1
    if (-not $ExpectedLine) {
        throw "Empreinte SHA-256 introuvable pour $Asset dans SHA256SUMS.txt."
    }
    $ExpectedHash = ($ExpectedLine -split "\s+")[0].ToLowerInvariant()
    $ActualHash = (Get-FileHash -Path $TmpExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ExpectedHash) {
        throw "Echec de verification SHA-256 (attendu=$ExpectedHash, recu=$ActualHash)."
    }

    $DestExe = Join-Path $InstallDir "sentinel-net.exe"
    Move-Item -Force -Path $TmpExe -Destination $DestExe

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $UserPath) {
        [Environment]::SetEnvironmentVariable("Path", $InstallDir, "User")
    } elseif (($UserPath -split ";") -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    }
    if (($env:Path -split ";") -notcontains $InstallDir) {
        $env:Path = "$env:Path;$InstallDir"
    }

    # Creation du raccourci dans le menu Demarrer
    $StartMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Sentinel Net"
    New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut((Join-Path $StartMenuDir "Sentinel Net.lnk"))
    $Shortcut.TargetPath = $DestExe
    $Shortcut.Arguments = "gui"
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.IconLocation = "$DestExe,0"
    $Shortcut.Description = "Sentinel Net - Console d'audit reseau defensif"
    $Shortcut.Save()

    Write-Host "Installation terminee : $DestExe"
    & $DestExe --version
    Write-Host "Tapez 'sentinel-net --help' dans un terminal ou lancez 'Sentinel Net' depuis le menu Demarrer."
} finally {
    Remove-Item -Recurse -Force -Path $TempDir -ErrorAction SilentlyContinue
}
