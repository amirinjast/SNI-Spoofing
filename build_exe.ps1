param(
    [string]$Name = "SNI-Spoofing-Diagnostics",
    [switch]$OneFile,
    [switch]$NoUacAdmin,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

function Write-Step($Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-Command($CommandName) {
    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw "Required command '$CommandName' was not found in PATH. Install Python and make sure it is available from this shell."
    }
}

Assert-Command python

if ($Clean) {
    Write-Step "Cleaning previous build output"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue build, dist
    Remove-Item -Force -ErrorAction SilentlyContinue "$Name.spec"
}

Write-Step "Installing runtime and build dependencies"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller

$pyInstallerArgs = @(
    "-m", "PyInstaller",
    "--name", $Name,
    "--clean",
    "--noconfirm",
    "--console",
    "--add-data", "config.json;."
)

if ($OneFile) {
    $pyInstallerArgs += "--onefile"
} else {
    $pyInstallerArgs += "--onedir"
}

if (-not $NoUacAdmin) {
    $pyInstallerArgs += "--uac-admin"
}

$pyInstallerArgs += @(
    "--hidden-import", "pydivert",
    "--hidden-import", "pydivert.windivert",
    "--hidden-import", "pydivert.windivert_dll",
    "main.py"
)

Write-Step "Building executable with PyInstaller"
python @pyInstallerArgs

if ($OneFile) {
    $ExePath = Join-Path $ProjectRoot "dist\$Name.exe"
} else {
    $ExePath = Join-Path $ProjectRoot "dist\$Name\$Name.exe"
}

if (-not (Test-Path $ExePath)) {
    throw "Build finished but executable was not found at: $ExePath"
}

Write-Step "Build complete"
Write-Host "Executable: $ExePath" -ForegroundColor Green
Write-Host "Run it from an Administrator prompt, or double-click it and accept the UAC prompt." -ForegroundColor Yellow
Write-Host "Edit config.json before building, or edit the copied config beside the exe in onedir builds." -ForegroundColor Yellow
