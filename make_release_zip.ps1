$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$releaseDir = Join-Path $projectRoot "release"
$packageDir = Join-Path $releaseDir "DevSec_Studio"
$zipPath = Join-Path $releaseDir "DevSec_Studio_local.zip"

if (Test-Path $packageDir) {
  Remove-Item -Recurse -Force $packageDir
}
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null

$items = @(
  "app.py",
  "requirements.txt",
  "README.md",
  "start_windows.bat",
  "start_unix.sh",
  "prepare_offline_wheels.ps1",
  "prepare_offline_wheels.sh",
  ".env.example",
  "templates",
  "static",
  "vendor"
)

foreach ($item in $items) {
  $source = Join-Path $projectRoot $item
  if (Test-Path $source) {
    Copy-Item -Path $source -Destination $packageDir -Recurse -Force
  }
}

if (Test-Path $zipPath) {
  Remove-Item -Force $zipPath
}
Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $zipPath

Write-Host "Release creee: $zipPath"
