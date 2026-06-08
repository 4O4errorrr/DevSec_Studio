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
  ".env.example",
  "templates",
  "static"
)

foreach ($item in $items) {
  Copy-Item -Path (Join-Path $projectRoot $item) -Destination $packageDir -Recurse -Force
}

if (Test-Path $zipPath) {
  Remove-Item -Force $zipPath
}
Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $zipPath

Write-Host "Release creee: $zipPath"
