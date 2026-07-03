$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$wheelDir = Join-Path $projectRoot "vendor\wheels"

New-Item -ItemType Directory -Force -Path $wheelDir | Out-Null

$python = Get-Command py -ErrorAction SilentlyContinue
if ($python) {
  $pythonExe = "py"
  $pythonArgs = @("-3")
} else {
  $python = Get-Command python -ErrorAction SilentlyContinue
  if (-not $python) {
    throw "Python 3 est introuvable. Installe Python avant de preparer le package offline."
  }
  $pythonExe = "python"
  $pythonArgs = @()
}

Write-Host "Telechargement des wheels dans $wheelDir"
& $pythonExe @pythonArgs -m pip download `
  --dest $wheelDir `
  --only-binary=:all: `
  -r (Join-Path $projectRoot "requirements.txt")

Write-Host ""
Write-Host "Dossier offline pret: $wheelDir"
Write-Host "Tu peux maintenant creer le zip avec .\make_release_zip.ps1"
