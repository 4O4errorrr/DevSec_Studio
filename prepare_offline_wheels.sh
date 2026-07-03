#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON_BIN:-python3}"
WHEEL_DIR="vendor/wheels"

mkdir -p "$WHEEL_DIR"

echo "Telechargement des wheels dans $WHEEL_DIR"
"$PYTHON_BIN" -m pip download \
  --dest "$WHEEL_DIR" \
  --only-binary=:all: \
  -r requirements.txt

echo
echo "Dossier offline pret: $WHEEL_DIR"
echo "Tu peux maintenant creer le zip avec ./make_release_zip.ps1 depuis Windows, ou distribuer ce dossier avec le lab."
