#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON_BIN:-python3}"

if [ ! -x ".venv/bin/python" ]; then
  echo "Creation de l'environnement virtuel..."
  "$PYTHON_BIN" -m venv .venv
fi

echo "Installation des dependances..."
.venv/bin/python -m pip install -r requirements.txt

if [ ! -f ".env" ]; then
  echo "Generation du fichier .env local..."
  .venv/bin/python -c "import secrets; print('FLASK_SECRET_KEY=' + secrets.token_hex(32)); print('FLAG_SECRET=' + secrets.token_hex(32))" > .env
fi

set -a
. ./.env
set +a

echo
echo "DevSec Studio demarre sur http://127.0.0.1:5000"
echo "Ctrl+C pour arreter."
echo
.venv/bin/python app.py
