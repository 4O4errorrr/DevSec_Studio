@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
  set "PY=py -3"
) else (
  where python >nul 2>nul
  if %errorlevel%==0 (
    set "PY=python"
  ) else (
    echo Python 3 est introuvable. Installe Python depuis https://www.python.org/downloads/
    pause
    exit /b 1
  )
)

if not exist ".venv\Scripts\python.exe" (
  echo Creation de l'environnement virtuel...
  %PY% -m venv .venv
)

echo Installation des dependances...
".venv\Scripts\python.exe" -m pip install -r requirements.txt

if not exist ".env" (
  echo Generation du fichier .env local...
  ".venv\Scripts\python.exe" -c "import secrets; print('FLASK_SECRET_KEY=' + secrets.token_hex(32)); print('FLAG_SECRET=' + secrets.token_hex(32))" > .env
)

for /f "usebackq tokens=1,* delims==" %%A in (".env") do set "%%A=%%B"

echo.
echo DevSec Studio demarre sur http://127.0.0.1:5000
echo Ferme cette fenetre ou fais Ctrl+C pour arreter.
echo.
".venv\Scripts\python.exe" app.py

pause
