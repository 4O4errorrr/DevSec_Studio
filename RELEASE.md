# Release et demarrage simple

## Option recommandee pour atelier local

Fournir un dossier zip contenant:

- `app.py`
- `templates/`
- `static/`
- `requirements.txt`
- `start_windows.bat`
- `start_unix.sh`
- `README.md`

Les participants lancent:

- Windows: double-clic sur `start_windows.bat`
- WSL/Linux/macOS: `./start_unix.sh`

Les scripts creent le venv, installent Flask et generent `.env`.

Limite: cette option donne le code source aux participants.

Pour generer ce zip depuis PowerShell:

```powershell
.\make_release_zip.ps1
```

Le fichier sera cree dans:

```text
release/DevSec_Studio_local.zip
```

## Option sans exposer le code source

Si les participants clonent un depot qui contient `app.py`, ils peuvent lire le code, les routes et les solutions. Pour eviter cela, distribuer une image Docker preconstruite.

### Build facilitateur

```bash
docker build -t devsec-studio:latest .
```

Avec un registre:

```bash
docker tag devsec-studio:latest ghcr.io/your-org/devsec-studio:latest
docker push ghcr.io/your-org/devsec-studio:latest
```

### Distribution participants

Donner uniquement:

- `docker-compose.release.yml`
- un `.env` contenant `FLASK_SECRET_KEY` et `FLAG_SECRET`

Lancement:

```bash
docker compose -f docker-compose.release.yml --env-file .env up
```

## Flags

Les flags ne sont plus stockes en dur dans le code. Ils sont derives de `FLAG_SECRET` au demarrage. Garder ce secret cote facilitateur.
