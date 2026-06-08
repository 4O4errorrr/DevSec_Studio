# DevSec Studio

Application Flask volontairement vulnerable pour atelier local de sensibilisation securite developpeur.

> Ne pas exposer cette application sur Internet. Elle contient volontairement des vulnerabilites.

## Lancement rapide

### Windows

Double-clique sur:

```text
start_windows.bat
```

Ou depuis PowerShell:

```powershell
.\start_windows.bat
```

### WSL, Linux ou macOS

```bash
chmod +x start_unix.sh
./start_unix.sh
```

Ouvre ensuite <http://127.0.0.1:5000>.

Les scripts creent automatiquement l'environnement virtuel, installent les dependances et generent un fichier `.env` local avec les secrets necessaires.

## Lancement manuel

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Sur Windows, l'equivalent est:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

## Docker optionnel

```bash
docker compose up --build
```

Puis ouvre <http://127.0.0.1:5000>.

## Comptes de test

- `alice` / `alice`
- `bob` / `bob`
- `charlie` / `charlie`

## Challenges

Les 10 challenges sont orientes vers des erreurs plausibles qu'un developpeur peut introduire et qui peuvent conduire a une fuite de donnees. La mission "La console oubliee" contient aussi un quiz bonus avec un flag supplementaire:

1. Le ticket voisin.
2. Le centre documentaire.
3. Le mur de feedback.
4. Le testeur webhook.
5. La console oubliee.
6. Le jeton lisible.
7. Le lien magique.
8. L'annuaire trop bavard.
9. Les traces de debug.
10. Le profil trop flexible.

Chaque page de mission contient deux niveaux d'indice:

- Indice 1: la famille de vulnerabilite a envisager.
- Indice 2: une piste concrete pour avancer.

## Guide d'animation

Le guide facilitateur n'est pas stocke dans ce dossier projet afin de ne pas etre donne aux participants avec l'application.

## Flags et scoreboard

Quand une mission est exploitee avec succes, la page affiche:

- un message de reussite;
- une synthese de la vulnerabilite exploitee;
- l'impact possible dans un contexte reel;
- un flag au format `QOS_SEC_...`.

La progression de la session courante est visible dans le menu et sur la page `/scoreboard`.

Les flags sont generes au demarrage a partir de `FLAG_SECRET`; ils ne doivent pas etre commites en clair.

## Distribution

Voir [RELEASE.md](RELEASE.md). Le plus simple pour un atelier sans Docker est de distribuer le dossier avec `start_windows.bat` et `start_unix.sh`. Si tu veux eviter que les participants aient acces au code source, distribue plutot une image Docker preconstruite.
