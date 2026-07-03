# DevSec Studio

Un environnement local volontairement vulnérable pour s'exercer à identifier les failles de sécurité les plus courantes pouvant se glisser dans du code.

> A utiliser uniquement en local. Ne pas exposer sur Internet.
> 
<img width="1693" height="929" alt="image" src="https://github.com/user-attachments/assets/aaa7fc62-b8d8-4e80-9b19-17eb83773d0a" />

## Lancer le lab

### Windows

Double-clique sur:

```text
start_windows.bat
```

### WSL, Linux ou macOS

```bash
chmod +x start_unix.sh
./start_unix.sh
```

Ouvre ensuite:

```text
http://127.0.0.1:5000
```

## Mode hors ligne

Avant l'atelier, avec Internet:

```powershell
.\prepare_offline_wheels.ps1
.\make_release_zip.ps1
```

Le zip généré contient alors `vendor/wheels`. Les scripts de lancement installeront les dépendances depuis ce dossier, sans joindre PyPI.

## Comptes

```text
alice / alice
bob / bob
charlie / charlie
```

## Objectif

Explore l'application à ton rythme et pars à la chasse aux failles dissimulées dans les tickets, exports, webhooks, notifications et profils. Des indices sont semés dans chaque écran pour t'accompagner mais avant d'y recourir, rappelle-toi qu'en cybersécurité, la curiosité et la recherche sont tes meilleures armes.
