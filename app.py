import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from flask import Flask, jsonify, redirect, render_template, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix


def load_dotenv_file(path=".env"):
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key, value)


load_dotenv_file()

app = Flask(__name__)
if os.environ.get("PORT"):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
FLAG_SECRET = os.environ.get("FLAG_SECRET", secrets.token_hex(32))
app.config["SUPPORT_EXPORT_TOKEN"] = "support-export-dev-42"
app.config["NOTIFICATION_SIGNING_KEY"] = "notify-signing-key-lab"
SCORES_BY_PARTICIPANT = {}
DEBUG_FILES_DIR = Path(__file__).resolve().parent / "debug_files"


def build_flag(challenge_id):
    digest = hmac.new(FLAG_SECRET.encode("utf-8"), challenge_id.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"QOS_SEC_{digest[:10].upper()}"

USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "password": "alice",
        "role": "developer",
        "email": "alice@devsec.local",
        "team": "Frontend",
        "ticket_ids": [101],
        "export_allowed": False,
    },
    2: {
        "id": 2,
        "username": "bob",
        "password": "bob",
        "role": "lead",
        "email": "bob@devsec.local",
        "team": "Backend",
        "ticket_ids": [102],
        "export_allowed": True,
    },
    3: {
        "id": 3,
        "username": "charlie",
        "password": "charlie",
        "role": "admin",
        "email": "charlie@devsec.local",
        "team": "Platform",
        "ticket_ids": [103],
        "export_allowed": True,
    },
}

USER_BASELINE = {
    user_id: {
        "email": user["email"],
        "team": user["team"],
        "role": user["role"],
        "export_allowed": user["export_allowed"],
    }
    for user_id, user in USERS.items()
}

TICKETS = {
    101: {
        "id": 101,
        "owner_id": 1,
        "title": "Erreur paiement sandbox",
        "customer": "Northwind Labs",
        "details": "Carte de test rattachée à alice.demo@customer.local",
    },
    102: {
        "id": 102,
        "owner_id": 2,
        "title": "Export client lent",
        "customer": "BlueRiver Health",
        "details": "L'export contient des e-mails, des contrats et des références internes.",
    },
    103: {
        "id": 103,
        "owner_id": 3,
        "title": "Rotation secret API",
        "customer": "Internal Platform",
        "details": "Secret legacy visible dans un ancien dump de configuration.",
    },
}

FEEDBACKS = [
    {"author": "alice", "content": "Le dashboard de revue de code est beaucoup plus clair.", "rendered": "Le dashboard de revue de code est beaucoup plus clair."},
    {"author": "bob", "content": "À vérifier : les exports doivent rester accessibles aux leads seulement.", "rendered": "À vérifier : les exports doivent rester accessibles aux leads seulement."},
]

SECURITY_LOGS = [
    "09:02 user=alice action=login status=success",
    "09:04 user=bob action=dashboard status=success",
    "09:08 job=debug-cleanup status=success",
]

PRIVATE_FILES = {
    "customer_export.csv": "email,contract,value\nceo@blueriver.local,BR-2026-001,92000\nops@northwind.local,NW-2026-117,43000\n",
    "api_keys.txt": "LEGACY_API_KEY=sk_lab_legacy_do_not_use\nREPORT_TOKEN=report-dev-7788\n",
}

PUBLIC_FILES = {
    "docs/release-notes.txt": "DevSec Studio 0.9 - ajout du module exports et du proxy webhook.\n",
    "docs/onboarding.txt": "Bienvenue dans le portail interne de formation sécurité développeur.\n",
    "docs/procedure-export.txt": "Procédure export : les exports clients doivent être produits uniquement depuis le module Reporting, réservé aux leads.\n",
    "notes/engineering-notes.txt": "Note dev : les exports clients ne doivent jamais être servis par ce module. Backup temporaire observé pendant les tests de chemin : ../private/customer_export.csv\n",
}

DOCUMENTS = [
    {
        "title": "Notes de version",
        "category": "Produit",
        "owner": "Equipe Platform",
        "storage_key": "docs/release-notes.txt",
        "visibility": "Public interne",
    },
    {
        "title": "Onboarding développeur",
        "category": "RH / IT",
        "owner": "Equipe DevRel",
        "storage_key": "docs/onboarding.txt",
        "visibility": "Public interne",
    },
    {
        "title": "Procédure export",
        "category": "Reporting",
        "owner": "Equipe Data",
        "storage_key": "docs/procedure-export.txt",
        "visibility": "Public interne",
    },
    {
        "title": "Notes d'intégration",
        "category": "Développement",
        "owner": "Equipe Platform",
        "storage_key": "notes/engineering-notes.txt",
        "visibility": "Dev interne",
    },
]

PROMOS = [
    ("alice@devsec.local", "Frontend", "Vue tickets frontend"),
    ("bob@devsec.local", "Backend", "Accès exports clients"),
    ("charlie@devsec.local", "Platform", "Accès administration"),
]

CHALLENGES = {
    "ticket": {
        "name": "Le ticket voisin",
        "flag": build_flag("ticket"),
        "vulnerability": "Contrôle d'accès défaillant : un utilisateur connecté peut consulter un objet qui ne lui appartient pas.",
        "why": "La route `/ticket/<id>` vérifie seulement que l'utilisateur est connecté, puis charge le ticket demandé sans comparer `owner_id` avec l'utilisateur courant.",
        "impact": "Avec un vrai attaquant, cela peut exposer des tickets clients, contrats, incidents ou données personnelles par simple modification d'URL.",
        "fix": "Vérifier l'autorisation côté serveur pour chaque objet, tester les accès avec plusieurs comptes et refuser les objets hors périmètre.",
    },
    "download": {
        "name": "Le centre documentaire",
        "flag": build_flag("download"),
        "vulnerability": "Path traversal : un chemin fourni par l'utilisateur permet de lire un fichier hors de la zone prévue.",
        "why": "Le paramètre `file` est utilisé directement pour choisir un fichier, et l'application accepte le préfixe `../private/`.",
        "impact": "Avec un vrai attaquant, cela peut mener à la fuite d'exports clients, fichiers de configuration, clés API ou sauvegardes internes.",
        "fix": "Utiliser une liste blanche de fichiers, normaliser les chemins et interdire toute navigation hors du répertoire prévu.",
    },
    "feedback": {
        "name": "Le mur de feedback",
        "flag": build_flag("feedback"),
        "vulnerability": "XSS stockée : un contenu utilisateur est enregistré puis rendu comme du HTML actif.",
        "why": "Le message est stocké tel quel, puis affiché dans le template avec `| safe`, ce qui désactive l'échappement HTML.",
        "impact": "Avec un vrai attaquant, du JavaScript pourrait s'exécuter chez d'autres utilisateurs, voler des sessions ou afficher de faux contenus.",
        "fix": "Échapper les sorties par défaut, éviter `| safe` sur les entrées utilisateur et appliquer une Content Security Policy.",
    },
    "webhook": {
        "name": "Le testeur webhook",
        "flag": build_flag("webhook"),
        "vulnerability": "SSRF : le serveur effectue une requête vers une URL contrôlée par l'utilisateur.",
        "why": "Le paramètre `url` est transmis à `urlopen`, ce qui permet au serveur d'interroger des ressources internes.",
        "impact": "Avec un vrai attaquant, cela peut exposer des endpoints internes, métadonnées cloud, tokens ou services non accessibles publiquement.",
        "fix": "Utiliser une liste blanche stricte, bloquer les adresses internes et isoler les services accessibles depuis le serveur.",
    },
    "debug": {
        "name": "La console oubliée",
        "flag": build_flag("debug"),
        "vulnerability": "Mauvaise configuration : un listing de répertoire expose un fichier de configuration et des identifiants.",
        "why": "La route `/debug/config` expose un répertoire listable. Le fichier `README.txt` divulgue `/adminoos`, et `app.conf` contient des identifiants de consultation.",
        "impact": "Avec un vrai attaquant, cela peut exposer des secrets, chemins internes, endpoints privés et faciliter une compromission en chaîne.",
        "fix": "Désactiver le directory listing, protéger les outils de debug et ne jamais stocker d'identifiants en clair dans des fichiers exposés.",
    },
    "debug_quiz": {
        "name": "Bonus - Diagnostic du listing",
        "flag": build_flag("debug_quiz"),
        "vulnerability": "Directory listing : le serveur liste le contenu d'un répertoire au lieu de refuser l'accès.",
        "why": "La page imite un index de fichiers public pour `/debug/`, ce qui révèle noms, dates et types de fichiers.",
        "impact": "Avec un vrai attaquant, un listing donne une carte de reconnaissance : sauvegardes, configurations, archives ou indices exploitables.",
        "fix": "Désactiver le listing automatique et servir uniquement des fichiers explicitement autorisés.",
    },
    "token": {
        "name": "Le jeton lisible",
        "flag": build_flag("token"),
        "vulnerability": "Défaillance cryptographique : le token est seulement encodé en base64, sans signature ni chiffrement.",
        "why": "La fonction `decode_token` accepte le contenu décodé sans vérifier d'intégrité : un utilisateur peut modifier le JSON puis le réencoder.",
        "impact": "Avec un vrai attaquant, des attributs de session, privilèges ou autorisations côté client pourraient être modifiés.",
        "fix": "Signer les jetons, vérifier leur intégrité et garder les autorisations sensibles côté serveur.",
    },
    "admin": {
        "name": "Le lien magique",
        "flag": build_flag("admin"),
        "vulnerability": "Authentification incorrecte : un lien de connexion sans mot de passe utilise un token prédictible.",
        "why": "La fonction `magic_token` dérive le token depuis la partie locale de l'e-mail, par exemple `alice.devsec`.",
        "impact": "Avec un vrai attaquant, il serait possible de forger un lien pour prendre le contrôle d'un autre compte sans connaître son mot de passe.",
        "fix": "Générer des tokens longs, aléatoires, à usage unique, expirables et stockés côté serveur.",
    },
    "people": {
        "name": "L'annuaire trop bavard",
        "flag": build_flag("people"),
        "vulnerability": "Injection SQL : une entrée utilisateur est concaténée directement dans une requête.",
        "why": "Le champ `email` est inséré dans une chaîne SQL avec une f-string au lieu d'utiliser une requête paramétrée.",
        "impact": "Avec un vrai attaquant, une injection peut extraire des données internes, contourner des filtres ou modifier la base.",
        "fix": "Utiliser des requêtes paramétrées, ne pas afficher les erreurs SQL brutes et tester les entrées avec des caractères spéciaux.",
    },
    "logs": {
        "name": "Le modèle de notification",
        "flag": build_flag("logs"),
        "vulnerability": "SSTI : un modèle fourni par l'utilisateur est interprété par le moteur de template côté serveur.",
        "why": "La route `/notification-preview` passe directement le modèle utilisateur à `render_template_string`.",
        "impact": "Avec un vrai attaquant, une SSTI peut exposer la configuration applicative, des secrets ou des tokens internes.",
        "fix": "Ne jamais interpréter une entrée utilisateur comme template serveur ; utiliser des modèles prédéfinis et injecter seulement des variables contrôlées.",
    },
    "profile": {
        "name": "Le profil trop flexible",
        "flag": build_flag("profile"),
        "vulnerability": "Mass assignment : le serveur accepte et applique des champs qui ne devraient pas être modifiables.",
        "why": "La route `/api/profile` parcourt tous les champs JSON reçus et les copie dans l'objet utilisateur sans liste blanche.",
        "impact": "Avec un vrai attaquant, un utilisateur peut changer son rôle et obtenir des droits d'administration sans workflow d'autorisation.",
        "fix": "Définir une liste blanche stricte des champs modifiables et ignorer tout champ sensible reçu depuis le client.",
    },
}


def current_user():
    user_id = session.get("user_id")
    return USERS.get(user_id)


def current_profile():
    user = current_user()
    if not user:
        return None
    profile = session.get("profile_state")
    if not profile or profile.get("id") != user["id"]:
        baseline = USER_BASELINE[user["id"]]
        profile = {
            "id": user["id"],
            "username": user["username"],
            "email": baseline["email"],
            "team": baseline["team"],
            "role": baseline["role"],
        }
        session["profile_state"] = profile
        session.modified = True
    return profile


def client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.headers.get("X-Real-IP") or request.remote_addr or "local"


def use_ip_scoreboard():
    return bool(os.environ.get("PORT"))


def participant_name():
    return session.get("participant_name", "").strip()


def participant_key():
    name = participant_name()
    if name:
        raw = f"name:{name.lower()}"
    elif use_ip_scoreboard():
        raw = f"ip:{client_ip()}"
    else:
        raw = session.setdefault("participant_id", secrets.token_hex(12))
    return hmac.new(FLAG_SECRET.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def participant_label():
    return participant_name() or f"Participant {participant_key()[:8]}"


def public_base_url():
    return request.host_url.rstrip("/")


def allowed_webhook_hosts():
    current_host = urlparse(public_base_url()).hostname
    hosts = {"127.0.0.1", "localhost"}
    if current_host:
        hosts.add(current_host)
    return hosts


def solved_ids():
    if use_ip_scoreboard():
        return set(SCORES_BY_PARTICIPANT.get(participant_key(), []))
    solved_by_participant = session.get("solved_by_participant", {})
    return set(solved_by_participant.get(participant_key(), []))


def mark_solved(challenge_id):
    solved = solved_ids()
    solved.add(challenge_id)
    if use_ip_scoreboard():
        SCORES_BY_PARTICIPANT[participant_key()] = sorted(solved)
    else:
        solved_by_participant = session.setdefault("solved_by_participant", {})
        solved_by_participant[participant_key()] = sorted(solved)
        session.modified = True
    return CHALLENGES[challenge_id]


def challenge_status():
    solved = solved_ids()
    return [
        {"id": key, **value, "solved": key in solved}
        for key, value in CHALLENGES.items()
    ]


def build_people_db():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE people(email TEXT, team TEXT, access_note TEXT)")
    connection.executemany("INSERT INTO people(email, team, access_note) VALUES (?, ?, ?)", PROMOS)
    return connection


def render_feedback_markup(content):
    # VULNERABLE BY DESIGN: this partial Markdown renderer keeps raw HTML.
    rendered = content
    rendered = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", rendered)
    rendered = re.sub(r"_(.+?)_", r"<em>\1</em>", rendered)
    rendered = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", r'<img src="\2" alt="\1">', rendered)
    rendered = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', rendered)
    return rendered


def encode_token(payload):
    raw = json.dumps(payload).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def decode_token(data):
    try:
        return json.loads(base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return {"error": "Token illisible"}


@app.context_processor
def inject_user():
    return {
        "current_user": current_user(),
        "solved_count": len(solved_ids()),
        "total_challenges": len(CHALLENGES),
        "participant_label": participant_label(),
        "participant_name": participant_name(),
        "render_mode": bool(os.environ.get("PORT")),
    }


@app.before_request
def require_participant_name():
    allowed_endpoints = {
        "welcome",
        "static",
        "partner_callback_status",
        "internal_health",
        "internal_metadata",
        "internal_secrets",
    }
    if request.endpoint in allowed_endpoints or request.endpoint is None:
        return None
    if not participant_name():
        return redirect(url_for("welcome", next=request.path))
    return None


@app.route("/", methods=["GET", "POST"])
def welcome():
    error = None
    if request.method == "POST":
        pseudo = request.form.get("pseudo", "").strip()
        pseudo = re.sub(r"\s+", " ", pseudo)
        if not 2 <= len(pseudo) <= 32:
            error = "Choisis un pseudo entre 2 et 32 caractères."
        else:
            session["participant_name"] = pseudo
            session.modified = True
            next_url = request.form.get("next") or url_for("index")
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = url_for("index")
            return redirect(next_url)
    return render_template("welcome.html", error=error, next_url=request.args.get("next", url_for("index")))


@app.route("/challenges")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    team_members = [
        {
            "name": "Alice",
            "role": "Développeuse frontend",
            "focus": "Elle construit les écrans produit, les formulaires et les parcours utilisateurs.",
            "note": "Son quotidien : aller vite, rendre l'interface claire et éviter que le navigateur devienne une zone de confiance implicite.",
        },
        {
            "name": "Bob",
            "role": "Développeur backend",
            "focus": "Il maintient les API, les webhooks, les exports et les accès aux données internes.",
            "note": "Son enjeu : vérifier que chaque entrée reçue par le serveur est contrôlée avant d'être utilisée.",
        },
        {
            "name": "Charlie",
            "role": "Développeur plateforme",
            "focus": "Il s'occupe des configurations, des outils de debug, des notifications et de l'exploitation locale.",
            "note": "Son point d'attention : ne pas laisser un détail technique devenir une fuite d'information exploitable.",
        },
    ]
    return render_template("about.html", team_members=team_members)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        for user in USERS.values():
            if user["username"] == username and user["password"] == password:
                session["user_id"] = user["id"]
                return redirect(url_for("dashboard"))
        SECURITY_LOGS.append(f"user={username} action=login status=failed password={password}")
        error = "Identifiants invalides"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if not current_user():
        return redirect(url_for("login"))
    user = current_user()
    visible_tickets = [TICKETS[ticket_id] for ticket_id in user["ticket_ids"]]
    return render_template("dashboard.html", tickets=visible_tickets)


@app.route("/ticket/<int:ticket_id>")
def ticket(ticket_id):
    if not current_user():
        return redirect(url_for("login"))
    # VULNERABLE BY DESIGN: IDOR.
    # The route checks authentication but not ownership of the ticket.
    item = TICKETS.get(ticket_id)
    if not item:
        return render_template("not_found.html"), 404
    success = None
    if item["owner_id"] != current_user()["id"]:
        success = mark_solved("ticket")
    return render_template("ticket.html", ticket=item, success=success)


@app.route("/download")
def download():
    filename = request.args.get("file", "docs/release-notes.txt")
    # VULNERABLE BY DESIGN: path traversal simulation.
    # The app trusts a user-controlled path and allows ../private/* to be reached.
    if filename.startswith("../private/"):
        key = filename.replace("../private/", "", 1)
        content = PRIVATE_FILES.get(key)
    else:
        content = PUBLIC_FILES.get(filename)
    if content is None:
        content = "Fichier introuvable."
    success = mark_solved("download") if filename.startswith("../private/") and content != "Fichier introuvable." else None
    return render_template(
        "download.html",
        filename=filename,
        content=content,
        documents=DOCUMENTS,
        success=success,
    )


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        content = request.form.get("content", "")
        # VULNERABLE BY DESIGN: stored XSS.
        # User input is converted with an incomplete Markdown renderer, then rendered with |safe in the template.
        FEEDBACKS.append({"author": author, "content": content, "rendered": render_feedback_markup(content)})
        if any(marker in content.lower() for marker in ["<script", "onerror=", "onload=", "javascript:"]):
            mark_solved("feedback")
        return redirect(url_for("feedback"))
    success = CHALLENGES["feedback"] if "feedback" in solved_ids() else None
    return render_template("feedback.html", feedbacks=FEEDBACKS, success=success)


@app.route("/webhook-tester")
def webhook_tester():
    target = request.args.get("url", url_for("partner_callback_status", _external=True))
    body = ""
    error = None
    parsed = urlparse(target)
    try:
        if parsed.hostname not in allowed_webhook_hosts():
            raise ValueError("Lab: le proxy est limité à l'hôte de cette application pour éviter les abus.")
        # VULNERABLE BY DESIGN: SSRF-like local proxy.
        req = Request(target, headers={"X-DevSec-Proxy": "1"})
        with urlopen(req, timeout=2) as response:
            body = response.read().decode("utf-8")
    except Exception as exc:
        error = str(exc)
    success = None
    if "INTERNAL_REPORT_TOKEN" in body:
        success = mark_solved("webhook")
    return render_template("webhook.html", target=target, body=body, error=error, success=success)


@app.route("/callbacks/partner-status")
def partner_callback_status():
    return "callback=ok; partner=acme-payments; last_check=green; diagnostic_ref=/internal/health"


@app.route("/internal/metadata")
def internal_metadata():
    return f"service=reporting; env=dev; host={request.host}; internal_prefix=/internal; audit_route=secrets; backup=../private/customer_export.csv"


@app.route("/internal/health")
def internal_health():
    return "ok=true; service=public-webhook-health; metadata_ref=/internal/metadata"


@app.route("/internal/secrets")
def internal_secrets():
    if request.headers.get("X-DevSec-Proxy") != "1":
        return "Interne uniquement.", 403
    return "INTERNAL_REPORT_TOKEN=report-dev-7788"


@app.route("/debug/")
def debug_root():
    return redirect(url_for("debug_config"))


@app.route("/debug/config")
def debug_config():
    return render_debug_directory()


@app.route("/debug/config/<path:selected_file>")
def debug_file(selected_file):
    return render_debug_directory(selected_file)


def full_debug_config():
    return (
        "APP_ENV=development\n"
        "DEBUG=true\n"
        "BACKUP_EXPORT=../private/customer_export.csv\n"
        "LEGACY_KEYS_FILE=../private/api_keys.txt\n"
        f"INTERNAL_METADATA={url_for('internal_metadata', _external=True)}\n"
        "CONFIG_VIEWER_LOGIN=config_reader\n"
        "CONFIG_VIEWER_PASSWORD=reader-2026\n"
        f"FLAG={CHALLENGES['debug']['flag']}\n"
    )


def render_debug_directory(selected_file=None):
    # VULNERABLE BY DESIGN: security misconfiguration.
    # A debug endpoint exposes details useful in later challenges.
    files = []
    for path in sorted(DEBUG_FILES_DIR.iterdir()):
        if not path.is_file():
            continue
        stat = path.stat()
        files.append(
            {
                "name": path.name,
                "modified": "2026-06-04 09:18" if path.name == "app.conf" else "2026-06-04 09:12",
                "size": f"{stat.st_size} B",
                "description": "Configuration" if path.name == "app.conf" else "Fichier texte",
            }
        )
    if selected_file is None:
        selected_file = request.args.get("file", "")
    content = None
    selected_path = (DEBUG_FILES_DIR / selected_file).resolve() if selected_file else None
    if selected_path and selected_path.parent == DEBUG_FILES_DIR and selected_path.is_file():
        content = selected_path.read_text(encoding="utf-8")
    success = None

    quiz_answer = request.args.get("quiz", "")
    quiz_success = None
    if "directory" in quiz_answer.lower() and "listing" in quiz_answer.lower():
        quiz_success = mark_solved("debug_quiz")

    return render_template(
        "debug_config.html",
        files=files,
        selected_file=selected_file,
        content=content,
        success=success,
        quiz_success=quiz_success,
    )


@app.route("/adminoos", methods=["GET", "POST"])
def adminoos():
    content = None
    error = None
    success = None
    login = ""
    if request.method == "POST":
        login = request.form.get("user", "")
        password = request.form.get("password", "")
        if login == "config_reader" and password == "reader-2026":
            content = full_debug_config()
            success = mark_solved("debug")
        else:
            error = "Identifiants invalides."
    return render_template("adminoos.html", content=content, error=error, login=login, success=success)


@app.route("/token")
def token():
    sample = encode_token({"user": "alice", "role": "developer", "export_allowed": False})
    data = request.args.get("data", sample)
    # VULNERABLE BY DESIGN: cryptographic failure.
    # The token is base64-encoded but not encrypted or signed.
    payload = decode_token(data)
    success = None
    can_export = payload.get("export_allowed") is True or payload.get("role") in {"lead", "admin"}
    if data != sample and can_export:
        success = mark_solved("token")
    export_preview = PRIVATE_FILES["customer_export.csv"] if can_export else None
    return render_template(
        "token.html",
        data=data,
        payload=payload,
        sample=sample,
        can_export=can_export,
        export_preview=export_preview,
        success=success,
    )


@app.route("/admin-gate", methods=["GET", "POST"])
def admin_gate():
    target_email = "alice@devsec.local"
    magic_link = url_for("magic_login", email=target_email, token=magic_token(target_email), _external=False)
    tested_link = request.form.get("magic_link", "")
    result_user = None
    error = None
    success = None
    if request.method == "POST":
        if tested_link:
            parsed = urlparse(tested_link)
            params = dict([part.split("=", 1) for part in parsed.query.split("&") if "=" in part])
            result_user, error = verify_magic_link(params.get("email", ""), params.get("token", ""))
            if result_user and result_user["email"] != "alice@devsec.local":
                success = mark_solved("admin")
        SECURITY_LOGS.append("user=alice@devsec.local action=magic-link status=tested")
    return render_template(
        "admin_gate.html",
        target_email=target_email,
        magic_link=magic_link,
        tested_link=tested_link,
        result_user=result_user,
        error=error,
        success=success,
    )


def magic_token(email):
    # VULNERABLE BY DESIGN: predictable token.
    local_part = email.split("@", 1)[0]
    return f"{local_part}.devsec"


def verify_magic_link(email, token):
    user = next((item for item in USERS.values() if item["email"] == email), None)
    if not user:
        return None, "Compte introuvable."
    if token != magic_token(email):
        return None, "Token invalide."
    return user, None


@app.route("/magic-login")
def magic_login():
    result_user, error = verify_magic_link(request.args.get("email", ""), request.args.get("token", ""))
    if not result_user:
        return error or "Lien invalide.", 403
    session["user_id"] = result_user["id"]
    if result_user["email"] != "alice@devsec.local":
        mark_solved("admin")
    return redirect(url_for("dashboard"))


@app.route("/people-search")
def people_search():
    email = request.args.get("email", "alice@devsec.local")
    diagnostic = request.args.get("diagnostic") == "1"
    connection = build_people_db()
    # VULNERABLE BY DESIGN: SQL injection.
    query = f"SELECT email, team, access_note FROM people WHERE email = '{email}'"
    try:
        rows = connection.execute(query).fetchall()
        error = None
    except sqlite3.Error as exc:
        rows = []
        error = str(exc)
    success = mark_solved("people") if len(rows) > 1 else None
    return render_template(
        "people_search.html",
        email=email,
        query=query,
        rows=rows,
        error=error,
        diagnostic=diagnostic,
        sample_emails=[item[0] for item in PROMOS],
        success=success,
    )


@app.route("/notification-preview", methods=["GET", "POST"])
def notification_preview():
    app.config["FLAG"] = CHALLENGES["logs"]["flag"]
    template = request.form.get("template", "Bonjour {{ name }}, votre ticket {{ ticket_id }} est prêt.")
    rendered = ""
    error = None
    context = {
        "name": "Alice",
        "ticket_id": "101",
        "product": "DevSec Studio",
        "notification_type": "support",
    }
    try:
        # VULNERABLE BY DESIGN: SSTI.
        # A user-controlled string is rendered as a server-side Jinja template.
        rendered = render_template_string(template, **context)
    except Exception as exc:
        error = str(exc)
    success = None
    if CHALLENGES["logs"]["flag"] in rendered:
        success = mark_solved("logs")
    return render_template("notification_preview.html", template=template, rendered=rendered, error=error, success=success)


@app.route("/profile-editor")
def profile_editor():
    if not current_user():
        return redirect(url_for("login"))
    user = current_profile()
    expected_profile = USER_BASELINE[user["id"]]
    success = CHALLENGES["profile"] if "profile" in solved_ids() else None
    return render_template("profile_editor.html", user=user, expected_profile=expected_profile, success=success)


@app.route("/api/profile", methods=["GET", "PATCH"])
def profile_api():
    user = current_profile()
    if not user:
        return jsonify({"error": "Authentification requise."}), 401
    if request.method == "GET":
        return jsonify(
            {
                "id": user["id"],
                "email": user["email"],
                "team": user["team"],
                "role": user["role"],
                "editable_fields": ["email", "team"],
            }
        )

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON attendu."}), 400

    # VULNERABLE BY DESIGN: mass assignment.
    # Every JSON field is copied into the user object, including privileged fields.
    for key, value in payload.items():
        user[key] = value
    session["profile_state"] = user
    session.modified = True

    success = None
    if payload.get("role") == "admin":
        success = mark_solved("profile")

    return jsonify(
        {
            "profile": {
                "id": user["id"],
                "email": user["email"],
                "team": user["team"],
                "role": user["role"],
            },
            "challenge": success,
        }
    )


@app.route("/scoreboard")
def scoreboard():
    return render_template("scoreboard.html", challenges=challenge_status())


if __name__ == "__main__":
    render_port = os.environ.get("PORT")
    port = int(render_port or 5000)
    host = "0.0.0.0" if render_port else "127.0.0.1"
    debug = render_port is None

    app.run(host=host, port=port, debug=debug)

