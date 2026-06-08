import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from flask import Flask, redirect, render_template, request, session, url_for


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
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
FLAG_SECRET = os.environ.get("FLAG_SECRET", secrets.token_hex(32))


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
        "details": "Carte de test rattachee a alice.demo@customer.local",
    },
    102: {
        "id": 102,
        "owner_id": 2,
        "title": "Export client lent",
        "customer": "BlueRiver Health",
        "details": "Export contient emails, contrats et references internes.",
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
    {"author": "alice", "content": "Le dashboard de revue de code est beaucoup plus clair."},
    {"author": "bob", "content": "A verifier: les exports doivent rester accessibles aux leads seulement."},
]

SECURITY_LOGS = [
    "09:02 user=alice action=login status=success",
    "09:05 reset_token=RST-DEV-4421 generated_for=bob",
    "09:08 export_path=../private/customer_export.csv requested_by=debug-job",
]

PRIVATE_FILES = {
    "customer_export.csv": "email,contract,value\nceo@blueriver.local,BR-2026-001,92000\nops@northwind.local,NW-2026-117,43000\n",
    "api_keys.txt": "LEGACY_API_KEY=sk_lab_legacy_do_not_use\nREPORT_TOKEN=report-dev-7788\n",
}

PUBLIC_FILES = {
    "release-notes.txt": "DevSec Studio 0.9 - ajout du module exports et du proxy webhook.\n",
    "onboarding.txt": "Bienvenue dans le portail interne de formation securite developpeur.\n",
    "engineering-notes.txt": "Note dev: les exports clients ne doivent jamais etre servis par ce module. Backup temporaire observe pendant les tests: ../private/customer_export.csv\n",
}

PROMOS = [
    ("alice@devsec.local", "Frontend", "Vue tickets frontend"),
    ("bob@devsec.local", "Backend", "Acces exports clients"),
    ("charlie@devsec.local", "Platform", "Acces administration"),
]

CHALLENGES = {
    "ticket": {
        "name": "Le ticket voisin",
        "flag": build_flag("ticket"),
        "vulnerability": "Controle d'acces defaillant: un utilisateur connecte peut consulter un objet qui ne lui appartient pas.",
        "impact": "Dans un environnement reel, cela peut exposer des tickets clients, contrats, incidents ou donnees personnelles.",
    },
    "download": {
        "name": "Le centre documentaire",
        "flag": build_flag("download"),
        "vulnerability": "Path traversal: un chemin fourni par l'utilisateur permet de lire un fichier hors de la zone prevue.",
        "impact": "Cela peut mener a la fuite d'exports clients, fichiers de configuration, cles API ou sauvegardes internes.",
    },
    "feedback": {
        "name": "Le mur de feedback",
        "flag": build_flag("feedback"),
        "vulnerability": "XSS stockee: un contenu utilisateur est enregistre puis rendu comme du HTML actif.",
        "impact": "Un attaquant pourrait executer du JavaScript chez d'autres utilisateurs, voler des sessions ou afficher de faux contenus.",
    },
    "webhook": {
        "name": "Le testeur webhook",
        "flag": build_flag("webhook"),
        "vulnerability": "SSRF: le serveur effectue une requete vers une URL controlee par l'utilisateur.",
        "impact": "Cela peut exposer des endpoints internes, metadonnees cloud, tokens ou services non accessibles publiquement.",
    },
    "debug": {
        "name": "La console oubliee",
        "flag": build_flag("debug"),
        "vulnerability": "Mauvaise configuration: un listing de repertoire expose un fichier de configuration et des identifiants qui permettent de reveler la configuration complete.",
        "impact": "Dans un cas reel, cela peut exposer des secrets, chemins internes, endpoints prives et faciliter une compromission en chaine.",
    },
    "debug_quiz": {
        "name": "Bonus - Diagnostic du listing",
        "flag": build_flag("debug_quiz"),
        "vulnerability": "Directory listing: le serveur liste le contenu d'un repertoire au lieu de refuser ou servir uniquement des fichiers attendus.",
        "impact": "Un listing donne une carte de reconnaissance: noms de fichiers, sauvegardes, configs, archives ou indices exploitables.",
    },
    "token": {
        "name": "Le jeton lisible",
        "flag": build_flag("token"),
        "vulnerability": "Defaillance cryptographique: le token est seulement encode en base64, sans signature ni chiffrement.",
        "impact": "Un utilisateur peut lire ou modifier des attributs de session, privileges ou autorisations cote client.",
    },
    "admin": {
        "name": "Le lien magique",
        "flag": build_flag("admin"),
        "vulnerability": "Authentification incorrecte: un lien de connexion sans mot de passe utilise un token predictible.",
        "impact": "Un attaquant peut forger un lien pour prendre le controle d'un autre compte sans connaitre son mot de passe.",
    },
    "people": {
        "name": "L'annuaire trop bavard",
        "flag": build_flag("people"),
        "vulnerability": "Injection SQL: une entree utilisateur est concatenee directement dans une requete.",
        "impact": "Une injection peut extraire des donnees internes, contourner des filtres ou modifier la base dans un cas reel.",
    },
    "logs": {
        "name": "Les traces de debug",
        "flag": build_flag("logs"),
        "vulnerability": "Exposition de donnees sensibles dans les logs: mots de passe, tokens ou chemins internes sont journalises.",
        "impact": "Des logs partages ou consultes par trop de personnes peuvent devenir une source de compromission.",
    },
    "profile": {
        "name": "Le profil trop flexible",
        "flag": build_flag("profile"),
        "vulnerability": "Mass assignment: le serveur accepte et applique des champs qui ne devraient pas etre modifiables.",
        "impact": "Un utilisateur peut changer son role et obtenir des droits d'administration sans passer par un vrai workflow d'autorisation.",
    },
}


def current_user():
    user_id = session.get("user_id")
    return USERS.get(user_id)


def solved_ids():
    return set(session.get("solved", []))


def mark_solved(challenge_id):
    solved = solved_ids()
    solved.add(challenge_id)
    session["solved"] = sorted(solved)
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
    }


@app.route("/")
def index():
    return render_template("index.html")


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
    filename = request.args.get("file", "release-notes.txt")
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
        public_files=PUBLIC_FILES.keys(),
        success=success,
    )


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        content = request.form.get("content", "")
        # VULNERABLE BY DESIGN: stored XSS.
        # User input is stored and rendered with |safe in the template.
        FEEDBACKS.append({"author": author, "content": content})
        if any(marker in content.lower() for marker in ["<script", "onerror=", "javascript:"]):
            mark_solved("feedback")
        return redirect(url_for("feedback"))
    success = CHALLENGES["feedback"] if "feedback" in solved_ids() else None
    return render_template("feedback.html", feedbacks=FEEDBACKS, success=success)


@app.route("/webhook-tester")
def webhook_tester():
    target = request.args.get("url", "http://127.0.0.1:5000/internal/health")
    body = ""
    error = None
    parsed = urlparse(target)
    try:
        if parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("Lab local: le proxy est limite a localhost pour eviter les abus.")
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


@app.route("/internal/metadata")
def internal_metadata():
    return "service=reporting; env=dev; host=127.0.0.1:5000; internal_prefix=/internal; audit_route=secrets; backup=../private/customer_export.csv"


@app.route("/internal/health")
def internal_health():
    return "ok=true; service=public-webhook-health; metadata_ref=/internal/metadata"


@app.route("/internal/secrets")
def internal_secrets():
    if request.headers.get("X-DevSec-Proxy") != "1":
        return "Interne uniquement.", 403
    return "INTERNAL_REPORT_TOKEN=report-dev-7788"


@app.route("/debug/config")
def debug_config():
    # VULNERABLE BY DESIGN: security misconfiguration.
    # A debug endpoint exposes details useful in later challenges.
    files = {
        "README.txt": {
            "modified": "2026-06-04 09:12",
            "size": "142 B",
            "description": "Notes",
            "content": "Debug dropzone - fichiers temporaires generes par les outils de developpement.\nNe pas exposer ce repertoire en production.\n",
        },
        "app.conf": {
            "modified": "2026-06-04 09:18",
            "size": "312 B",
            "description": "Configuration",
            "content": (
                "APP_ENV=development\n"
                "DEBUG=true\n"
                "BACKUP_EXPORT=********\n"
                "LEGACY_KEYS_FILE=********\n"
                "INTERNAL_METADATA=********\n"
                "CONFIG_VIEWER_LOGIN=config_reader\n"
                "CONFIG_VIEWER_PASSWORD=reader-2026\n"
            ),
        },
        "old-app.conf.bak": {
            "modified": "2026-06-03 18:41",
            "size": "71 B",
            "description": "Backup",
            "content": "Ancienne sauvegarde: voir app.conf pour la configuration courante.\n",
        },
    }
    full_config = (
        "APP_ENV=development\n"
        "DEBUG=true\n"
        "BACKUP_EXPORT=../private/customer_export.csv\n"
        "LEGACY_KEYS_FILE=../private/api_keys.txt\n"
        "INTERNAL_METADATA=http://127.0.0.1:5000/internal/metadata\n"
        "CONFIG_VIEWER_LOGIN=config_reader\n"
        "CONFIG_VIEWER_PASSWORD=reader-2026\n"
        f"FLAG={CHALLENGES['debug']['flag']}\n"
    )
    selected_file = request.args.get("file", "")
    file_record = files.get(selected_file)
    content = file_record["content"] if file_record else None
    if selected_file == "app.conf" and request.args.get("user") == "config_reader" and request.args.get("password") == "reader-2026":
        content = full_config
        success = mark_solved("debug")
    else:
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
    return f"ml-{local_part}-2026"


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


@app.route("/logs")
def logs():
    # VULNERABLE BY DESIGN: sensitive data exposure in logs.
    # Logs contain tokens, passwords and export paths.
    success = None
    if any("password=" in event or "reset_token=" in event or "export_path=" in event for event in SECURITY_LOGS):
        success = mark_solved("logs")
    return render_template("logs.html", events=SECURITY_LOGS, success=success)


@app.route("/profile-editor", methods=["GET", "POST"])
def profile_editor():
    if not current_user():
        return redirect(url_for("login"))
    user = current_user()
    expected_profile = USER_BASELINE[user["id"]]
    if request.method == "POST":
        # VULNERABLE BY DESIGN: mass assignment.
        # Every posted field is copied into the user object, including privileged fields.
        injected_body = request.form.get("injected_body", "")
        normalized_body = injected_body.replace('"', "'").replace(" ", "").lower()
        if "role:'admin'" in normalized_body or "role=admin" in normalized_body:
            user["role"] = "admin"
        for key, value in request.form.items():
            if key == "injected_body":
                continue
            if value.lower() == "true":
                user[key] = True
            elif value.lower() == "false":
                user[key] = False
            else:
                user[key] = value
        if user.get("role") == "admin":
            mark_solved("profile")
        return redirect(url_for("profile_editor"))
    success = CHALLENGES["profile"] if "profile" in solved_ids() else None
    return render_template("profile_editor.html", user=user, expected_profile=expected_profile, success=success)


@app.route("/scoreboard")
def scoreboard():
    return render_template("scoreboard.html", challenges=challenge_status())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
