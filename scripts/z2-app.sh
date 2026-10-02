#!/bin/bash
# Z2 — Applicative : API de demo (Flask) qui lit les patients dans la BDD (flux F3)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
DB_PASSWORD="$1"

apt-get install -y -q python3-flask python3-psycopg2 openssl netcat-openbsd

id startupmed > /dev/null 2>&1 || useradd --system --home /opt/startupmed --shell /usr/sbin/nologin startupmed
install -d -m 0755 /opt/startupmed
install -d -m 0750 -g startupmed /etc/startupmed

# Certificat TLS de labo pour le flux F2 (WAF -> API)
if [ ! -f /etc/startupmed/app.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=z2-app" \
    -keyout /etc/startupmed/app.key -out /etc/startupmed/app.crt 2> /dev/null
fi
chown root:startupmed /etc/startupmed/app.key /etc/startupmed/app.crt
chmod 0640 /etc/startupmed/app.key

# Secret injecte par l'environnement, jamais dans le code
printf 'DB_PASSWORD=%s\n' "$DB_PASSWORD" > /etc/startupmed/app.env
chown root:startupmed /etc/startupmed/app.env
chmod 0640 /etc/startupmed/app.env

cat > /opt/startupmed/app.py <<'EOF'
"""API de demonstration StartupMed — donnees FICTIVES."""
import html
import os

import psycopg2
from flask import Flask, abort, jsonify, request

app = Flask(__name__)


def connexion():
    # Flux F3 : TLS obligatoire vers la BDD en Z3
    return psycopg2.connect(
        host="10.10.3.10",
        dbname="startupmed",
        user="appuser",
        password=os.environ["DB_PASSWORD"],
        sslmode="require",
        connect_timeout=5,
    )


def patients(patient_id=None):
    with connexion() as conn, conn.cursor() as cur:
        if patient_id is None:
            cur.execute("SELECT id, nom, prenom, motif FROM patients ORDER BY id")
        else:
            # Requete parametree : pas d'injection SQL possible ici
            cur.execute("SELECT id, nom, prenom, motif FROM patients WHERE id = %s", (patient_id,))
        return cur.fetchall()


@app.get("/")
def accueil():
    lignes = "".join(
        f"<tr><td>{i}</td><td>{html.escape(n)}</td><td>{html.escape(p)}</td><td>{html.escape(m)}</td></tr>"
        for i, n, p, m in patients()
    )
    return (
        "<!doctype html><meta charset='utf-8'><title>StartupMed</title>"
        "<body style='font-family:sans-serif;max-width:720px;margin:40px auto'>"
        "<h1>StartupMed — plateforme de demo</h1>"
        "<p>Chemin : Internet → pare-feu F1 → WAF (Z1) → F2 → API (Z2) → F3 → PostgreSQL (Z3)</p>"
        "<table border='1' cellpadding='6' style='border-collapse:collapse'>"
        "<tr><th>#</th><th>Nom</th><th>Prenom</th><th>Motif</th></tr>"
        f"{lignes}</table><p><small>Donnees fictives.</small></p></body>"
    )


@app.get("/patients")
def api_patients():
    brut = request.args.get("id")
    if brut is None:
        return jsonify(patients())
    if not brut.isdigit():
        abort(400)
    return jsonify(patients(int(brut)))


if __name__ == "__main__":
    tls = os.environ.get("TLS_DIR", "/etc/startupmed")
    app.run(host="0.0.0.0", port=8443,
            ssl_context=(f"{tls}/app.crt", f"{tls}/app.key"))
EOF

cat > /etc/systemd/system/startupmed-api.service <<'EOF'
[Unit]
Description=StartupMed API (demo)
After=network-online.target
Wants=network-online.target

[Service]
User=startupmed
EnvironmentFile=/etc/startupmed/app.env
ExecStart=/usr/bin/python3 /opt/startupmed/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now startupmed-api
systemctl restart startupmed-api

echo "[z2-app] API demarree sur https://10.10.2.10:8443."
