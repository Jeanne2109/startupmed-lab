#!/bin/bash
# Z3 — Donnees de sante : PostgreSQL, TLS obligatoire, accessible seulement par l'API (F3)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
DB_PASSWORD="$1"

apt-get install -y -q postgresql

PGCONF="$(ls -d /etc/postgresql/*/main)"

# Ecoute sur l'adresse de la zone, TLS active (certificat de labo Debian)
sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost,10.10.3.10'/" "$PGCONF/postgresql.conf"
sed -i "s/^#\?ssl = .*/ssl = on/" "$PGCONF/postgresql.conf"

# Seule l'API (10.10.2.10) peut se connecter, en TLS (hostssl), sur sa seule base
if ! grep -q "10.10.2.10/32" "$PGCONF/pg_hba.conf"; then
  echo "hostssl  startupmed  appuser  10.10.2.10/32  scram-sha-256" >> "$PGCONF/pg_hba.conf"
fi
systemctl restart postgresql

# Base, compte applicatif au moindre privilege, donnees FICTIVES
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='appuser'" | grep -q 1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -v pw="$DB_PASSWORD" <<'EOF'
CREATE ROLE appuser LOGIN PASSWORD :'pw';
CREATE DATABASE startupmed;
\c startupmed
CREATE TABLE patients (
    id      serial PRIMARY KEY,
    nom     text NOT NULL,
    prenom  text NOT NULL,
    motif   text NOT NULL
);
INSERT INTO patients (nom, prenom, motif) VALUES
    ('Martin',  'Claire', 'Suivi tension'),
    ('Durand',  'Hugo',   'Renouvellement ordonnance'),
    ('Bernard', 'Lina',   'Consultation dermatologie'),
    ('Petit',   'Yanis',  'Certificat sport'),
    ('Moreau',  'Sofia',  'Suivi diabete');
REVOKE ALL ON DATABASE startupmed FROM PUBLIC;
GRANT CONNECT ON DATABASE startupmed TO appuser;
GRANT SELECT ON patients TO appuser;
EOF
fi

echo "[z3-db] PostgreSQL pret (TLS, acces API uniquement)."
