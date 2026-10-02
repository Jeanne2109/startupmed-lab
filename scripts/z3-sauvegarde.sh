#!/bin/bash
# Z3 — Jour 3 : sauvegarde horaire de la base (RPO 1 h)
# + droit de restauration tres limite pour le compte admin (depuis le bastion)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get install -y -q cron

install -d -m 0750 -o root -g admin /var/backups/startupmed

cat > /usr/local/bin/sauvegarde-bdd <<'EOF'
#!/bin/bash
# Sauvegarde de la base patients (format PostgreSQL "custom")
set -euo pipefail
F=/var/backups/startupmed/startupmed-$(date +%Y%m%d-%H%M%S).dump
sudo -u postgres pg_dump -Fc startupmed > "$F"
chown root:admin "$F"
chmod 0640 "$F"
# 48 sauvegardes locales max (2 jours)
ls -1t /var/backups/startupmed/*.dump | tail -n +49 | xargs -r rm -f
echo "Sauvegarde OK : $(basename "$F")"
EOF
chmod +x /usr/local/bin/sauvegarde-bdd

# Toutes les heures pile = RPO 1 h
echo "0 * * * * root /usr/local/bin/sauvegarde-bdd > /dev/null" > /etc/cron.d/startupmed-sauvegarde

# Moindre privilege : admin peut UNIQUEMENT lancer cette restauration precise
cat > /etc/sudoers.d/admin-restauration <<'EOF'
admin ALL=(postgres) NOPASSWD: /usr/bin/pg_restore --clean --if-exists -d startupmed
EOF
chmod 0440 /etc/sudoers.d/admin-restauration
visudo -cf /etc/sudoers.d/admin-restauration

/usr/local/bin/sauvegarde-bdd
echo "[z3-db] Sauvegarde horaire active."
