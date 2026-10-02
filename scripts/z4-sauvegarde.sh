#!/bin/bash
# Z4 — Jour 3 : copie des sauvegardes hors de la zone donnees, rendue IMMUABLE,
# et restauration en une commande (mesure du temps reel vs RTO)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get install -y -q cron

install -d -m 0700 /srv/sauvegardes

cat > /usr/local/bin/rapatrier-sauvegardes <<'EOF'
#!/bin/bash
# Recupere les nouvelles sauvegardes de z3-db et les verrouille (chattr +i)
set -euo pipefail
for f in $(sudo -u admin -H ssh -o BatchMode=yes z3-db 'ls -1 /var/backups/startupmed/'); do
  [ -e "/srv/sauvegardes/$f" ] && continue
  sudo -u admin -H scp -q -o BatchMode=yes "z3-db:/var/backups/startupmed/$f" "/tmp/$f"
  mv "/tmp/$f" "/srv/sauvegardes/$f"
  chown root:root "/srv/sauvegardes/$f"
  chmod 0400 "/srv/sauvegardes/$f"
  chattr +i "/srv/sauvegardes/$f"     # immuable : meme root ne peut plus l'effacer
  echo "Copie immuable : $f"
done
EOF

cat > /usr/local/bin/restaurer-bdd <<'EOF'
#!/bin/bash
# Restaure la base de z3-db depuis la derniere copie immuable du bastion
set -euo pipefail
F="${1:-$(ls -1t /srv/sauvegardes/*.dump | head -n 1)}"
echo "Restauration depuis la copie immuable : $(basename "$F")"
debut=$(date +%s)
sudo -u admin -H ssh -o BatchMode=yes z3-db \
  "sudo -u postgres /usr/bin/pg_restore --clean --if-exists -d startupmed" < "$F"
fin=$(date +%s)
echo "Restauration terminee en $((fin - debut)) s  (objectif RTO : 4 h, RPO : 1 h)"
EOF

cat > /usr/local/bin/voir-sauvegardes <<'EOF'
#!/bin/bash
# Liste les copies et leur attribut immuable ("i")
cd /srv/sauvegardes && ls -lh && echo && lsattr
EOF
chmod +x /usr/local/bin/rapatrier-sauvegardes /usr/local/bin/restaurer-bdd /usr/local/bin/voir-sauvegardes

# 10 minutes apres chaque sauvegarde horaire de z3-db
echo "10 * * * * root /usr/local/bin/rapatrier-sauvegardes > /dev/null" > /etc/cron.d/startupmed-rapatriement

/usr/local/bin/rapatrier-sauvegardes
echo "[z4-bastion] Copies immuables des sauvegardes actives."
