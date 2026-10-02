#!/bin/bash
# Z5 — Siege : poste salarie avec les outils de test
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Garde-fou : s'assurer que la resolution DNS fonctionne (NAT VirtualBox parfois capricieux)
getent hosts deb.debian.org >/dev/null 2>&1 || echo 'nameserver 8.8.8.8' > /etc/resolv.conf

apt-get update -q
apt-get install -y -q netcat-openbsd openssh-client postgresql-client curl nmap sshpass rsyslog

# Le poste envoie ses journaux d'authentification au SIEM (agent EDR simule, flux F10)
cat > /etc/rsyslog.d/90-siem.conf <<'EOF'
auth,authpriv.*  @@10.10.4.10:514
EOF
systemctl restart rsyslog

# Utilisateur STANDARD (sans droits admin) : sert a demontrer l'elevation de privilege
# Compte leurre de demo uniquement, sur le poste local.
id stagiaire > /dev/null 2>&1 || useradd -m -s /bin/bash stagiaire
echo 'stagiaire:Demo-Stagiaire-2026' | chpasswd

# ---------------------------------------------------------------------------
# Simulateur d'attaques pour la demo SIEM (contre NOTRE labo uniquement)
# ---------------------------------------------------------------------------
cat > /usr/local/bin/siem-attaques <<'SCRIPT'
#!/bin/bash
# Attaques INTERNES (depuis le poste du siege) pour verifier que le SIEM les remonte.
# Les attaques venues d'Internet (exfiltration, injection SQL, RDP externe) se lancent
# depuis votre PC - voir le README, section "Démos SIEM".
set -u
BASTION=10.10.4.10
gras=$'\e[1m'; raz=$'\e[0m'

case "${1:-tout}" in
  bruteforce|1)
    echo "${gras}[1] Brute force : 6 tentatives de mot de passe sur le bastion${raz}"
    for i in $(seq 1 6); do
      timeout 8 sshpass -p "mauvais_mdp_$i" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
        -o NumberOfPasswordPrompts=1 admin@$BASTION true 2>/dev/null
      echo "  tentative $i : refusee"
    done ;;
  privilege|5)
    echo "${gras}[5] Elevation de privilege : le compte standard 'stagiaire' tente d'obtenir les droits admin${raz}"
    # stagiaire s'authentifie correctement mais n'est PAS autorise -> "NOT in sudoers"
    sudo -u stagiaire bash -c 'echo Demo-Stagiaire-2026 | sudo -S -k cat /etc/shadow' 2>&1 | head -n 2 | sed 's/^/  /' ;;
  tout|*)
    "$0" bruteforce; echo; "$0" privilege
    echo; echo "Attaques internes envoyees. Lancez aussi les attaques Internet depuis votre PC (README)."
    echo "Puis sur le SIEM (z4-bastion) : sudo siem-detect" ;;
esac
SCRIPT
chmod +x /usr/local/bin/siem-attaques

echo "[z5-poste] Poste du siege pret (outils de test + siem-attaques)."
