#!/bin/bash
# Pare-feu -> SIEM : envoie les lignes de blocage (nftables) au SIEM Wazuh en Z4 (flux F10)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Garde-fou : s'assurer que la resolution DNS fonctionne (NAT VirtualBox parfois capricieux)
getent hosts deb.debian.org >/dev/null 2>&1 || echo 'nameserver 8.8.8.8' > /etc/resolv.conf

# rsyslog est souvent deja present dans la box ; on l'installe seulement si besoin
command -v rsyslogd >/dev/null 2>&1 || apt-get install -y -q rsyslog

# Toutes les lignes du noyau contenant BLOQUE partent vers le SIEM (10.10.4.10:514)
cat > /etc/rsyslog.d/90-siem.conf <<'EOF'
:msg, contains, "BLOQUE" @@10.10.4.10:514
EOF
systemctl restart rsyslog

echo "[fw] Blocages transmis au SIEM (Z4)."
