#!/bin/bash
# Serveurs Z1/Z2/Z3 : compte "admin" joignable UNIQUEMENT depuis le bastion, par cle.
# Envoi des journaux d'authentification vers le bastion (flux F10).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -y -q rsyslog

# Compte admin sans mot de passe, cle publique du bastion seulement
id admin > /dev/null 2>&1 || useradd -m -s /bin/bash admin
install -d -m 0700 -o admin -g admin /home/admin/.ssh
install -m 0600 -o admin -g admin /tmp/admin_id_rsa.pub /home/admin/.ssh/authorized_keys
rm -f /tmp/admin_id_rsa.pub

# SSH : admin seulement depuis le bastion (10.10.4.10), jamais de mot de passe ni de root
cat > /etc/ssh/sshd_config.d/50-startupmed.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
AllowUsers vagrant admin@10.10.4.10
EOF
systemctl restart ssh

# Journaux d'authentification + WAF (local1) vers le bastion
cat > /etc/rsyslog.d/90-central.conf <<'EOF'
auth,authpriv.*;local1.*  @@10.10.4.10:514
EOF
systemctl restart rsyslog

echo "[$(hostname)] Acces admin limite au bastion."
