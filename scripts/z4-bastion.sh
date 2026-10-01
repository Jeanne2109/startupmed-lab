#!/bin/bash
# Z4 — Administration : bastion SSH avec MFA (mot de passe + code TOTP)
# + collecte centralisee des journaux (flux F10)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
ADMIN_PASSWORD="$1"

apt-get update -q
apt-get install -y -q libpam-google-authenticator qrencode rsyslog systemd-timesyncd openssh-client
systemctl enable --now systemd-timesyncd   # TOTP = horloge juste obligatoire

# ---- Compte admin : mot de passe + TOTP --------------------------------------
id admin > /dev/null 2>&1 || useradd -m -s /bin/bash admin
echo "admin:${ADMIN_PASSWORD}" | chpasswd

# Cle pour rebondir vers les serveurs (flux F7)
install -d -m 0700 -o admin -g admin /home/admin/.ssh
install -m 0600 -o admin -g admin /tmp/admin_id_rsa /home/admin/.ssh/id_rsa
rm -f /tmp/admin_id_rsa
cat > /home/admin/.ssh/config <<'EOF'
Host z1-dmz
    HostName 10.10.1.10
Host z2-app
    HostName 10.10.2.10
Host z3-db
    HostName 10.10.3.10
Host *
    User admin
    IdentityFile ~/.ssh/id_rsa
    StrictHostKeyChecking accept-new
EOF
chown admin:admin /home/admin/.ssh/config
chmod 0600 /home/admin/.ssh/config

# Secret TOTP de l'admin (genere une seule fois)
if [ ! -f /home/admin/.google_authenticator ]; then
  sudo -u admin google-authenticator -t -d -f -r 3 -R 30 -w 3 -q
fi

# PAM : apres le mot de passe, demander le code TOTP
if ! grep -q pam_google_authenticator /etc/pam.d/sshd; then
  sed -i 's/^@include common-auth/@include common-auth\nauth required pam_google_authenticator.so/' /etc/pam.d/sshd
fi

# SSH : admin uniquement depuis le siege (Z5), MFA obligatoire
cat > /etc/ssh/sshd_config.d/50-bastion.conf <<'EOF'
KbdInteractiveAuthentication yes
UsePAM yes
PermitRootLogin no
AllowUsers vagrant admin@10.10.5.*
EOF
if ! grep -q "^Match User admin" /etc/ssh/sshd_config; then
  cat >> /etc/ssh/sshd_config <<'EOF'

Match User admin
    AuthenticationMethods keyboard-interactive
EOF
fi
sshd -t
systemctl restart ssh

# Afficher le QR code a scanner (Google Authenticator, Microsoft Authenticator...)
cat > /usr/local/bin/qr-mfa <<'EOF'
#!/bin/bash
SECRET=$(head -n1 /home/admin/.google_authenticator)
qrencode -t ansiutf8 "otpauth://totp/StartupMed:admin@z4-bastion?secret=${SECRET}&issuer=StartupMed"
echo "Cle a saisir manuellement si le QR ne s'affiche pas : ${SECRET}"
EOF
chmod +x /usr/local/bin/qr-mfa

# ---- Collecte centralisee des journaux (mini-SIEM) ---------------------------
install -d -m 0750 /var/log/central
cat > /etc/rsyslog.d/10-central.conf <<'EOF'
module(load="imtcp")
template(name="ParHote" type="string" string="/var/log/central/%HOSTNAME%.log")
ruleset(name="distant") { action(type="omfile" dynaFile="ParHote") }
input(type="imtcp" port="514" ruleset="distant")
EOF
systemctl restart rsyslog

cat > /usr/local/bin/logs-centraux <<'EOF'
#!/bin/bash
# Journaux recus de z1-dmz, z2-app et z3-db (connexions SSH, blocages WAF)
tail -n 20 -f /var/log/central/*.log
EOF
chmod +x /usr/local/bin/logs-centraux

echo "[z4-bastion] Bastion pret. QR code MFA : vagrant ssh z4-bastion -c 'sudo qr-mfa'"
