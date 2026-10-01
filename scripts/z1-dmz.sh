#!/bin/bash
# Z1 — DMZ : WAF = Apache reverse proxy + ModSecurity + OWASP Core Rule Set
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get install -y -q apache2 libapache2-mod-security2 modsecurity-crs ssl-cert

# ModSecurity en mode BLOCAGE (par defaut il ne fait que detecter)
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# S'assurer que les regles OWASP CRS sont chargees
if ! grep -q "modsecurity-crs" /etc/apache2/mods-available/security2.conf; then
  cat > /etc/apache2/conf-available/owasp-crs.conf <<'EOF'
IncludeOptional /etc/modsecurity/crs/crs-setup.conf
IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
EOF
  a2enconf owasp-crs
fi

a2enmod ssl proxy proxy_http headers security2 > /dev/null
a2dissite 000-default > /dev/null

# Site public : HTTPS en entree, relaye vers l'API (flux F2)
cat > /etc/apache2/sites-available/startupmed.conf <<'EOF'
<VirtualHost *:443>
    ServerName startupmed.lab
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

    # Relais vers l'API metier en Z2 (certificat de labo auto-signe)
    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    ProxyPass        / https://10.10.2.10:8443/
    ProxyPassReverse / https://10.10.2.10:8443/

    Header always set Strict-Transport-Security "max-age=31536000"
    Header always set X-Content-Type-Options "nosniff"

    # Les blocages WAF partent aussi vers les logs centralises (local1)
    ErrorLog syslog:local1
    CustomLog ${APACHE_LOG_DIR}/startupmed_access.log combined
</VirtualHost>
EOF
a2ensite startupmed > /dev/null

# Durcissement : ne pas reveler la version d'Apache ni l'OS
sed -i 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/' /etc/apache2/conf-available/security.conf
apache2ctl configtest
systemctl restart apache2

echo "[z1-dmz] WAF pret sur https://10.10.1.10 (publie sur https://192.168.56.10)."
