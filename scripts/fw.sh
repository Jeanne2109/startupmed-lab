#!/bin/bash
# Pare-feu : routeur Debian + nftables (matrice de flux)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -y -q nftables tcpdump

# Activer le routage entre les zones
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-routeur.conf
sysctl --system > /dev/null

# Charger les regles (verification de syntaxe d'abord)
sed -i 's/\r$//' /tmp/nftables.conf   # au cas ou le fichier a ete copie avec des fins de ligne Windows
install -m 0644 /tmp/nftables.conf /etc/nftables.conf
nft -c -f /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables

# Raccourcis pour la demo
cat > /usr/local/bin/logs-blocages <<'EOF'
#!/bin/bash
# Affiche en direct les flux bloques par le pare-feu
journalctl -k -f -o short | grep --line-buffered BLOQUE
EOF
cat > /usr/local/bin/regles <<'EOF'
#!/bin/bash
# Affiche les regles avec leurs compteurs de paquets
nft list ruleset
EOF
chmod +x /usr/local/bin/logs-blocages /usr/local/bin/regles

echo "[fw] Pare-feu pret : $(nft list ruleset | grep -c accept) regles d'autorisation chargees."
