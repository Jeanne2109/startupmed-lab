#!/bin/bash
# BONUS : OpenSearch (stockage/recherche des logs) + OpenSearch Dashboards (interface web)
# Labo : securite interne desactivee pour simplifier (pas de TLS/mot de passe entre composants).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Garde-fou DNS (NAT VirtualBox parfois capricieux)
getent hosts artifacts.opensearch.org >/dev/null 2>&1 || echo 'nameserver 8.8.8.8' > /etc/resolv.conf
timedatectl set-timezone Europe/Paris 2>/dev/null || true

# Pre-requis systeme d'OpenSearch
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-opensearch.conf
sysctl -w vm.max_map_count=262144 >/dev/null

apt-get update -q
apt-get install -y -q ca-certificates curl gnupg apt-transport-https lsb-release

# Depot officiel OpenSearch 2.x
curl -sSL https://artifacts.opensearch.org/publickeys/opensearch.pgp \
  | gpg --dearmor --batch --yes -o /usr/share/keyrings/opensearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring.gpg] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main" \
  > /etc/apt/sources.list.d/opensearch-2.x.list
echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring.gpg] https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/2.x/apt stable main" \
  > /etc/apt/sources.list.d/opensearch-dashboards-2.x.list
apt-get update -q

# Installation (le mot de passe initial est exige par le paquet mais la securite est desactivee ensuite)
env OPENSEARCH_INITIAL_ADMIN_PASSWORD='Demo-OpenSearch-2026!' \
  apt-get install -y -q opensearch opensearch-dashboards

# --- Configuration OpenSearch : mono-noeud, 1 Go de heap, securite desactivee ---
cat > /etc/opensearch/opensearch.yml <<'YML'
cluster.name: startupmed-siem
node.name: opensearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
plugins.security.disabled: true
YML
mkdir -p /etc/opensearch/jvm.options.d
cat > /etc/opensearch/jvm.options.d/heap.options <<'OPT'
-Xms1g
-Xmx1g
OPT

# --- Configuration Dashboards : ecoute sur toutes les interfaces, sans securite ---
cat > /etc/opensearch-dashboards/opensearch_dashboards.yml <<'YML'
server.host: "0.0.0.0"
server.port: 5601
opensearch.hosts: ["http://localhost:9200"]
YML

systemctl daemon-reload
systemctl enable opensearch opensearch-dashboards >/dev/null 2>&1

echo "[opensearch] Demarrage d'OpenSearch (peut prendre 1 a 2 minutes)..."
systemctl restart opensearch
for i in $(seq 1 60); do
  curl -s http://localhost:9200 >/dev/null 2>&1 && break
  sleep 3
done
curl -s http://localhost:9200 >/dev/null 2>&1 && echo "[opensearch] OpenSearch repond sur 9200." || echo "[opensearch] ATTENTION: OpenSearch ne repond pas encore."

echo "[opensearch] Acces direct (labo) : retrait du plugin d'authentification de Dashboards..."
/usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin remove securityDashboards --allow-root 2>/dev/null || true

echo "[opensearch] Demarrage des Dashboards..."
systemctl restart opensearch-dashboards

echo "[opensearch] Pret. Interface web : http://192.168.56.30:5601 (depuis votre PC)."
