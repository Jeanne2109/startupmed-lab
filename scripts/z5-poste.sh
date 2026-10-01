#!/bin/bash
# Z5 — Siege : poste salarie avec les outils de test
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -y -q netcat-openbsd openssh-client postgresql-client curl nmap

echo "[z5-poste] Poste du siege pret."
