#!/bin/bash
# BONUS : alimentation AUTOMATIQUE d'OpenSearch depuis les journaux du SIEM
set -euo pipefail

cat > /usr/local/bin/siem-vers-opensearch <<'PY'
#!/usr/bin/env python3
"""Envoie les lignes des journaux du SIEM dans l'index OpenSearch 'startupmed-logs'.
Chaque ligne a un identifiant unique (empreinte) -> pas de doublon si on relance."""
import glob, os, re, json, sys, datetime, hashlib, urllib.request, urllib.error

OS_URL = "http://10.10.4.30:9200"
INDEX  = "startupmed-logs"
iso    = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)')
quiet  = "--quiet" in sys.argv

def norm(raw):
    try:
        return datetime.datetime.fromisoformat(raw).isoformat()
    except Exception:
        return datetime.datetime.now().astimezone().isoformat()

# Creer l'index avec un mapping explicite (@timestamp = date) s'il n'existe pas
mapping = json.dumps({"mappings": {"properties": {
    "@timestamp": {"type": "date"}, "message": {"type": "text"},
    "source": {"type": "keyword"}, "type": {"type": "keyword"}}}}).encode()
try:
    urllib.request.urlopen(urllib.request.Request(
        f"{OS_URL}/{INDEX}", data=mapping, method="PUT",
        headers={"Content-Type": "application/json"}), timeout=30)
except urllib.error.HTTPError as e:
    if e.code != 400:
        raise

bulk = []
for f in sorted(glob.glob('/var/log/central/*.log')):
    src = os.path.basename(f)
    try:
        for line in open(f, errors='replace'):
            line = line.rstrip('\n')
            if not line.strip():
                continue
            m = iso.match(line)
            t = norm(m.group(1)) if m else datetime.datetime.now().astimezone().isoformat()
            typ = "alerte" if src == "ALERTES.log" else "log"
            # identifiant deterministe = empreinte de (fichier + ligne) -> ecrase au lieu de dupliquer
            _id = hashlib.md5((src + "|" + line).encode()).hexdigest()
            bulk.append(json.dumps({"index": {"_id": _id}}))
            bulk.append(json.dumps({"@timestamp": t, "message": line, "source": src, "type": typ}))
    except Exception:
        pass

if not bulk:
    if not quiet: print("Aucun journal a envoyer.")
    sys.exit(0)

data = ("\n".join(bulk) + "\n").encode()
resp = json.load(urllib.request.urlopen(urllib.request.Request(
    f"{OS_URL}/{INDEX}/_bulk", data=data,
    headers={"Content-Type": "application/x-ndjson"}), timeout=60))
n = sum(1 for it in resp.get("items", []) if not it.get("index", {}).get("error"))
if not quiet:
    print(f"{n} lignes synchronisees dans l'index OpenSearch '{INDEX}'.")
    print("Interface : http://192.168.56.30:5601")
PY
chmod +x /usr/local/bin/siem-vers-opensearch

# --- Alimentation AUTOMATIQUE : minuteur systemd toutes les 20 secondes ---
cat > /etc/systemd/system/siem-opensearch.service <<'UNIT'
[Unit]
Description=Envoi des journaux du SIEM vers OpenSearch
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/siem-vers-opensearch --quiet
UNIT

cat > /etc/systemd/system/siem-opensearch.timer <<'UNIT'
[Unit]
Description=Alimente OpenSearch toutes les 20 secondes

[Timer]
OnBootSec=20
OnUnitActiveSec=20
AccuracySec=5s

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now siem-opensearch.timer >/dev/null 2>&1
systemctl start siem-opensearch.service || true

echo "[z4-bastion] Alimentation AUTOMATIQUE d'OpenSearch active (toutes les 20 s)."
