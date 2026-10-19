#!/bin/bash
# BONUS : envoie les journaux centralises du SIEM vers OpenSearch (script maison, sans dependance)
set -euo pipefail

cat > /usr/local/bin/siem-vers-opensearch <<'PY'
#!/usr/bin/env python3
"""Envoie les lignes des journaux du SIEM dans l'index OpenSearch 'startupmed-logs'."""
import glob, os, re, json, sys, datetime, urllib.request, urllib.error

OS_URL = "http://10.10.4.30:9200"
INDEX  = "startupmed-logs"
iso    = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)')

def req(path, data=None, method="GET"):
    r = urllib.request.Request(f"{OS_URL}{path}", data=data, method=method,
                               headers={"Content-Type": "application/json"} if data else {})
    return urllib.request.urlopen(r, timeout=60)

# 1. Creer l'index avec un mapping explicite (@timestamp = date) s'il n'existe pas
mapping = json.dumps({"mappings": {"properties": {
    "@timestamp": {"type": "date"},
    "message":    {"type": "text"},
    "source":     {"type": "keyword"},
    "type":       {"type": "keyword"}}}}).encode()
try:
    req(f"/{INDEX}", data=mapping, method="PUT")
except urllib.error.HTTPError as e:
    if e.code != 400:   # 400 = l'index existe deja
        raise

# 2. Lire les journaux et construire l'envoi en masse
def norm(raw):
    try:
        return datetime.datetime.fromisoformat(raw).isoformat()
    except Exception:
        return datetime.datetime.now().astimezone().isoformat()

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
            bulk.append(json.dumps({"index": {}}))
            bulk.append(json.dumps({"@timestamp": t, "message": line, "source": src, "type": typ}))
    except Exception:
        pass

if not bulk:
    print("Aucun journal a envoyer."); sys.exit(0)

data = ("\n".join(bulk) + "\n").encode()
r = urllib.request.Request(f"{OS_URL}/{INDEX}/_bulk", data=data,
                           headers={"Content-Type": "application/x-ndjson"})
resp = json.load(urllib.request.urlopen(r, timeout=60))
n = sum(1 for it in resp.get("items", []) if not it.get("index", {}).get("error"))
print(f"{n} lignes envoyees dans l'index OpenSearch '{INDEX}'.")
print("Ouvrez http://192.168.56.30:5601 -> Discover pour les visualiser.")
PY
chmod +x /usr/local/bin/siem-vers-opensearch

echo "[z4-bastion] Commande 'siem-vers-opensearch' installee (mapping date + envoi vers OpenSearch)."
