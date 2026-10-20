#!/bin/bash
# BONUS : alimentation AUTOMATIQUE d'OpenSearch + classement de chaque log par type d'attaque
set -euo pipefail

cat > /usr/local/bin/siem-vers-opensearch <<'PY'
#!/usr/bin/env python3
"""Envoie les journaux du SIEM dans OpenSearch, en classant chaque ligne par type d'attaque."""
import glob, os, re, json, sys, datetime, hashlib, urllib.request, urllib.error

OS_URL = "http://10.10.4.30:9200"
INDEX  = "startupmed-logs"
iso    = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)')
quiet  = "--quiet" in sys.argv

# Classement : premier motif trouve gagne (logs bruts ET alertes)
REGLES = [
    ("bloque-rdp-externe", "rdp_externe"),
    ("dpt=3389",           "rdp_externe"),
    ("rdp depuis",         "rdp_externe"),
    ("modsecurity",        "injection_sql"),
    ("injection sql",      "injection_sql"),
    ("not in the sudoers", "elevation_privilege"),
    ("not in sudoers",     "elevation_privilege"),
    ("elevation de privilege", "elevation_privilege"),
    ("authentication failure", "brute_force"),
    ("failed password",    "brute_force"),
    ("failed keyboard",    "brute_force"),
    ("brute force",        "brute_force"),
    ("get /patients?id=",  "exfiltration"),
    ("exfiltration",       "exfiltration"),
    ("get /patients",      "acces_api"),
]
def classer(msg):
    m = msg.lower()
    for motif, label in REGLES:
        if motif in m:
            return label
    return "normal"

def norm(raw):
    try:
        return datetime.datetime.fromisoformat(raw).isoformat()
    except Exception:
        return datetime.datetime.now().astimezone().isoformat()

# Index avec mapping explicite (dont le champ "attaque")
mapping = json.dumps({"mappings": {"properties": {
    "@timestamp": {"type": "date"}, "message": {"type": "text"},
    "source": {"type": "keyword"}, "type": {"type": "keyword"},
    "attaque": {"type": "keyword"}}}}).encode()
try:
    urllib.request.urlopen(urllib.request.Request(
        f"{OS_URL}/{INDEX}", data=mapping, method="PUT",
        headers={"Content-Type": "application/json"}), timeout=30)
except urllib.error.HTTPError as e:
    if e.code != 400:
        raise

bulk = []
for f in sorted(glob.glob('/var/log/central/*.log')) + ['/var/log/auth.log']:
    src = os.path.basename(f)
    try:
        for line in open(f, errors='replace'):
            line = line.rstrip('\n')
            if not line.strip():
                continue
            m = iso.match(line)
            t = norm(m.group(1)) if m else datetime.datetime.now().astimezone().isoformat()
            typ = "alerte" if src == "ALERTES.log" else "log"
            _id = hashlib.md5((src + "|" + line).encode()).hexdigest()
            bulk.append(json.dumps({"index": {"_id": _id}}))
            bulk.append(json.dumps({"@timestamp": t, "message": line,
                                    "source": src, "type": typ, "attaque": classer(line)}))
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
    print(f"{n} lignes synchronisees (classees par attaque) dans '{INDEX}'.")
PY
chmod +x /usr/local/bin/siem-vers-opensearch

# Minuteur systemd (toutes les 20 s) - inchange
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
echo "[z4-bastion] Alimentation automatique + classement par attaque actifs."
