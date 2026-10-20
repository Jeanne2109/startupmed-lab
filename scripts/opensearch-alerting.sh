#!/bin/bash
# BONUS : OpenSearch Alerting - un monitor qui alerte automatiquement sur les attaques
set -euo pipefail
OS=http://localhost:9200

for i in $(seq 1 40); do curl -s -o /dev/null "$OS" && break; sleep 3; done

# Supprimer un ancien monitor du meme nom (idempotence)
for id in $(curl -s -X GET "$OS/_plugins/_alerting/monitors/_search" -H "Content-Type: application/json" -d '{"query":{"match":{"monitor.name":"Attaques StartupMed"}}}' 2>/dev/null | grep -o '"_id":"[^"]*"' | cut -d'"' -f4); do
  curl -s -X DELETE "$OS/_plugins/_alerting/monitors/$id" >/dev/null 2>&1 || true
done

# Creer le monitor : toutes les minutes, compte les attaques des 60 dernieres minutes
curl -s -o /tmp/mon.out -w "monitor: %{http_code}\n" \
  -X POST "$OS/_plugins/_alerting/monitors" -H "Content-Type: application/json" --data-binary @- <<'JSON'
{
  "type": "monitor",
  "name": "Attaques StartupMed",
  "monitor_type": "query_level_monitor",
  "enabled": true,
  "schedule": { "period": { "interval": 1, "unit": "MINUTES" } },
  "inputs": [{
    "search": {
      "indices": ["startupmed-logs"],
      "query": {
        "size": 0,
        "query": {
          "bool": {
            "filter": [
              { "range": { "@timestamp": { "gte": "now-60m" } } },
              { "terms": { "attaque": ["brute_force","exfiltration","rdp_externe","injection_sql","elevation_privilege"] } }
            ]
          }
        }
      }
    }
  }],
  "triggers": [{
    "name": "Attaque detectee",
    "severity": "1",
    "condition": { "script": { "source": "ctx.results[0].hits.total.value > 0", "lang": "painless" } },
    "actions": []
  }]
}
JSON
echo "--- reponse ---"
grep -o '"id":"[^"]*"' /tmp/mon.out | head -n1 || true
cat /tmp/mon.out | head -c 200; echo
echo "[opensearch] Monitor 'Attaques StartupMed' cree (verifie toutes les minutes)."
