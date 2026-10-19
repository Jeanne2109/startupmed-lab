#!/bin/bash
# BONUS : cree la vue (index pattern) dans Dashboards pour visualiser les logs du SIEM
set -euo pipefail

# Attendre que Dashboards reponde
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5601/api/status || true)
  [ "$code" = "200" ] && break
  sleep 3
done

# Creer l'index pattern "startupmed-logs" avec le champ temps @timestamp
curl -s -X POST "http://localhost:5601/api/saved_objects/index-pattern/startupmed-logs" \
  -H "osd-xsrf: true" -H "Content-Type: application/json" \
  -d '{"attributes":{"title":"startupmed-logs","timeFieldName":"@timestamp"}}' >/dev/null || true

# Le definir comme vue par defaut (ouverture directe dans Discover)
curl -s -X POST "http://localhost:5601/api/opensearch-dashboards/settings/defaultIndex" \
  -H "osd-xsrf: true" -H "Content-Type: application/json" \
  -d '{"value":"startupmed-logs"}' >/dev/null || true

echo "[opensearch] Vue 'startupmed-logs' prete dans Dashboards (Discover)."
