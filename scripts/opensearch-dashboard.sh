#!/bin/bash
# BONUS : repare la vue (champs a jour) et cree un tableau de bord SIEM pret a l'emploi
set -euo pipefail
OSD=http://localhost:5601

# Attendre que Dashboards reponde
for i in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' $OSD/api/status || true)" = "200" ] && break
  sleep 3
done

# 1. Recreer la vue en redecouvrant les champs (corrige @timestamp = date)
curl -s -X DELETE "$OSD/api/saved_objects/index-pattern/startupmed-logs" -H "osd-xsrf: true" >/dev/null 2>&1 || true
curl -s -o /tmp/ip.out -w "index-pattern: %{http_code}\n" \
  -X POST "$OSD/api/index_patterns/index_pattern" -H "osd-xsrf: true" -H "Content-Type: application/json" \
  --data-binary @- <<'JSON'
{"index_pattern":{"id":"startupmed-logs","title":"startupmed-logs","timeFieldName":"@timestamp"}}
JSON

# 2. Importer les visualisations + le dashboard (ensemble coherent, en NDJSON)
cat > /tmp/siem.ndjson <<'NDJSON'
{"type":"index-pattern","id":"startupmed-logs","attributes":{"title":"startupmed-logs","timeFieldName":"@timestamp"}}
{"type":"visualization","id":"viz-source","attributes":{"title":"Evenements par source","visState":"{\"title\":\"Evenements par source\",\"type\":\"histogram\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"source\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10}}],\"params\":{\"type\":\"histogram\",\"addLegend\":true,\"addTooltip\":true,\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\"}],\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}]}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"startupmed-logs"}]}
{"type":"visualization","id":"viz-type","attributes":{"title":"Evenements par type","visState":"{\"title\":\"Evenements par type\",\"type\":\"pie\",\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"type\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":5}}],\"params\":{\"type\":\"pie\",\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true}}","uiStateJSON":"{}","description":"","kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"startupmed-logs"}]}
{"type":"dashboard","id":"siem-dashboard","attributes":{"title":"StartupMed - SIEM","hits":0,"description":"Vue d'ensemble des journaux et alertes","panelsJSON":"[{\"version\":\"2.0.0\",\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15,\"i\":\"1\"},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"},{\"version\":\"2.0.0\",\"gridData\":{\"x\":24,\"y\":0,\"w\":24,\"h\":15,\"i\":\"2\"},\"panelIndex\":\"2\",\"embeddableConfig\":{},\"panelRefName\":\"panel_2\"}]","optionsJSON":"{\"useMargins\":true,\"hidePanelTitles\":false}","version":1,"timeRestore":false,"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"panel_1","type":"visualization","id":"viz-source"},{"name":"panel_2","type":"visualization","id":"viz-type"}]}
NDJSON

curl -s -o /tmp/imp.out -w "import: %{http_code}\n" \
  -X POST "$OSD/api/saved_objects/_import?overwrite=true" -H "osd-xsrf: true" \
  --form file=@/tmp/siem.ndjson

echo "--- resultat import ---"
cat /tmp/imp.out; echo
echo "[opensearch] Tableau de bord 'StartupMed - SIEM' cree."
