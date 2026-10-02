#!/bin/bash
# Z4 - SIEM : moteur de detection des 4 scenarios d'attaque a partir des journaux centralises
#   1. Brute force sur mot de passe   2. Exfiltration de donnees
#   3. RDP depuis une IP externe       4. Injection SQL
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

install -d -m 0750 /var/log/central

# ---------------------------------------------------------------------------
# Regles de detection (seuils) - un seul endroit a ajuster
# ---------------------------------------------------------------------------
cat > /etc/siem-regles.conf <<'EOF'
# Nombre d'echecs d'authentification a partir duquel on parle de brute force
SEUIL_BRUTEFORCE=5
# Nombre de lectures de dossiers patients en rafale = exfiltration probable
SEUIL_EXFILTRATION=15
# Nombre de lignes recentes analysees dans chaque journal
LIGNES=3000
EOF

# ---------------------------------------------------------------------------
# Moteur de detection : scanne les journaux et affiche les alertes trouvees
# ---------------------------------------------------------------------------
cat > /usr/local/bin/siem-detect <<'SCRIPT'
#!/bin/bash
# Analyse les journaux centralises (Z1 a Z5 + pare-feu) et leve des alertes.
source /etc/siem-regles.conf
DIR=/var/log/central
JOURNAL_ALERTES="$DIR/ALERTES.log"
# Sources : journaux distants + journal local d'authentification du bastion
SRC=$(ls "$DIR"/*.log 2>/dev/null | grep -v ALERTES || true)
AUTH=/var/log/auth.log

bleu=$'\e[36m'; rouge=$'\e[31m'; jaune=$'\e[33m'; vert=$'\e[32m'; gras=$'\e[1m'; raz=$'\e[0m'
alerte() { # severite  regle  details
  local h; h=$(date '+%Y-%m-%d %H:%M:%S')
  local coul="$jaune"; [ "$1" = "CRITIQUE" ] && coul="$rouge"
  printf "%s[%s]%s %s%-8s%s %s\n" "$bleu" "$h" "$raz" "$coul$gras" "$1" "$raz" "$2 : $3"
  echo "$h [$1] $2 : $3" >> "$JOURNAL_ALERTES"
}

echo "${gras}=== SIEM StartupMed - analyse des journaux ===${raz}"
alertes=0

# --- 1. BRUTE FORCE : echecs d'authentification repetes depuis une meme source ---
mapfile -t bf < <(
  { tail -n "$LIGNES" $SRC "$AUTH" 2>/dev/null | \
    grep -hE "Failed password|authentication failure|Invalid user|Failed keyboard-interactive"; } | \
  grep -oE "rhost=[0-9.]+|from [0-9.]+" | grep -oE "[0-9.]+" | sort | uniq -c | sort -rn
)
for ligne in "${bf[@]}"; do
  n=$(echo "$ligne" | awk '{print $1}'); ip=$(echo "$ligne" | awk '{print $2}')
  if [ "${n:-0}" -ge "$SEUIL_BRUTEFORCE" ]; then
    alerte CRITIQUE "Brute force mot de passe" "$n echecs d'authentification depuis $ip (seuil $SEUIL_BRUTEFORCE)"
    alertes=$((alertes+1))
  fi
done

# --- 2. EXFILTRATION : lecture massive de dossiers patients via l'API ---
n=$(tail -n "$LIGNES" $SRC 2>/dev/null | grep -hE "GET /patients" | wc -l)
if [ "${n:-0}" -ge "$SEUIL_EXFILTRATION" ]; then
  alerte CRITIQUE "Exfiltration de donnees" "$n lectures de dossiers patients en rafale (seuil $SEUIL_EXFILTRATION) - lecture massive suspecte"
  alertes=$((alertes+1))
fi
# Suppression massive de dossiers (rancongiciel / sabotage)
if tail -n "$LIGNES" $SRC 2>/dev/null | grep -qiE "DELETE FROM patients"; then
  alerte CRITIQUE "Exfiltration de donnees" "suppression de dossiers patients detectee dans la base"
  alertes=$((alertes+1))
fi

# --- 3. RDP depuis une IP externe : bloque par le pare-feu ---
mapfile -t rdp < <(
  tail -n "$LIGNES" $SRC 2>/dev/null | grep -hE "BLOQUE-RDP-EXTERNE|DPT=3389" | \
  grep -oE "SRC=[0-9.]+" | sort | uniq -c | sort -rn
)
for ligne in "${rdp[@]}"; do
  n=$(echo "$ligne" | awk '{print $1}'); ip=$(echo "$ligne" | awk -F= '{print $2}')
  alerte CRITIQUE "RDP depuis l'exterieur" "$n tentative(s) RDP (port 3389) depuis l'IP externe $ip - bloquee(s) par le pare-feu"
  alertes=$((alertes+1))
done

# --- 4. INJECTION SQL : bloquee par le WAF (ModSecurity, regles OWASP 942xxx) ---
# On compte les requetes effectivement refusees (une ligne "Access denied" par requete)
n=$(tail -n "$LIGNES" $SRC 2>/dev/null | grep -hcE "ModSecurity: Access denied")
if [ "${n:-0}" -ge 1 ]; then
  # Message prioritaire : une regle SQL si presente, sinon la premiere alerte ModSecurity
  ex=$(tail -n "$LIGNES" $SRC 2>/dev/null | grep -hE "ModSecurity" | grep -iE "SQL" | \
       grep -oE "\[msg \"[^\"]+\"" | head -n 1 | sed 's/\[msg "//; s/"$//')
  [ -z "$ex" ] && ex=$(tail -n "$LIGNES" $SRC 2>/dev/null | grep -hE "ModSecurity" | \
       grep -oE "\[msg \"[^\"]+\"" | head -n 1 | sed 's/\[msg "//; s/"$//')
  alerte HAUTE "Injection SQL / attaque web" "$n requete(s) refusee(s) par le WAF ${ex:+(}${ex}${ex:+)}"
  alertes=$((alertes+1))
fi

# --- 5. ELEVATION DE PRIVILEGE : un utilisateur standard tente d'obtenir des droits admin ---
mapfile -t priv < <(
  tail -n "$LIGNES" $SRC "$AUTH" 2>/dev/null | \
  grep -hiE "not in the sudoers|user NOT in sudoers|added to group .?sudo|usermod.*(-aG|sudo|wheel)" | \
  grep -hoE "sudo:[[:space:]]+[a-zA-Z0-9_-]+" | awk '{print $NF}' | sort | uniq -c | sort -rn
)
for ligne in "${priv[@]}"; do
  n=$(echo "$ligne" | awk '{print $1}'); u=$(echo "$ligne" | awk '{print $2}')
  [ -z "${u:-}" ] && continue
  alerte CRITIQUE "Elevation de privilege" "le compte standard '$u' a tente d'obtenir des droits admin (sudo refuse) - $n evenement(s)"
  alertes=$((alertes+1))
done

echo
if [ "$alertes" -eq 0 ]; then
  echo "${vert}Aucune alerte sur la periode analysee.${raz}"
else
  echo "${rouge}${gras}$alertes alerte(s) - voir $JOURNAL_ALERTES${raz}"
fi
SCRIPT
chmod +x /usr/local/bin/siem-detect

# ---------------------------------------------------------------------------
# Surveillance en continu : relance la detection toutes les 5 s (pour la demo)
# ---------------------------------------------------------------------------
cat > /usr/local/bin/siem-surveiller <<'SCRIPT'
#!/bin/bash
echo "Surveillance SIEM en continu (Ctrl+C pour arreter)..."
while true; do
  clear
  /usr/local/bin/siem-detect
  sleep 5
done
SCRIPT
chmod +x /usr/local/bin/siem-surveiller

echo "[z4-bastion] Moteur de detection SIEM installe (siem-detect, siem-surveiller)."
