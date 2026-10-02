#!/bin/bash
# Z2 — Jour 3 : l'API passe en conteneur durci (non-root, lecture seule, sans capacites)
# + scan de l'image avec Trivy + redemarrage automatique en cas de panne
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -y -q docker.io

# ---- Image : utilisateur non privilegie, aucun secret dedans ------------------
install -d -m 0755 /opt/startupmed/image
cp /opt/startupmed/app.py /opt/startupmed/image/app.py
cat > /opt/startupmed/image/Dockerfile <<'EOF'
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3 psycopg2-binary==2.9.9 \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY app.py /app/app.py
# Jamais root dans le conteneur
USER 10001
EXPOSE 8443
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD python -c "import ssl,urllib.request; urllib.request.urlopen('https://127.0.0.1:8443/patients', context=ssl._create_unverified_context(), timeout=4)"
CMD ["python", "/app/app.py"]
EOF
docker build -q -t startupmed-api:1.0 /opt/startupmed/image

# Certificat TLS lisible uniquement par l'utilisateur du conteneur (uid 10001)
install -d -m 0500 -o 10001 -g 10001 /etc/startupmed/tls
install -m 0400 -o 10001 -g 10001 /etc/startupmed/app.crt /etc/startupmed/tls/app.crt
install -m 0400 -o 10001 -g 10001 /etc/startupmed/app.key /etc/startupmed/tls/app.key

# ---- Remplacer le service Python "nu" par le conteneur -------------------------
systemctl disable --now startupmed-api 2> /dev/null || true
docker rm -f startupmed-api > /dev/null 2>&1 || true
docker run -d --name startupmed-api \
  --restart always \
  -p 10.10.2.10:8443:8443 \
  --env-file /etc/startupmed/app.env \
  -e TLS_DIR=/tls -v /etc/startupmed/tls:/tls:ro \
  --read-only --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 256m --pids-limit 100 \
  startupmed-api:1.0 > /dev/null

# ---- Raccourcis pour la demo ----------------------------------------------------
cat > /usr/local/bin/verif-conteneur <<'EOF'
#!/bin/bash
# Montre les protections appliquees au conteneur de l'API
docker inspect -f 'Image            : {{.Config.Image}}
Utilisateur      : {{.Config.User}} (non root)
FS lecture seule : {{.HostConfig.ReadonlyRootfs}}
Capacites retirees : {{.HostConfig.CapDrop}}
Options securite : {{.HostConfig.SecurityOpt}}
Limite memoire   : {{.HostConfig.Memory}} octets
Redemarrage auto : {{.HostConfig.RestartPolicy.Name}}
Etat de sante    : {{.State.Health.Status}}' startupmed-api
echo
echo "> id dans le conteneur :"
docker exec startupmed-api id
echo "> tentative d'ecriture dans l'image :"
docker exec startupmed-api touch /app/pirate 2>&1 || true
EOF

cat > /usr/local/bin/scan-image <<'EOF'
#!/bin/bash
# Scan des vulnerabilites HIGH/CRITICAL de l'image avec Trivy (comme dans une CI/CD)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache \
  aquasec/trivy:latest image --scanners vuln --severity HIGH,CRITICAL --no-progress startupmed-api:1.0
EOF

cat > /usr/local/bin/simuler-panne <<'EOF'
#!/bin/bash
# Tue brutalement l'API puis montre que le conteneur redemarre tout seul
echo "Avant : $(docker ps --filter name=startupmed-api --format '{{.Status}}')"
echo ">>> Panne simulee : arret brutal du processus de l'API"
pkill -9 -f "python /app/app.py"
for i in 1 2 3 4 5 6; do
  sleep 2
  echo "  +$((i*2)) s : $(docker ps -a --filter name=startupmed-api --format '{{.Status}}')"
done
echo "Redemarrages depuis le lancement : $(docker inspect -f '{{.RestartCount}}' startupmed-api)"
EOF
chmod +x /usr/local/bin/verif-conteneur /usr/local/bin/scan-image /usr/local/bin/simuler-panne

echo "[z2-app] API en conteneur durci (startupmed-api:1.0)."
