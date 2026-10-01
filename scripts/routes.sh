#!/bin/bash
# Fait passer tout le trafic inter-zones (et le retour vers Z0) par le pare-feu.
# Execute a chaque demarrage (run: "always").
set -euo pipefail
GW="$1"
ip route replace 10.10.0.0/16 via "$GW"
ip route replace 192.168.56.0/24 via "$GW"
