# Labo StartupMed - Segmentation & matrice de flux

Ce labo reproduit l'architecture de l'Atelier 2 avec 6 VM Debian et une seule commande.
Le pare-feu applique la matrice de flux : tout ce qui n'est pas autorisé est bloqué et journalisé.

```
Votre PC (Z0 « Internet », 192.168.56.1)
        │ HTTPS 443
   ┌────▼─────┐
   │    fw    │  routeur + nftables = F1 / F2 / F3
   └┬──┬──┬──┬┬┘
    │  │  │  │└─ Z5 Siège ........ z5-poste    10.10.5.10
    │  │  │  └── Z4 Admin ........ z4-bastion  10.10.4.10  (SSH + MFA, logs centralisés)
    │  │  └───── Z3 Données ...... z3-db       10.10.3.10  (PostgreSQL TLS)
    │  └──────── Z2 Applicative .. z2-app      10.10.2.10  (API de démo)
    └─────────── Z1 DMZ .......... z1-dmz      10.10.1.10  (WAF Apache + ModSecurity)
```

## 1. Installation (une seule fois)

1. Installez **VirtualBox** (virtualbox.org) puis **Vagrant** (vagrantup.com), et redémarrez le PC.
2. Vérifiez que la virtualisation est activée : Gestionnaire des tâches → Performance → Processeur → « Virtualisation : Activé ».
3. Ouvrez un terminal (PowerShell) **dans ce dossier** et lancez :

```
vagrant up
```

La première fois, comptez 15 à 20 minutes (téléchargement de Debian + installation).
RAM utilisée : environ 3,5 Go.

4. Vérifiez que les 6 VM tournent :

```
vagrant status
```

## 2. Préparer la démo 

**a. Enregistrer le MFA sur votre téléphone** (une seule fois) :

```
vagrant ssh z4-bastion -c "sudo qr-mfa"
```

Scannez le QR code avec Google Authenticator ou Microsoft Authenticator.

**b. Récupérer le mot de passe du compte admin** (généré automatiquement, jamais écrit dans le code) :

```
type .lab-secrets\admin_password
```

(Dans PowerShell, `type` fonctionne aussi ; `Get-Content` ne marche que dans PowerShell, pas dans l'Invite de commandes.)

**c. Ouvrir 3 fenêtres de terminal** dans ce dossier :

| Fenêtre | Commande | Rôle |
| --- | --- | --- |
| 1 — Pare-feu | `vagrant ssh fw` puis `sudo logs-blocages` | Voir les blocages en direct |
| 2 — Siège | `vagrant ssh z5-poste` | Jouer le salarié / l'attaquant interne |
| 3 — Bastion | `vagrant ssh z4-bastion` puis `sudo logs-centraux` | Voir la traçabilité |

## 3. Scénario de démo (5 minutes)

### Démo 1 — Le chemin légitime fonctionne (F1 → F2 → F3)
Dans le navigateur de votre PC : **https://192.168.56.10**
→ Acceptez l'avertissement de certificat (certificat de labo).
→ La page affiche les patients (fictifs) : Internet → WAF → API → base de données.

> « Le patient ne parle qu'au WAF. Le WAF ne parle qu'à l'API. Seule l'API parle à la base. »

### Démo 2 — Le WAF bloque une injection SQL
Dans PowerShell sur votre PC (attention : `curl.exe`, pas `curl`) :

```
curl.exe -k -i "https://192.168.56.10/patients?id=1%27%20OR%20%271%27=%271"
```

→ Réponse **403 Forbidden** : ModSecurity a bloqué `1' OR '1'='1`.
→ Fenêtre 3 : la ligne ModSecurity apparaît dans les logs centralisés (`z1-dmz.log`).

### Démo 3 — Le siège ne peut pas atteindre les données (F15 bloqué)
Fenêtre 2 (z5-poste) :

```
nc -zv -w 3 10.10.3.10 5432
```

→ Échec (timeout).
→ Fenêtre 1 : `BLOQUE-F15 ... SRC=10.10.5.10 DST=10.10.3.10 ... DPT=5432`

> « Même un poste interne compromis par phishing n'a aucun chemin réseau vers les données de santé. »

Pour comparer, le même test depuis l'API fonctionne (F3 autorisé) :

```
vagrant ssh z2-app -c "nc -zv -w 3 10.10.3.10 5432"
```

### Démo 4 — L'administration passe obligatoirement par le bastion avec MFA
Fenêtre 2 (z5-poste), tentative d'accès direct :

```
ssh -o ConnectTimeout=5 admin@10.10.3.10
```

→ Échec, et `BLOQUE-F15` dans la fenêtre 1.

Accès légitime via le bastion :

```
ssh admin@10.10.4.10
```

→ `Password:` (mot de passe de l'étape 2b), puis `Verification code:` (code du téléphone).
Une fois sur le bastion, rebond vers la base :

```
ssh z3-db
```

→ Connexion réussie par clé (flux F7). Fenêtre 3 : la connexion est tracée dans `z3-db.log`.

> « Pas de MFA, pas d'admin. Et chaque connexion est journalisée de façon centralisée. »

### Démo 5 — La matrice de flux EST la configuration
Fenêtre 1 : `Ctrl+C`, puis :

```
sudo regles
```

→ Chaque règle porte le numéro de flux de la matrice (F1, F2, F3, F6, F7, F10, F15, F16) et un **compteur de paquets**.
La dernière ligne `BLOQUE-NON-DOCUMENTE` refuse tout le reste.

> « Un flux non documenté est un flux suspect : ici il est littéralement refusé. »

### Bonus — Internet ne voit que le port 443
Si Nmap est installé sur votre PC :

```
nmap -Pn 192.168.56.10
```

→ Seul le port **443** est ouvert : aucune interface d'administration n'est exposée.

## 4. Correspondance avec la matrice de flux (Atelier 2)

| Flux | Labo | Port labo | Différence avec la cible de production |
| --- | --- | --- | --- |
| F1 | Votre PC → WAF | 443 | Identique (+ anti-DDoS en production) |
| F2 | WAF → API | 8443 HTTPS | mTLS avec certificat client en production |
| F3 | API → PostgreSQL | 5432 TLS | Identique (+ KMS en production) |
| F6 | Siège → bastion | 22 SSH + TOTP | ZTNA (443) + Teleport + Keycloak en production |
| F7 | Bastion → serveurs | 22 par clé | Certificats éphémères + sessions enregistrées (Teleport) |
| F10 | Serveurs → logs | 514 (rsyslog) | SIEM Wazuh en TLS, rétention 12 mois |
| F15 | Siège → données | — | **Bloqué**, identique |
| F16 | Internet → admin | — | **Bloqué**, identique |

À dire à l'oral : « En labo, on démontre les principes avec des briques légères. En production, ce sont les composants de la matrice (Teleport, Keycloak, Wazuh, mTLS) qui les portent. »

## 5. Commandes utiles

| Commande | Effet |
| --- | --- |
| `vagrant up` | Démarre tout le labo |
| `vagrant halt` | Éteint toutes les VM |
| `vagrant ssh <vm>` | Ouvre un terminal dans une VM (fw, z1-dmz, z2-app, z3-db, z4-bastion, z5-poste) |
| `vagrant provision <vm>` | Réapplique la configuration d'une VM |
| `vagrant destroy -f` | Supprime toutes les VM (repartir de zéro) |

## 6. En cas de problème

| Symptôme | Solution |
| --- | --- |
| `vagrant up` dit que VT-x/AMD-V n'est pas disponible | Activez la virtualisation dans le BIOS |
| VM très lentes ou qui ne démarrent pas | Désactivez « Plateforme de machine virtuelle » dans Fonctionnalités Windows, puis redémarrez |
| La page https://192.168.56.10 ne répond pas | `vagrant status` : vérifiez que fw, z1-dmz, z2-app et z3-db tournent |
| Le code MFA est refusé | Vérifiez l'heure du téléphone (automatique). Sur le bastion : `timedatectl` |
| Une VM est cassée | `vagrant destroy -f z2-app` puis `vagrant up z2-app` |

## Limites connues du labo
- Chaque VM garde une carte « NAT » dont Vagrant se sert pour la piloter et installer les paquets. Les tests de segmentation se font donc sur les adresses `10.10.x.x` et `192.168.56.10`.
- Le dossier `.lab-secrets/` contient les secrets du labo (mot de passe admin, mot de passe BDD, clé SSH). Ne le partagez pas et ne le mettez pas sur Git.
- Les données patients sont fictives.
