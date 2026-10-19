# Guide de soutenance - Projet StartupMed

Tout le projet de A à Z, pour l'expliquer simplement et sans se faire piéger.

---

## 1. Le contexte

StartupMed est une startup de **télémédecine** : téléconsultation + dossier patient.
Elle traite des **données de santé**, donc :
- hébergement **HDS obligatoire** (Hébergeur de Données de Santé, loi française) ;
- **RGPD** (données sensibles, article 9) ;
- disponibilité élevée (continuité des soins).

Ces contraintes commandent toute l'architecture.

---

## 2. Ce qu'on a produit (les livrables)

Le projet suit 3 ateliers + une synthèse :

| Atelier | Contenu |
|---|---|
| **Atelier 1** | Actifs critiques, analyse de risque, matrice d'exigences (E1 à E12), choix d'hébergement |
| **Atelier 2** | Segmentation en zones + matrice de flux (17 flux) + 3 risques résiduels |
| **Atelier 3** | Résilience (RTO/RPO, sauvegardes), supervision (SIEM), conteneurs (Kubernetes) |
| **Architecture cible** | Le schéma qui regroupe tout |
| **Labo** | Une maquette qui démontre l'architecture avec 6 machines virtuelles |

---

## 3. L'architecture en bref (5 zones)

Principe : **plus on est proche des données de santé, moins il y a de chemins d'accès.**
Tout flux non documenté est refusé par défaut.

```
Internet (Z0)
   | F1 (pare-feu + WAF)
Z1 DMZ          -> WAF, point d'entree expose
   | F2 (pare-feu interne)
Z2 Applicatif   -> l'application (API)
   | F3 (TLS)
Z3 Donnees      -> base patients (la plus critique)

Z4 Administration -> bastion MFA + SIEM (surveille tout)
Z5 Siege          -> postes salaries (traites comme non fiables)
```

5 principes appliqués : défense en profondeur, moindre privilège, cloisonnement,
résilience, réduction de la surface d'attaque.

---

## 4. Le labo de démonstration (6 VM)

Chaque VM = une zone. Le tout est décrit en code avec **Vagrant** (Infrastructure as Code).

| VM | Zone | Rôle | Outil |
|---|---|---|---|
| **fw** | toutes | Pare-feu : applique la matrice de flux | nftables |
| **z1-dmz** | Z1 | WAF exposé à Internet | Apache + ModSecurity |
| **z2-app** | Z2 | Application conteneurisée | Docker |
| **z3-db** | Z3 | Base des données de santé | PostgreSQL (TLS) |
| **z4-bastion** | Z4 | Bastion MFA + SIEM | OpenSSH + rsyslog |
| **z5-poste** | Z5 | Poste salarié (source d'attaques) | - |

Le PC joue "Internet" (Z0).

---

## 5. Les choix et leurs justifications

- **Hébergement hybride HDS** : les données chez un cloud certifié HDS (2 régions),
  le siège en local. Une startup ne peut pas certifier son propre datacenter.
- **Vagrant** : monte le labo en une commande, reproductible, versionné dans Git (= IaC, Jour 2).
- **nftables au lieu d'OPNsense** : même rôle de pare-feu, mais configurable automatiquement
  et lisible comme la matrice de flux.
- **SIEM léger (rsyslog + script) au lieu de Wazuh** : même logique (collecter, corréler,
  alerter), mais Wazuh demanderait 4 à 8 Go de RAM. Wazuh reste dans l'architecture cible.

> À dire : "En labo je démontre les principes avec des briques légères ; en production
> ce sont les outils de l'architecture cible (Wazuh, Keycloak, Teleport, Kubernetes)."

---

## 6. La démo en direct (étapes)

**Préparer** (journaux propres) :
`vagrant ssh z4-bastion -c "sudo siem-reset"`

**1. L'architecture marche** : ouvrir `https://192.168.56.10` -> la liste des patients.
**2. Le WAF bloque l'injection SQL** : `curl.exe -k "https://192.168.56.10/patients?id=1%27%20OR%20%271%27=%271"` -> 403.
**3. Le siège n'atteint pas les données** : `vagrant ssh z5-poste -c "nc -zv -w 3 10.10.3.10 5432"` -> echec.

**4. Le SIEM détecte 5 attaques** :
- `vagrant ssh z4-bastion -c "sudo siem-detect"` (0 alerte)
- Brute force : `vagrant ssh z5-poste -c "siem-attaques bruteforce"`
- Elevation de privilege : `vagrant ssh z5-poste -c "siem-attaques privilege"`
- Exfiltration : `1..20 | ForEach-Object { curl.exe -k -s -o NUL --max-time 5 "https://192.168.56.10/patients?id=$_" }`
- Injection SQL : `curl.exe -k "https://192.168.56.10/patients?id=1%27%20OR%20%271%27=%271"`
- RDP externe : `Test-NetConnection 192.168.56.10 -Port 3389`
- Resultat : `vagrant ssh z4-bastion -c "sudo siem-detect"` -> 5 alertes avec criticite

---

## 7. Questions pièges probables + réponses

**"Ce sont de vraies attaques ?"**
Ce sont de vraies techniques, rejouées de façon contrôlée contre notre propre labo isolé,
à petite échelle, pour tester la DÉTECTION. On ne teste pas l'attaque, on teste le SIEM.

**"Pourquoi les alertes ont la même heure ?"**
Non : chaque alerte porte l'heure réelle de l'attaque (lue dans les logs). Les journaux
bruts (/var/log/central/) gardent aussi l'heure exacte de chaque évènement.

**"Pourquoi 5 échecs pour détecter le brute force ?"**
Un échec isolé est normal (faute de frappe). C'est la répétition qui fait l'attaque.
Le seuil est réglable dans /etc/siem-regles.conf.

**"Et si l'attaquant efface les journaux ?"**
Ils sont centralisés sur le SIEM, hors de la machine attaquée. L'admin n'a pas les droits
pour les effacer. En production : stockage immuable, rétention 12 mois (NIS2).

**"Le labo, c'est toute l'architecture ?"**
Non, c'est une maquette qui démontre les principes. Kubernetes, Wazuh, la 2e région HDS
restent dans l'architecture cible (sur le schéma), trop lourds pour une démo locale.

**"Pourquoi le certificat n'est pas sécurisé (avertissement navigateur) ?"**
C'est un certificat auto-signé de labo. En production : un vrai certificat (Let's Encrypt
ou autorité reconnue).

**"Comment les données sont-elles protégées ?"**
Chiffrement en transit (TLS partout) et au repos (KMS), accès par l'API uniquement,
sauvegardes immuables 3-2-1, et MFA pour tout accès.

---

## En une phrase

> "Notre architecture cloisonne le SI en zones, n'autorise que les flux documentés,
> maîtrise les accès par un bastion avec MFA, et supervise le tout avec un SIEM qui
> transforme chaque attaque en alerte classée par criticité."
