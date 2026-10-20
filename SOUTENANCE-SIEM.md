# Soutenance - SIEM & remontée des logs

Tout est centré sur : les logs remontent bien au SIEM, et le SIEM détecte les attaques.

---

## 1. Le sujet en une phrase

> « Chaque machine envoie ses journaux à un collecteur central (le SIEM). Le SIEM les
> range, les analyse, et transforme les attaques en alertes classées par criticité. »

---

## 2. Comment les logs remontent (le chemin à expliquer)

```
Chaque machine (pare-feu, serveurs, poste)
   │   rsyslog local filtre ce qui part
   ▼   @@10.10.4.10:514  (TCP vers le SIEM)
SIEM (z4-bastion) : rsyslog ecoute sur le port 514
   ▼   range par source
/var/log/central/fw.log, z1-dmz.log, z2-app.log, z5-poste.log ...
   ▼
siem-detect  ->  alertes (ALERTES.log)
   ▼
OpenSearch  ->  visualisation (automatique, toutes les 20 s)
```

**Qui envoie quoi** (config rsyslog) :
| Source | Ce qui part | Fichier de conf |
|---|---|---|
| Serveurs Z1/Z2/Z3 | `auth,authpriv` + WAF (`local1`) | /etc/rsyslog.d/90-central.conf |
| Pare-feu | lignes contenant `BLOQUE` | /etc/rsyslog.d/90-siem.conf |
| Poste Z5 | `auth,authpriv` | /etc/rsyslog.d/90-siem.conf |
| SIEM (collecteur) | ecoute sur 514, range par hote | /etc/rsyslog.d/10-central.conf |

`@@` = TCP (fiable) · `@` seul = UDP.

---

## 3. La détection : siem-detect

Le moteur lit les fichiers de /var/log/central et leve une alerte par scenario :

| Attaque | Signal dans les logs | Criticite |
|---|---|---|
| Brute force | >= 5 echecs d'authentification depuis une meme IP | CRITIQUE |
| Exfiltration | lecture massive de dossiers via l'API | CRITIQUE |
| RDP externe | tentative port 3389 depuis Internet (bloquee) | CRITIQUE |
| Injection SQL | requete refusee par le WAF (OWASP) | HAUTE |
| Elevation de privilege | compte standard qui tente sudo (refuse) | CRITIQUE |

Seuils reglables dans /etc/siem-regles.conf. Alertes horodatees a l'heure reelle.

---

## 4. La visualisation : OpenSearch

Les logs partent automatiquement vers OpenSearch (toutes les 20 s).
Interface : http://192.168.56.30:5601 -> Discover / Dashboard "StartupMed - SIEM".

---

## 5. Démo pas à pas (3 fenetres)

| Fenetre | Role |
|---|---|
| A - SIEM | `vagrant ssh z4-bastion` |
| B - Poste | `vagrant ssh z5-poste` |
| C - PC | PowerShell (= Internet) |

1. (A) Remise a zero : `vagrant ssh z4-bastion -c "sudo siem-reset"`
2. (A) Etat initial : `vagrant ssh z4-bastion -c "sudo siem-detect"`  -> aucune alerte
3. (B) `siem-attaques bruteforce`  puis  `siem-attaques privilege`
4. (C) exfiltration : `1..20 | % { curl.exe -k -s -o NUL --max-time 5 "https://192.168.56.10/patients?id=$_" }`
5. (C) injection SQL : `curl.exe -k "https://192.168.56.10/patients?id=1%27%20OR%20%271%27=%271"`
6. (C) RDP : `Test-NetConnection 192.168.56.10 -Port 3389`
7. (A) `vagrant ssh z4-bastion -c "sudo siem-detect"`  -> 5 alertes
8. (A) `vagrant ssh z4-bastion -c "sudo cat /var/log/central/ALERTES.log"`

(Si les dates sont decalees : lancer sync-heure.ps1 avant.)

---

## 6. PROUVER que les logs remontent bien (le point cle de la soutenance)

**Montrer les fichiers collectes, un par source :**
```
vagrant ssh z4-bastion -c "sudo ls -l /var/log/central/"
```

**Montrer une ligne brute avec son heure reelle (ex. le RDP) :**
```
vagrant ssh z4-bastion -c "sudo grep RDP /var/log/central/fw.log"
```

**Montrer que le poste remonte bien au SIEM (elevation de privilege) :**
```
vagrant ssh z4-bastion -c "sudo grep -i sudoers /var/log/central/z5-poste.log"
```

> « On voit que chaque machine a son fichier dans /var/log/central, et que chaque
> evenement arrive avec son horodatage : les logs remontent bien au SIEM. »

---

## 7. Questions probables du jury

**"Comment un log remonte-t-il au SIEM ?"**
rsyslog sur chaque machine envoie en TCP vers le port 514 du collecteur. Le collecteur
range par nom d'hote dans /var/log/central.

**"Pourquoi TCP et pas UDP ?"**
TCP (`@@`) garantit la livraison ; UDP (`@`) peut perdre des messages.

**"Et si une machine est compromise, l'attaquant efface les logs ?"**
Les logs sont deja partis vers le SIEM (hors de la machine). Sur le SIEM, l'admin n'a
pas les droits de les effacer. En production : stockage immuable, retention 12 mois (NIS2).

**"Ce sont de vraies attaques ?"**
De vraies techniques, rejouees de facon controlee contre notre propre labo, a petite
echelle, pour tester la DETECTION. On ne teste pas l'attaque, on teste le SIEM.

**"Pourquoi 5 echecs pour le brute force ?"**
Un echec isole est normal. C'est la repetition qui fait l'attaque. Seuil reglable.

**"C'est un vrai SIEM ?"**
Le principe oui : collecte (rsyslog), correlation (siem-detect), visualisation (OpenSearch).
En production on utiliserait Wazuh, qui repose sur le meme moteur OpenSearch.

---

## En une phrase de conclusion

> « Les journaux de toutes les machines remontent en continu vers un collecteur central,
> qui les analyse et alerte par criticite, avec une visualisation dans OpenSearch. »
