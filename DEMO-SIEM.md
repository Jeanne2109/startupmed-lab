# Fiche de démonstration SIEM - StartupMed

À suivre pas à pas devant le jury. Durée : environ 6 minutes.

---

## En une phrase

> « Notre SIEM centralise les journaux de toutes les zones et du pare-feu. Un moteur de
> détection les corrèle et transforme les évènements isolés en alertes classées par criticité.
> Je vais lancer 5 attaques ; le SIEM doit toutes les remonter. »

## Avant de commencer (5 min avant le passage)

Dans PowerShell, dans le dossier `StartupMed-Lab` :

```
vagrant up
```

Attendre que les 6 VM soient démarrées (`vagrant status` les montre « running »).

Ouvrir **2 fenêtres PowerShell** dans le même dossier :
- Fenêtre **SIEM** : la détection.
- Fenêtre **ATTAQUE** : les attaques.

---

## Déroulé de la démo

### 1. Partir de journaux propres, puis montrer que le SIEM surveille (fenêtre SIEM)

Remettre les journaux à zéro (pour une démo nette) :
```
vagrant ssh z4-bastion -c "sudo siem-reset"
```

Vérifier qu'il n'y a aucune alerte :
```
vagrant ssh z4-bastion -c "sudo siem-detect"
```

> « Au repos, aucune alerte. Le SIEM écoute les journaux de Z1 à Z5 et du pare-feu. »

### 2. Lancer les 5 attaques (fenêtre ATTAQUE)

**Attaque 1 - Brute force sur mot de passe** (depuis le poste du siège)
```
vagrant ssh z5-poste -c "siem-attaques bruteforce"
```
> « Un poste interne compromis tente 6 mots de passe sur le bastion. »

**Attaque 2 - Élévation de privilège** (depuis le poste)
```
vagrant ssh z5-poste -c "siem-attaques privilege"
```
> « Un compte standard, un stagiaire, essaie d'obtenir les droits administrateur. »

**Attaque 3 - Exfiltration de données** (depuis le PC = Internet)
```
1..20 | % { curl.exe -k -s -o NUL --max-time 5 "https://192.168.56.10/patients?id=$_" }
```
> « Un compte médecin volé aspire les dossiers patients en rafale. »

**Attaque 4 - Injection SQL** (depuis le PC)
```
curl.exe -k "https://192.168.56.10/patients?id=1%27%20OR%20%271%27=%271"
```
> « Une injection SQL classique ; le WAF répond 403. »

**Attaque 5 - RDP depuis l'extérieur** (depuis le PC)
```
Test-NetConnection 192.168.56.10 -Port 3389
```
> « Un scan RDP depuis Internet, bloqué par le pare-feu. »

### 3. Le SIEM remonte tout (fenêtre SIEM)

```
vagrant ssh z4-bastion -c "sudo siem-detect"
```

Les 5 alertes s'affichent, chacune avec sa criticité. Résultat attendu :

| Attaque | Alerte du SIEM | Criticité |
|---|---|---|
| 1 Brute force | N échecs d'authentification depuis 10.10.5.10 | CRITIQUE |
| 2 Élévation de privilège | le compte standard 'stagiaire' a tenté d'obtenir des droits admin | CRITIQUE |
| 3 Exfiltration | N lectures de dossiers patients en rafale - lecture massive suspecte | CRITIQUE |
| 4 Injection SQL | requête refusée par le WAF (SQL Injection Attack Detected) | HAUTE |
| 5 RDP externe | tentative RDP depuis l'IP externe 192.168.56.1 - bloquée par le pare-feu | CRITIQUE |

### 4. Les alertes sont tracées et conservées

```
vagrant ssh z4-bastion -c "sudo cat /var/log/central/ALERTES.log"
```

> « Chaque alerte est horodatée et attribuée. En production, elles partent vers l'astreinte
> puis vers un SOC, avec les règles de corrélation de Wazuh. »

---

## Si le jury pose des questions

- **« Comment le SIEM reçoit-il les journaux ? »**
  Chaque serveur et chaque poste a un agent qui envoie ses journaux au SIEM en Z4 (flux F10).
  Le pare-feu envoie aussi ses blocages. Les sondes IDS complètent (flux F20).

- **« Pourquoi 5 échecs et pas 1 ? »**
  Un échec d'authentification est normal (faute de frappe). C'est la répétition qui fait l'attaque.
  Le seuil est réglable dans `/etc/siem-regles.conf`.

- **« Que se passe-t-il après l'alerte ? »**
  En production : notification à l'astreinte, puis au SOC ; blocage automatique possible de l'IP ;
  et pour l'exfiltration, vérification des accès par patient.

- **« Et si l'attaquant efface les journaux ? »**
  Les journaux sont centralisés hors de la machine attaquée, et l'admin n'a pas les droits pour
  les effacer sur le SIEM. En production, stockage immuable, rétention 12 mois (NIS2).

---

## Rappel : où taper quoi

| Début de ligne | Où vous êtes | Commandes |
|---|---|---|
| `C:\...\StartupMed-Lab>` ou `PS C:\...>` | votre PC (= Internet) | `vagrant ...`, `curl.exe`, `Test-NetConnection` |
| `vagrant@z5-poste:~$` | dans une VM | `siem-attaques`, `nc` |

Les commandes `Test-NetConnection` et `1..20 | % { }` sont du **PowerShell** : si vous êtes dans
l'invite `cmd`, tapez d'abord `powershell`.
