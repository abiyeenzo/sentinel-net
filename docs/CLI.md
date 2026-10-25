# Guide d'utilisation : Interface Graphique et Commandes CLI (style Nmap)

Sentinel Net fonctionne selon le meme principe que le couple **Nmap + Zenmap** : un moteur unique utilisable soit via une **interface graphique de bureau**, soit en **ligne de commande courte et directe**.

> **Rappel d'autorisation :** toute analyse active exige le drapeau `-y` (ou `--authorized`), ou la case d'autorisation cochee dans l'interface graphique.

---

## 1. Interface graphique de bureau (style Zenmap)

### Comment l'ouvrir

- **Windows** : double-cliquez sur le raccourci **Sentinel Net** (ou sur `sentinel-net-gui.exe` / `sentinel-net.exe`), ou tapez `sentinel-net gui`. L'application s'ouvre dans sa propre fenetre sans console noire en arriere-plan.
- **macOS** : ouvrez `Sentinel Net.app` depuis le dossier `Applications` (fenetre Cocoa `WKWebView` native), ou tapez `sentinel-net gui`.
- **Linux** : lancez **Sentinel Net** depuis le menu Applications de votre bureau, ou tapez `sentinel-net gui`.

### Organisation de la fenetre

1. **Barre de commande interactive (haut)** : saisissez une cible, choisissez un profil (`Scan rapide (-F)`, `Audit complet (-A)`, `Audit Web`, `Bases de donnees`, etc.) et la cadence (`-T1` a `-T5`). Le champ **Commande** affiche en temps reel la commande CLI exacte correspondante et peut aussi etre modifie directement au clavier.
2. **Panneau lateral gauche** : basculez entre la liste des **Hotes** analyses (avec note de posture `A+` a `F`), la liste des **Services** ouverts (`ssh`, `https`, `postgresql`, etc.) et vos **Interfaces** reseau locales (clic direct sur l'IP ou le sous-reseau `/24`).
3. **Cinq onglets d'analyse** :
   - **Sortie Nmap** : journal en direct et rapport texte structure au format Nmap.
   - **Ports / Hotes** : tableau filtrable par etat (`open`, `closed`, `unknown`), port, service ou banniere.
   - **Topologie** : carte radiale interactive reliant le scanner aux hotes et a leurs ports ouverts.
   - **Risques & Details** : score sur 100, constats `SN-*`, details X.509 TLS, en-tetes HTTP et ecarts par rapport a une baseline.
   - **Guide CLI** : modeles de commandes prets a charger en un clic.

---

## 2. Equivalence directe avec Nmap

Si vous connaissez deja `nmap`, vous connaissez deja les commandes de `sentinel-net` :

| Intention | Commande Nmap | Equivalent Sentinel Net |
|---|---|---|
| Scanner les ports courants d'un hote | `nmap 192.168.1.1` | `sentinel-net 192.168.1.1 -y` |
| Scan rapide (ports essentiels) | `nmap -F 192.168.1.1` | `sentinel-net -F 192.168.1.1 -y` |
| Scanner des ports precis et plages | `nmap -p 22,80,443,8000-8050 10.0.0.5` | `sentinel-net -p 22,80,443,8000-8050 10.0.0.5 -y` |
| Scanner les N ports les plus frequents | `nmap --top-ports 25 10.0.0.5` | `sentinel-net --top-ports 25 10.0.0.5 -y` |
| Plage etendue 1 a 4096 | `nmap -p 1-4096 10.0.0.5` | `sentinel-net -p- 10.0.0.5 -y` |
| Identifier les services et bannieres | `nmap -sV 10.0.0.5` | `sentinel-net -sV 10.0.0.5 -y` |
| Verifier TLS X.509 et en-tetes HTTP | `nmap -sC 10.0.0.5` | `sentinel-net -sC 10.0.0.5 -y` |
| Audit complet (banniere + TLS + HTTP) | `nmap -A 10.0.0.5` | `sentinel-net -A 10.0.0.5 -y` |
| Scanner tout un sous-reseau `/24` vite | `nmap -F -T4 192.168.1.0/24` | `sentinel-net -F -T4 192.168.1.0/24 -y` |
| Afficher uniquement les ports ouverts | `nmap --open 192.168.1.0/24` | `sentinel-net --open 192.168.1.0/24 -y` |
| Lire les cibles depuis un fichier | `nmap -iL cibles.txt` | `sentinel-net -iL cibles.txt -y` |
| Activer la resolution DNS | `nmap -R srv01.interne.lan` | `sentinel-net -R srv01.interne.lan -y` |
| Sortie texte style Nmap dans un fichier | `nmap -oN resultat.txt ...` | `sentinel-net -oN resultat.txt ... -y` |
| Exporter tous les formats d'un coup | `nmap -oA audit-prod ...` | `sentinel-net -oA audit-prod ... -y` |

---

## 3. Recettes pratiques par scenario

### Verifier rapidement un serveur

```bash
sentinel-net -F 192.168.1.10 -y
```

### Cartographier les machines actives d'un LAN `/24`

```bash
sentinel-net -F -T4 --open 192.168.1.0/24 -y
```

### Audit complet d'un serveur Web ou API (banniere, certificat TLS, en-tetes HTTP)

```bash
sentinel-net -A -P web -R mon-service.exemple.fr -y
```

### Verifier qu'aucune base de donnees n'est exposee sur un segment

```bash
sentinel-net -P database -sV 10.0.10.1-50 -y
```

### Generer un dossier complet d'audit en une seule commande (`-oA`)

```bash
sentinel-net -A 192.168.1.10 -oA audit-2026-10 -y
```

Cette commande produit quatre fichiers prets a archiver ou partager :
- `audit-2026-10.txt` : rapport texte style Nmap
- `audit-2026-10.json` : rapport JSON complet
- `audit-2026-10.html` : rapport visuel autonome ouvrable dans n'importe quel navigateur
- `audit-2026-10.sarif` : rapport SARIF 2.1.0 pour GitHub Code Scanning / SIEM

### Detecter automatiquement toute nouvelle ouverture de port (CI / Cron)

```bash
# 1. Enregistrer l'etat de reference signe SHA-256
sentinel-net -F 10.0.0.5 --save-baseline reference.json -y

# 2. Verifier plus tard qu'aucun nouveau port n'a ete ouvert (retourne code 3 en cas d'ecart)
sentinel-net -F 10.0.0.5 --compare reference.json --fail-on-drift -y

# 3. Echouer si un constat de severite high ou critical est detecte
sentinel-net -A 10.0.0.5 --fail-on-severity high -y
```

---

## 4. Cadences d'execution (`-T1` a `-T5`)

| Template | Concurrence | Timeout / sonde | Pause inter-sonde | Retries | Usage conseille |
|---|---|---|---|---|---|
| `-T1` | `2` | `3000 ms` | `250 ms` | `1` | Equipements anciens ou liens WAN fragiles |
| `-T2` | `8` | `2000 ms` | `60 ms` | `1` | Objets connectes (IoT), imprimantes, automates |
| `-T3` | `24` | `1000 ms` | `0 ms` | `0` | Cadence equilibree par defaut |
| `-T4` | `64` | `500 ms` | `0 ms` | `1` | Reseau local (LAN Ethernet / Wi-Fi fiable) |
| `-T5` | `128` | `250 ms` | `0 ms` | `0` | Machine locale (`127.0.0.1`) ou lien gigabit dedie |

Tout parametre explicite (`--concurrency`, `--timeout`, `--delay-ms`, `--retries`) surcharge la valeur du template `-T` choisi.

---

## 5. Profils metier integres (`-P` / `--profile`)

Consultables a tout moment via `sentinel-net profiles` :

- `quick` (ou `-F`) : 18 ports critiques (SSH, HTTP/S, SMB, RDP, MySQL, PostgreSQL, Redis, Docker, etc.)
- `top100` : 95 ports TCP les plus courants en entreprise (profil applique par defaut)
- `web` : ports HTTP, HTTPS, proxys inverses et serveurs applicatifs (80, 443, 3000, 8000, 8080, 8443, 9000...)
- `database` : MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB, Elasticsearch, ClickHouse, Cassandra...
- `infra` : SSH, Telnet, DNS, Kerberos, LDAP/S, SMB, SNMP, WinRM, RDP, VNC, IPMI...
- `containers` : Docker daemon, Kubernetes API/Kubelet, etcd, Consul, Prometheus, Grafana, Registry...
- `iot` : MQTT, RTSP, CoAP, UPnP, Modbus, BACnet, panneaux d'administration embarques...

---

## 6. Signification des etats de ports et codes retour

### Etats de ports

- `open` : connexion TCP etablie (`SYN-ACK` recu).
- `closed` : port joignable mais aucun service en ecoute (`RST` / `ECONNREFUSED`).
- `unknown` : aucune reponse avant expiration du delai (pare-feu filtrant en mode `DROP` ou hote hors ligne). Sentinel Net distingue explicitement cet etat pour eviter les faux negatifs.

### Codes de sortie processus

| Code | Signification |
|---|---|
| `0` | Execution terminee avec succes |
| `2` | Erreur d'arguments ou absence de `-y` / `--authorized` |
| `3` | Echec d'une regle de politique (`--fail-on-drift` ou `--fail-on-severity`) |
| `130` | Scan interrompu par l'utilisateur (`Ctrl+C` / `SIGINT` / `SIGTERM`) |
