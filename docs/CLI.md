# Guide d'utilisation : Interface Graphique, Correlation CVE et Reconnaissance OSINT

Sentinel Net fonctionne selon le meme principe que le couple **Nmap + Zenmap**, enrichi d'un moteur de **correlation CVE avec scope de versions affectees et liens officiels** ainsi que d'une **suite complete de reconnaissance OSINT passive**.

> **Rappel d'autorisation :** toute analyse active (sondes TCP ou option `--web` sur cible distante) exige le drapeau `-y` (ou `--authorized`), ou la case d'autorisation cochee dans l'interface graphique.

---

## 1. Interface graphique de bureau (style Zenmap)

### Comment l'ouvrir

- **Windows** : double-cliquez sur le raccourci **Sentinel Net** (`sentinel-net-gui.exe` / `sentinel-net.exe`), ou tapez `sentinel-net gui`. L'application s'ouvre dans sa propre fenetre sans console noire en arriere-plan.
- **macOS** : ouvrez `Sentinel Net.app` depuis le dossier `Applications` (fenetre Cocoa `WKWebView` native), ou tapez `sentinel-net gui`.
- **Linux** : lancez **Sentinel Net** depuis le menu Applications de votre bureau, ou tapez `sentinel-net gui`.

### Organisation des sept onglets

1. **Sortie Nmap** : journal en direct et transcription complete au format Nmap (incluant `| vulns:`, le scope affecte, les liens NVD/CVE.org et les lignes `|_ osint-*`).
2. **Ports / Hotes** : tableau filtrable par etat (`open`, `closed`, `unknown`), port, service, banniere ou presence de CVE.
3. **Vulnerabilites & CVE** : liste des composants logiciels identifies (CPE 2.3), severite CVSS v3.1, **scope exact des versions affectees** (ex. `>= 8.5p1, < 9.8p1`), **version corrigee**, note sur le retroportage des paquets Linux et **boutons cliquables directs vers NIST NVD, CVE.org et l'avis editeur**.
4. **OSINT & Recon** : poste de reconnaissance dedie permettant de lancer une collecte OSINT sur n'importe quel domaine ou IP (DNS `A/AAAA/MX/NS/TXT/PTR`, posture anti-spoofing `SPF`/`DMARC`, ecosysteme Cloud/SaaS, sous-domaines issus des journaux de transparence des certificats `crt.sh`, attribution `RDAP`/WHOIS, `ASN` BGP et `security.txt` RFC 9116), avec ciblage en un clic des sous-domaines decouverts.
5. **Topologie** : carte radiale interactive reliant le scanner aux hotes et a leurs ports ouverts.
6. **Risques & Drift** : score de posture `/100`, constats `SN-*` et comparaison signee SHA-256 par rapport a une baseline.
7. **Guide CLI** : modeles de commandes prets a charger en un clic dans la barre de commande.

---

## 2. Correlation de vulnerabilites : Scope affecte et liens CVE (`--vuln` / `--script=vuln`)

Lorsqu'un service ouvert annonce sa version (banniere SSH/FTP/SMTP/Redis, en-tetes HTTP `Server` / `X-Powered-By`, ou protocole/chiffrement TLS), Sentinel Net extrait passivement une empreinte **CPE 2.3** sans envoyer la moindre charge d'exploitation :

```bash
# Verification CVE hors-ligne rapide avec scope affecte et liens NVD / CVE.org
sentinel-net -sV --vuln 192.168.1.10 -y

# Syntaxe compatible Nmap NSE (--script=vuln) avec sortie Nmap
sentinel-net --script=vuln --nmap -p 22,80,443 192.168.1.10 -y

# Interrogation complementaire en direct de l'API officielle NIST NVD v2.0 par CPE
sentinel-net -A --cve-online 192.168.1.10 -y
```

Chaque vulnerabilite identifiee affiche :
- **Identifiant et criticite** : `CVE-XXXX-YYYY`, score **CVSS v3.1** et categorie `CWE`.
- **Scope de vulnerabilite (`affectedScope`)** : plage exacte des versions vulnerables (par exemple `>= 8.5p1, < 9.8p1` pour `CVE-2024-6387` sur OpenSSH, ou `2.4.49 - 2.4.50` sur Apache HTTPd) ainsi que la **version corrigee**.
- **Avertissement de retroportage** : indication explicite lorsque la banniere provient d'une distribution Linux (`Debian`, `Ubuntu`, `RHEL`) susceptible d'avoir retroporte le correctif sans changer le numero de version amont.
- **Liens directs vers la CVE** : URL officielle **NIST NVD** (`https://nvd.nist.gov/vuln/detail/CVE-...`), **CVE.org** (`https://www.cve.org/CVERecord?id=CVE-...`) et avis de securite de l'editeur, cliquables dans l'interface graphique, les rapports HTML, Markdown et SARIF.

---

## 3. Systeme complet de reconnaissance OSINT (`osint` et `--osint`)

### Reconnaissance OSINT passive autonome (sans scan de ports)

La sous-commande `osint` interroge uniquement des sources publiques (DNS, `crt.sh`, `rdap.org`, `ipwho.is`) sans scanner les ports de la cible :

```bash
# Rapport OSINT complet dans le terminal (domaine, sous-domaine, URL ou IP publique)
sentinel-net osint exemple.com

# Export JSON structure (sous-domaines CT, enregistrements DNS, SPF/DMARC, RDAP, ASN)
sentinel-net osint exemple.com -f json -o osint-exemple.json

# Inclure l'inspection legere de surface Web (/.well-known/security.txt, /robots.txt, technologies)
sentinel-net osint exemple.com --web -y
```

### Scan reseau combine a l'OSINT (`--osint`)

```bash
sentinel-net -A --osint -R exemple.com -oA audit-complet -y
```

Modules OSINT executes en parallele :
- **DNS & messagerie** : `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `PTR` inverse, analyse anti-usurpation **SPF** (`-all`, `~all`, `+all`) et **DMARC** (`p=reject`, `quarantine`, `none`), et empreinte de l'ecosysteme Cloud/SaaS (`Cloudflare`, `Google Workspace`, `Microsoft 365`, `AWS`, `Proton Mail`, `SendGrid`, `Vercel`, etc.).
- **Transparence des certificats (`crt.sh`)** : enumeration passive et dedoublonnee des sous-domaines historiques et des autorites de certification, avec detection automatique des sous-domaines sensibles (`dev`, `staging`, `admin`, `vpn`, `gitlab`, `grafana`...).
- **Attribution RDAP / WHOIS & BGP ASN** : bureau d'enregistrement (`registrar`), etat **DNSSEC** (`delegationSigned`), bloc IP alloue, contact `abuse`, numero d'**ASN**, operateur et localisation geographique.
- **Surface Web (`--web -y`)** : titre HTML, empreinte technologique passive, directives `/robots.txt`, contact officiel de divulgation `/.well-known/security.txt` (RFC 9116) et certificat X.509.

---

## 4. Equivalence directe avec Nmap

| Intention | Commande Nmap | Equivalent Sentinel Net |
|---|---|---|
| Scanner les ports courants d'un hote | `nmap 192.168.1.1` | `sentinel-net 192.168.1.1 -y` |
| Scan rapide (ports essentiels) | `nmap -F 192.168.1.1` | `sentinel-net -F 192.168.1.1 -y` |
| Scanner des ports precis et plages | `nmap -p 22,80,443,8000-8050 10.0.0.5` | `sentinel-net -p 22,80,443,8000-8050 10.0.0.5 -y` |
| Scanner les N ports les plus frequents | `nmap --top-ports 25 10.0.0.5` | `sentinel-net --top-ports 25 10.0.0.5 -y` |
| Plage etendue 1 a 4096 | `nmap -p 1-4096 10.0.0.5` | `sentinel-net -p- 10.0.0.5 -y` |
| Identifier les services et bannieres | `nmap -sV 10.0.0.5` | `sentinel-net -sV 10.0.0.5 -y` |
| Verifier les CVE connues et leur scope | `nmap -sV --script=vuln 10.0.0.5` | `sentinel-net -sV --script=vuln 10.0.0.5 -y` |
| Verifier TLS X.509 et en-tetes HTTP | `nmap -sC 10.0.0.5` | `sentinel-net -sC 10.0.0.5 -y` |
| Audit complet (versions + TLS + HTTP + CVE) | `nmap -A 10.0.0.5` | `sentinel-net -A 10.0.0.5 -y` |
| Reconnaissance OSINT passive | `nmap --script=asn-query,whois-* ...` | `sentinel-net osint exemple.com` |
| Scanner tout un sous-reseau `/24` vite | `nmap -F -T4 192.168.1.0/24` | `sentinel-net -F -T4 192.168.1.0/24 -y` |
| Afficher uniquement les ports ouverts | `nmap --open 192.168.1.0/24` | `sentinel-net --open 192.168.1.0/24 -y` |
| Lire les cibles depuis un fichier | `nmap -iL cibles.txt` | `sentinel-net -iL cibles.txt -y` |
| Exporter tous les formats d'un coup | `nmap -oA audit-prod ...` | `sentinel-net -oA audit-prod ... -y` |

---

## 5. Cadences (`-T1` a `-T5`), Profils (`-P`) et Codes retour

| Template | Concurrence | Timeout / sonde | Pause inter-sonde | Retries | Usage conseille |
|---|---|---|---|---|---|
| `-T1` | `2` | `3000 ms` | `250 ms` | `1` | Equipements anciens ou liens WAN fragiles |
| `-T2` | `8` | `2000 ms` | `60 ms` | `1` | Objets connectes (IoT), imprimantes, automates |
| `-T3` | `24` | `1000 ms` | `0 ms` | `0` | Cadence equilibree par defaut |
| `-T4` | `64` | `500 ms` | `0 ms` | `1` | Reseau local (LAN Ethernet / Wi-Fi fiable) |
| `-T5` | `128` | `250 ms` | `0 ms` | `0` | Machine locale (`127.0.0.1`) ou lien gigabit dedie |

Profils disponibles (`sentinel-net profiles`) : `quick` (`-F`), `top100`, `web`, `database`, `infra`, `containers`, `iot`.

| Code sortie | Signification |
|---|---|
| `0` | Execution terminee avec succes |
| `2` | Erreur d'arguments ou absence de `-y` / `--authorized` |
| `3` | Echec d'une regle de politique (`--fail-on-drift` ou `--fail-on-severity` sur constat ou CVE) |
| `130` | Scan interrompu par l'utilisateur (`Ctrl+C` / `SIGINT` / `SIGTERM`) |
