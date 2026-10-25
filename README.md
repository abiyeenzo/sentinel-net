<p align="center">
  <img src="assets/logo.svg" alt="Logo Sentinel Net" width="128" height="128" />
</p>

<h1 align="center">Sentinel Net</h1>

<p align="center">
  <a href="https://github.com/abiyeenzo/sentinel-net/actions/workflows/test.yml"><img src="https://github.com/abiyeenzo/sentinel-net/actions/workflows/test.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/abiyeenzo/sentinel-net/actions/workflows/release.yml"><img src="https://github.com/abiyeenzo/sentinel-net/actions/workflows/release.yml/badge.svg" alt="Build &amp; Package Multi-OS Executables" /></a>
  <a href="https://github.com/abiyeenzo/sentinel-net/releases/latest"><img src="https://img.shields.io/github/v/release/abiyeenzo/sentinel-net?label=Release" alt="Latest Release" /></a>
</p>

Plateforme autonome d'audit reseau defensif, de **correlation de vulnerabilites CVE** et de **reconnaissance OSINT** ecrite en **Go** (bibliotheque standard uniquement, aucune dependance externe, aucun runtime a installer). Elle combine une **interface graphique de bureau inspiree de Zenmap** et une **ligne de commande directe inspiree de Nmap**, sur **Windows**, **macOS** et **Linux**.

> **Usage responsable :** tout scan actif exige une confirmation explicite d'autorisation (`-y` ou `--authorized`). N'auditez que des systemes et perimetres dont vous avez la responsabilite ou l'autorisation ecrite.

---

## Fonctionnalites principales

- **Scan TCP multi-hotes rapide et deterministe** : IPv4, IPv6, sous-reseaux CIDR (`/22` a `/32`), plages d'IP, cadences `-T1` a `-T5` et profils metier (`quick`, `web`, `database`, `infra`, `containers`, `iot`, `top100`).
- **Correlation CVE avec scope affecte et liens officiels (`--vuln`, `--script=vuln`, `--cve-online`)** : identification passive des versions logicielles (CPE 2.3), affichage du **perimetre exact des versions vulnerables** (ex. `>= 8.5p1, < 9.8p1`), de la **version corrigee**, des reserves de retroportage Linux et des **liens directs cliquables vers NIST NVD, CVE.org et l'avis editeur** (catalogue hors-ligne integre + enrichissement optionnel en direct via l'API NIST NVD v2.0).
- **Suite complete de reconnaissance OSINT (`sentinel-net osint`, `--osint`)** : collecte parallele DNS (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `PTR`), controle anti-spoofing **SPF / DMARC**, detection de l'ecosysteme SaaS/Cloud, decouverte passive de sous-domaines via les journaux de transparence des certificats **`crt.sh`**, attribution **RDAP / WHOIS** (registrar, DNSSEC, bloc IP, contact abuse), **ASN BGP** et inspection optionnelle `security.txt` (RFC 9116) / `robots.txt`.
- **Interface graphique de bureau (style Zenmap)** : binaire GUI dedie sous Windows sans fenetre console, bundle `.app` Cocoa `WKWebView` universel sous macOS, paquet `.deb` sous Linux, avec sept onglets (`Sortie Nmap`, `Ports / Hotes`, `Vulnerabilites & CVE`, `OSINT & Recon`, `Topologie`, `Risques & Drift`, `Guide CLI`).
- **Suivi d'integrite et rapports multi-formats (`-oA`)** : baselines signees SHA-256 (`--save-baseline`, `--compare`, `--fail-on-drift`) et exports Nmap `.txt`, `JSON`, `HTML` autonome, `SARIF 2.1.0`, `Markdown` et `CSV`.

---

## Telechargement et installation (Windows, macOS, Linux)

Tous les executables et installateurs precompiles (avec empreintes `SHA256SUMS.txt`) sont disponibles sur **[GitHub Releases](https://github.com/abiyeenzo/sentinel-net/releases/latest)**.

### Windows (x64 & ARM64)

1. **Installateur graphique (`sentinel-net-setup-windows-amd64.exe`)** : installe l'interface graphique (`sentinel-net-gui.exe` sans fenetre console) et la CLI (`sentinel-net.exe`), cree les raccourcis Bureau / Menu Demarrer avec icone et configure automatiquement le `PATH`.
2. **Executable graphique portable (`sentinel-net-gui-windows-amd64.exe`)** : un seul `.exe` a lancer par double-clic, sans installation.
3. **Installation en une ligne PowerShell** :

```powershell
irm https://raw.githubusercontent.com/abiyeenzo/sentinel-net/main/scripts/install.ps1 | iex
```

### macOS (Apple Silicon & Intel)

1. **Application native macOS (`Sentinel-Net-macOS-universal.dmg`)** : glissez `Sentinel Net.app` dans `Applications` et ouvrez-la directement (fenetre Cocoa `WKWebView` universelle `arm64` + `x86_64`).
2. **Installation CLI en une ligne** :

```bash
curl -fsSL https://raw.githubusercontent.com/abiyeenzo/sentinel-net/main/scripts/install.sh | sh
```

### Linux (Debian / Ubuntu / Kali & binaires statiques)

1. **Paquet bureau & CLI `.deb` (`sentinel-net_1.2.0_amd64.deb` ou `arm64.deb`)** :

```bash
sudo apt install ./sentinel-net_1.2.0_amd64.deb
```

2. **Installation rapide toutes distributions** :

```bash
curl -fsSL https://raw.githubusercontent.com/abiyeenzo/sentinel-net/main/scripts/install.sh | sh
```

---

## Interface graphique (style Zenmap)

Lancez l'application depuis son icone Bureau / Applications, ou via la commande :

```bash
sentinel-net gui
```

---

## Commandes rapides en terminal (style Nmap + OSINT)

Consultez le **[Guide complet des commandes (`docs/CLI.md`)](docs/CLI.md)** pour toutes les options et equivalences Nmap.

```bash
# Reconnaissance OSINT passive d'un domaine ou d'une IP publique (DNS, SPF/DMARC, crt.sh, RDAP, ASN)
sentinel-net osint exemple.com

# Audit de vulnerabilites CVE avec scope des versions affectees et liens NVD / CVE.org
sentinel-net -sV --vuln 192.168.1.10 -y

# Audit complet tout-en-un : services + TLS X.509 + HTTP + CVE + enrichissement OSINT
sentinel-net -A --osint -R exemple.com -y

# Scanner un sous-reseau /24 rapidement (-T4) et n'afficher que les ports ouverts (--open)
sentinel-net -F -T4 --open 192.168.1.0/24 -y

# Generer tous les formats d'un coup : .txt (Nmap), .json, .html et .sarif (-oA)
sentinel-net -A --vuln 192.168.1.10 -oA rapport-audit -y

# Controler en CI qu'aucune CVE ou exposition >= high n'est presente (code retour 3 sinon)
sentinel-net -A --vuln 10.0.0.5 --fail-on-severity high -y
```

### Raccourcis essentiels

| Option / Commande | Role |
|---|---|
| `osint <cible>` | Reconnaissance OSINT passive (`DNS`, `SPF/DMARC`, `crt.sh`, `RDAP`, `ASN`) |
| `--vuln`, `--script=vuln` | Correlation CVE passive avec scope affecte, correctif et liens NVD / CVE.org |
| `--cve-online` | Enrichissement CVE en direct via l'API officielle NIST NVD v2.0 (CPE) |
| `--osint` | Ajoute automatiquement la collecte OSINT aux hotes scannes |
| `-y`, `--authorized` | Confirme l'autorisation explicite d'auditer la cible (obligatoire en scan actif) |
| `-F` | Scan rapide (`quick`, 18 ports critiques) |
| `-p <spec>` / `-p-` | Ports ou plages (`-p 22,80,8000-8050`) ou plage `1-4096` (`-p-`) |
| `-P <profil>` | Profil metier (`web`, `database`, `infra`, `containers`, `iot`, `top100`) |
| `-sV` / `-sC` / `-A` | Versions (`-sV`), TLS + HTTP (`-sC`), ou audit complet + CVE (`-A`) |
| `-T1` .. `-T5` | Cadence d'execution (`-T1` prudent a `-T5` local tres rapide) |
| `-oA <prefixe>` | Genere simultanement `.txt`, `.json`, `.html` et `.sarif` |
| `gui` | Ouvre l'interface graphique de bureau |

---

## Compilation depuis les sources (optionnel)

Requiert Go 1.24 ou plus recent :

```bash
make test
make build-all
```

## Documentation

- [Guide complet CLI, CVE & OSINT (style Nmap/Zenmap)](docs/CLI.md)
- [Architecture technique](docs/ARCHITECTURE.md)
- [Positionnement produit](docs/PRODUCT.md)
- [Politique de securite](docs/SECURITY.md)

## Licence

MIT
