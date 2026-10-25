<p align="center">
  <img src="assets/logo.svg" alt="Logo Sentinel Net" width="128" height="128" />
</p>

<h1 align="center">Sentinel Net</h1>

<p align="center">
  <a href="https://github.com/abiyeenzo/sentinel-net/actions/workflows/test.yml"><img src="https://github.com/abiyeenzo/sentinel-net/actions/workflows/test.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/abiyeenzo/sentinel-net/actions/workflows/release.yml"><img src="https://github.com/abiyeenzo/sentinel-net/actions/workflows/release.yml/badge.svg" alt="Build &amp; Package Multi-OS Executables" /></a>
  <a href="https://github.com/abiyeenzo/sentinel-net/releases/latest"><img src="https://img.shields.io/github/v/release/abiyeenzo/sentinel-net?label=Release" alt="Latest Release" /></a>
</p>

Scanner d'audit reseau defensif autonome ecrit en **Go** (bibliotheque standard uniquement, aucune dependance externe, aucun runtime a installer). Il combine une **interface graphique de bureau inspiree de Zenmap** et une **ligne de commande directe inspiree de Nmap**, sur **Windows**, **macOS** et **Linux**.

> **Usage responsable :** Sentinel Net emet du trafic TCP actif vers les cibles indiquees. Utilisez-le uniquement sur des equipements et reseaux dont vous avez la responsabilite ou une autorisation ecrite explicite (`-y` ou `--authorized`).

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

1. **Application native macOS (`Sentinel-Net-macOS-universal.dmg`)** : glissez `Sentinel Net.app` dans `Applications` et ouvrez-la comme n'importe quelle application macOS (fenetre Cocoa `WKWebView` universelle `arm64` + `x86_64`).
2. **Installation CLI en une ligne** :

```bash
curl -fsSL https://raw.githubusercontent.com/abiyeenzo/sentinel-net/main/scripts/install.sh | sh
```

### Linux (Debian / Ubuntu / Kali & binaires statiques)

1. **Paquet bureau & CLI `.deb` (`sentinel-net_1.1.0_amd64.deb` ou `arm64.deb`)** :

```bash
sudo apt install ./sentinel-net_1.1.0_amd64.deb
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

L'interface graphique regroupe :
- **Barre de commande synchronisee** : choix de la cible, du profil (`Scan rapide (-F)`, `Audit complet (-A)`, `Web`, `Bases de donnees`, `Infrastructure`, `IoT`), de la cadence (`-T1` a `-T5`) et apercu modifiable de la commande exacte.
- **Arbre lateral Hotes / Services / Interfaces** : filtrage en un clic par machine decouverte, par service ouvert ou selection directe de vos sous-reseaux locaux `/24`.
- **Cinq vues complementaires** : **Sortie Nmap**, **Ports / Hotes**, **Topologie** (carte radiale interactive SVG), **Risques & Details** (score `/100`, certificats TLS X.509, en-tetes HTTP, comparaison baseline) et **Guide CLI**.

---

## Commandes simples en terminal (style Nmap)

Consultez le **[Guide complet des commandes (`docs/CLI.md`)](docs/CLI.md)** pour toutes les options et equivalences Nmap.

```bash
# Scan standard des 95 ports courants sur un hote
sentinel-net 192.168.1.1 -y

# Scan rapide des 18 ports critiques (-F)
sentinel-net -F 192.168.1.1 -y

# Scanner un sous-reseau /24 rapidement (-T4) et n'afficher que les ports ouverts (--open)
sentinel-net -F -T4 --open 192.168.1.0/24 -y

# Detection des services et bannieres sur des ports precis (-sV -p)
sentinel-net -sV -p 22,80,443,3306,5432 10.0.0.5 -y

# Audit complet tout-en-un : banniere + certificat TLS X.509 + en-tetes HTTP (-A)
sentinel-net -A 10.0.0.5 -y

# Profil metier cible (quick, web, database, infra, containers, iot, top100)
sentinel-net -P database -sV 10.0.0.1-30 -y

# Generer tous les formats d'un coup : .txt (Nmap), .json, .html et .sarif (-oA)
sentinel-net -A 192.168.1.10 -oA rapport-audit -y

# Enregistrer une baseline signee SHA-256 puis controler toute derive d'ouverture
sentinel-net -F 10.0.0.5 --save-baseline base.json -y
sentinel-net -F 10.0.0.5 --compare base.json --fail-on-drift -y
```

### Raccourcis essentiels

| Option | Role |
|---|---|
| `-y`, `--authorized` | Confirme l'autorisation explicite d'auditer la cible (obligatoire) |
| `-F` | Scan rapide (`quick`, 18 ports critiques) |
| `-p <spec>` / `-p-` | Ports ou plages (`-p 22,80,8000-8050`) ou plage `1-4096` (`-p-`) |
| `--top-ports <N>` | Scanne les `N` ports les plus courants (`1` a `95`) |
| `-P <profil>` | Profil metier (`web`, `database`, `infra`, `containers`, `iot`, `top100`) |
| `-sV` | Lecture passive de banniere et detection de version |
| `-sC` | Verification non-intrusive TLS X.509 + en-tetes de securite HTTP |
| `-A` | Audit complet (`-sV` + TLS + HTTP) |
| `-T1` .. `-T5` | Cadence d'execution (`-T1` prudent a `-T5` local tres rapide) |
| `-iL <fichier>` | Charge une liste de cibles depuis un fichier texte |
| `-R` / `-n` | Active (`-R`) ou desactive (`-n`) la resolution DNS |
| `--open` | Affiche uniquement les ports `open` |
| `--nmap` | Affiche la sortie console au format texte Nmap |
| `-oN` / `-oJ` / `-oH` / `-oS` | Sauvegarde en texte Nmap, JSON, HTML autonome ou SARIF |
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

- [Guide complet CLI & Interface Graphique (style Nmap/Zenmap)](docs/CLI.md)
- [Architecture technique](docs/ARCHITECTURE.md)
- [Positionnement produit](docs/PRODUCT.md)
- [Politique de securite](docs/SECURITY.md)

## Licence

MIT
