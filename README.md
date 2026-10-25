<p align="center">
  <img src="assets/logo.svg" alt="Logo Sentinel Net" width="128" height="128" />
</p>

<h1 align="center">Sentinel Net</h1>

<p align="center">
  <a href="https://github.com/abiyeenzo/sentinel-net/actions/workflows/test.yml"><img src="https://github.com/abiyeenzo/sentinel-net/actions/workflows/test.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/abiyeenzo/sentinel-net/actions/workflows/release.yml"><img src="https://github.com/abiyeenzo/sentinel-net/actions/workflows/release.yml/badge.svg" alt="Build &amp; Package Multi-OS Executables" /></a>
  <a href="https://github.com/abiyeenzo/sentinel-net/releases/latest"><img src="https://img.shields.io/github/v/release/abiyeenzo/sentinel-net?label=Release" alt="Latest Release" /></a>
</p>

Scanner d'audit reseau defensif autonome ecrit en **Go** (bibliotheque standard uniquement, aucune dependance externe, aucun runtime a installer). Disponible sous forme d'executables natifs et d'installateurs prets a l'emploi pour **Windows**, **macOS** et **Linux**, utilisable aussi bien en interface graphique locale (double-clic ou `sentinel-net gui`) qu'en ligne de commande.

> **Usage responsable :** Sentinel Net emet du trafic TCP actif vers les cibles indiquees. Utilisez-le uniquement sur des equipements et reseaux dont vous avez la responsabilite ou une autorisation ecrite explicite (`--authorized`).

## Telechargement et installation (sans Go ni dependances)

Tous les binaires precompiles et installateurs verifies par empreinte `SHA256SUMS.txt` sont disponibles sur la page **[GitHub Releases](https://github.com/abiyeenzo/sentinel-net/releases/latest)**.

### Windows (x64 & ARM64)

Trois options au choix sans droits administrateur requis :

1. **Installateur graphique Windows (`sentinel-net-setup-windows-amd64.exe`)** : installe l'application avec son icone, cree les raccourcis Bureau / Menu Demarrer et configure automatiquement le `PATH` utilisateur.
2. **Executable portable direct (`sentinel-net-windows-amd64.exe`)** : un seul fichier `.exe` (~7.8 Mo) avec icone integree. Un double-clic dans l'Explorateur Windows demarre directement la console graphique dans le navigateur.
3. **Installation en une ligne PowerShell** :

```powershell
irm https://raw.githubusercontent.com/abiyeenzo/sentinel-net/main/scripts/install.ps1 | iex
```

### macOS (Apple Silicon M1/M2/M3/M4 & Intel)

1. **Image disque macOS (`Sentinel-Net-macOS-universal.dmg`)** : binaire universel (`arm64` + `x86_64`) empaquete dans `Sentinel Net.app`. Ouvrez le `.dmg`, glissez `Sentinel Net.app` dans `Applications` et double-cliquez dessus.
2. **Installation CLI en une ligne (macOS & Linux)** :

```bash
curl -fsSL https://raw.githubusercontent.com/abiyeenzo/sentinel-net/main/scripts/install.sh | sh
```

### Linux (Debian / Ubuntu / Kali & binaires statiques x64 / ARM64)

1. **Paquet natif `.deb` (`sentinel-net_1.0.0_amd64.deb` ou `arm64.deb`)** : ajoute `/usr/bin/sentinel-net`, l'icone vectorielle et le lanceur d'application bureau.

```bash
sudo apt install ./sentinel-net_1.0.0_amd64.deb
```

2. **Installation rapide en une ligne (toutes distributions Linux)** :

```bash
curl -fsSL https://raw.githubusercontent.com/abiyeenzo/sentinel-net/main/scripts/install.sh | sh
```

3. **Binaire statique direct (`sentinel-net-linux-amd64` / `sentinel-net-linux-arm64`)** : `CGO_ENABLED=0`, fonctionne sur n'importe quel noyau Linux (glibc, musl, Alpine, Debian, Fedora, Arch).

## Capacites principales

- **Double mode d'utilisation (GUI + CLI)** : double-cliquez sur l'executable (ou lancez `sentinel-net gui`) pour ouvrir l'interface graphique Web locale, ou appelez `sentinel-net scan` dans un terminal ou pipeline CI/CD.
- **Ciblage borne (`internal/netscope`)** : IPv4, IPv6, blocs CIDR IPv4 (`/22` a `/32`), plages IPv4 (`192.168.1.1-50` ou `10.0.0.1-10.0.0.30`), fichiers de cibles (`--targets-file`), decouverte des interfaces locales (`interfaces`) et resolution DNS optionnelle (`--resolve`).
- **Profils et plages de ports (`internal/profiles`)** : 7 profils integres (`quick`, `web`, `infra`, `database`, `containers`, `iot`, `top100`) et support des plages (`-p 22,80,443,8000-8050`).
- **Moteur TCP concurrent (`internal/scanner`)** : pool de workers borne (`1..128`), mesure RTT en millisecondes (`min`, `avg`, `p95`, `max`), tentatives (`--retries`), delai inter-sondes (`--delay-ms`) et annulation immediate par `context.Context` / `SIGINT`.
- **Qualification fidele des etats** :
  - `open` : connexion TCP etablie (`SYN-ACK`).
  - `closed` : refus explicite (`RST` / `ECONNREFUSED`).
  - `unknown` : delai depasse ou hote injoignable (ne confond jamais un filtrage silencieux avec un port ferme).
- **Inspection non-intrusive (`internal/inspector`, `internal/services`)** :
  - Lecture passive de banniere TCP (512 octets max) avec filtrage des sequences ANSI et caracteres de controle.
  - Audit du handshake TLS et du certificat X.509 (`TLSv1.0` a `TLSv1.3`, CN/SAN, auto-signature, empreinte SHA-256, jours avant expiration).
  - Requete `HEAD /` HTTP/HTTPS controlant `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options` et les en-tetes `Server` / `X-Powered-By`.
- **Evaluation de posture et suivi de derive (`internal/risk`, `internal/baseline`)** :
  - Score `0-100` (note `A+` a `F`) et 15 regles explicables (`SN-CRIT-001` a `SN-INFO-001`) avec preuves et remediations.
  - Snapshots baseline signes `SHA-256` (`--save-baseline`) et comparaison differentielle (`--compare`, `diff`) avec codes de retour CI (`--fail-on-drift`, `--fail-on-severity`).
- **Rapports multi-formats (`internal/report`, `internal/web`)** : `table`, `json`, `sarif` (SARIF 2.1.0), `markdown`, `csv` et `html` autonome.

## Exemples d'utilisation

```bash
# Ouvrir directement l'interface graphique dans le navigateur par defaut
sentinel-net gui

# Lister les interfaces reseau locales
sentinel-net interfaces

# Audit rapide avec inspection banniere + TLS + HTTP
sentinel-net scan --target 127.0.0.1 --profile quick --inspect --authorized

# Audit d'un sous-reseau /24 avec rapport HTML autonome et export SARIF
sentinel-net scan -t 192.168.1.0/24 --profile infra --tls --http --authorized \
  --report-html audit.html --format sarif -o findings.sarif

# Enregistrer une baseline puis verifier l'absence de derive
sentinel-net scan -t 127.0.0.1 -p 22,80,443 --authorized --save-baseline base.json
sentinel-net scan -t 127.0.0.1 -p 22,80,443 --authorized --compare base.json --fail-on-drift
```

## Compilation depuis les sources (optionnel)

Requiert Go 1.24 ou plus recent :

```bash
make test
make build-all
```

Pour regenerer `assets/icon.ico` et les ressources PE Windows `.syso` apres modification de `assets/logo.png` :

```bash
make icons
```

## Codes de sortie

| Code | Signification |
|---|---|
| `0` | Execution terminee sans erreur ni violation de politique |
| `2` | Parametres invalides ou absence du drapeau `--authorized` |
| `3` | Violation d'un seuil CI (`--fail-on-drift` ou `--fail-on-severity`) |
| `130` | Annulation par signal (`SIGINT` / `SIGTERM`) |

## Structure du projet

```text
assets/                         Logos (logo.svg, logo.png) et icone Windows multi-tailles (icon.ico)
cmd/sentinel-net/               Point d'entree Go et ressources PE Windows (.syso)
internal/
  cli/                          Commandes CLI, mode bureau double-clic (gui) et codes retour
  netscope/                     Validation IPv4/IPv6, CIDR, plages, DNS opt-in, interfaces
  profiles/                     Profils de ports predefinis
  services/                     Catalogue de services TCP et nettoyage ANSI des bannieres
  scanner/                      Pool de workers TCP, statistiques RTT et annulation context
  inspector/                    Sondes passives banniere, TLS X.509 et en-tetes HTTP
  risk/                         Regles deterministes SN-* et calcul du score de posture
  baseline/                     Integrite SHA-256 et comparaison de derive
  report/                       Generateurs table, json, sarif, markdown, csv et html
  web/                          Serveur HTTP local et interface embarquee avec logo (go:embed)
packaging/                      Installateur Windows NSIS (.nsi), bundle macOS (.plist), Linux (.desktop)
scripts/                        Scripts d'installation en une ligne (install.sh, install.ps1)
```

## Documentation complementaire

- [Architecture technique](docs/ARCHITECTURE.md)
- [Positionnement produit](docs/PRODUCT.md)
- [Politique de securite](docs/SECURITY.md)

## Licence

MIT
