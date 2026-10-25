# Sentinel Net

[![CI](https://github.com/abiyeenzo/sentinel-net/actions/workflows/test.yml/badge.svg)](https://github.com/abiyeenzo/sentinel-net/actions/workflows/test.yml)
[![Build Windows EXE](https://github.com/abiyeenzo/sentinel-net/actions/workflows/build-windows.yml/badge.svg)](https://github.com/abiyeenzo/sentinel-net/actions/workflows/build-windows.yml)

Scanner d'audit reseau defensif ecrit en **Go** (bibliotheque standard uniquement, aucune dependance externe). Il permet d'inventorier l'exposition TCP/TLS/HTTP d'un perimetre autorise, d'evaluer le risque selon des regles deterministes et de suivre les derives d'ouverture dans le temps.

> **Usage responsable :** Sentinel Net emet du trafic TCP actif vers les cibles indiquees. Utilisez-le uniquement sur des equipements et reseaux dont vous avez la responsabilite ou une autorisation ecrite explicite (`--authorized`).

## Capacites principales

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
- **Rapports et console Web (`internal/report`, `internal/web`)** :
  - Formats `table`, `json`, `sarif` (SARIF 2.1.0), `markdown`, `csv` et `html` autonome.
  - Console Web locale embarquee dans le binaire via `go:embed` (`sentinel-net serve --port 3000`).

## Utilisation rapide

### Compilation depuis les sources

Requiert Go 1.24 ou plus recent :

```bash
go test -race ./...
go build -trimpath -ldflags="-s -w" -o dist/sentinel-net ./cmd/sentinel-net
```

Cross-compilation de l'executable Windows `sentinel-net.exe` depuis Linux, macOS ou Windows :

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/sentinel-net.exe ./cmd/sentinel-net
```

### Exemples CLI

```bash
# Lister les interfaces reseau locales
./dist/sentinel-net interfaces

# Audit rapide avec inspection banniere + TLS + HTTP
./dist/sentinel-net scan --target 127.0.0.1 --profile quick --inspect --authorized

# Audit d'un sous-reseau /24 avec rapport HTML autonome et export SARIF
./dist/sentinel-net scan -t 192.168.1.0/24 --profile infra --tls --http --authorized \
  --report-html audit.html --format sarif -o findings.sarif

# Enregistrer une baseline puis verifier l'absence de derive
./dist/sentinel-net scan -t 127.0.0.1 -p 22,80,443 --authorized --save-baseline base.json
./dist/sentinel-net scan -t 127.0.0.1 -p 22,80,443 --authorized --compare base.json --fail-on-drift

# Lancer la console Web locale
./dist/sentinel-net serve --port 3000
```

## Build automatise Windows (.exe)

Le workflow `.github/workflows/build-windows.yml` compile `dist/sentinel-net.exe` en natif statique (`CGO_ENABLED=0`, ~8 Mo, sans DLL ni runtime externe) sur `windows-latest`, execute des tests fonctionnels PowerShell sur le binaire produit, genere l'archive `sentinel-net-win-x64.zip` ainsi que `SHA256SUMS.txt`, et publie automatiquement une GitHub Release lors du push d'un tag `v*`.

## Codes de sortie

| Code | Signification |
|---|---|
| `0` | Execution terminee sans erreur ni violation de politique |
| `2` | Parametres invalides ou absence du drapeau `--authorized` |
| `3` | Violation d'un seuil CI (`--fail-on-drift` ou `--fail-on-severity`) |
| `130` | Annulation par signal (`SIGINT` / `SIGTERM`) |

## Structure du code

```text
cmd/sentinel-net/main.go        Point d'entree binaire
internal/
  cli/                          Parsing des options et sous-commandes CLI
  netscope/                     Validation IPv4/IPv6, CIDR, plages, DNS opt-in, interfaces
  profiles/                     Profils de ports predefinis
  services/                     Catalogue de services TCP et nettoyage ANSI des bannieres
  scanner/                      Pool de workers TCP, statistiques RTT et annulation context
  inspector/                    Sondes passives banniere, TLS X.509 et en-tetes HTTP
  risk/                         Regles deterministes SN-* et calcul du score de posture
  baseline/                     Integrite SHA-256 et comparaison de derive
  report/                       Generateurs table, json, sarif, markdown, csv et html
  web/                          Serveur HTTP local et interface embarquee (go:embed)
```

Voir `docs/ARCHITECTURE.md`, `docs/PRODUCT.md` et `docs/SECURITY.md` pour le detail des contrats techniques et limites operationnelles.
