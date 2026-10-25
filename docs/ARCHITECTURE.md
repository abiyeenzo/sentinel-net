# Architecture - Sentinel Net

## Organisation modulaire

Sentinel Net suit l'architecture standard des projets Go systeme : un point d'entree minimal dans `cmd/sentinel-net` et des packages isoles sous `internal/`, sans aucune dependance tierce dans `go.mod`.

- `internal/netscope` : validation stricte d'adresses via `net/netip`, qualification de portee (`loopback`, `private`, `link-local`, `carrier-nat`, `documentation`, `public`), developpement borne des CIDR IPv4 (`/22` a `/32`) et plages IPv4, resolution DNS optionnelle et inventaire des interfaces locales.
- `internal/profiles` : catalogue immuable des 7 profils de ports (`quick`, `web`, `infra`, `database`, `containers`, `iot`, `top100`).
- `internal/scanner` : pool concurrent de goroutines pilote par `context.Context`. Supporte l'injection d'une fonction `DialFunc` pour tester de maniere deterministe les timeouts et l'annulation de sondes actives sans dependre de la pile noyau locale.
- `internal/inspector` et `internal/services` : lecture passive de banniere TCP (avec fermeture immediate du socket sur annulation du contexte), inspection TLS X.509 et verification des en-tetes HTTP via `HEAD /`.
- `internal/risk` : moteur de regles sans etat calculant les constats `SN-*` et le score `0-100`.
- `internal/baseline` : empreinte canonique `SHA-256` et calcul d'ecarts entre deux scans.
- `internal/report` : formatage de sortie (`table`, `json`, `sarif`, `markdown`, `csv`, `html`).
- `internal/web` : serveur HTTP local embarquant `static/index.html` via `//go:embed` et diffusant l'avancement des scans en flux `application/x-ndjson`.

## Semantique des etats TCP

- `open` (`reason: "tcp-connect"`) : le handshake TCP a abouti.
- `closed` (`reason: "ECONNREFUSED"`) : l'hote a repondu par un segment TCP `RST` explicite (gere de maniere portable sous Linux, macOS et Windows `WSAECONNREFUSED`).
- `unknown` (`reason: "timeout"` ou code d'erreur reseau) : aucune reponse recue dans le delai configure. Un paquet ignore par un pare-feu n'est jamais declare `closed`.

## Annulation et arret propre

Toutes les operations bloquantes (`DialContext`, pauses entre sondes, lecture de banniere, handshake TLS, requete HTTP) sont rattachees au `context.Context` racine relie a `SIGINT` / `SIGTERM` (ou au bouton d'annulation de l'API Web). Lorsqu'une annulation survient, les sockets ouverts sont fermes immediatement et le moteur retourne `scanner.ErrCancelled`.
