# Architecture — Sentinel Net 0.1

## Flux

CLI (`src/cli.js`) → validation des arguments (`src/target.js`) → moteur indépendant de l'interface (`src/scanner.js`) → observations JSON sur stdout. Erreurs diagnostiques sur stderr. Aucun sous-processus, service tiers, stockage ni dépendance externe.

## Contrat d'observation TCP

`{ port, state, reason }` : `open` indique qu'une connexion TCP a abouti (`tcp-connect`). `unknown` indique que l'état n'a pas pu être déterminé (timeout ou erreur réseau). Aucun résultat `closed` n'est affirmé, car un échec de connexion ne permet pas toujours de différencier fermeture et filtrage.

## Contrat du moteur

`scanTcp({target, ports, timeoutMs, concurrency, signal})` accepte une IP littérale, 1–32 ports uniques, délai 100–5000 ms, concurrence 1–8 et `AbortSignal`. Rejette les paramètres hors limites avant les connexions. Le CLI fixe des paramètres conservateurs et écoute SIGINT.

## Évolution

Les futurs adaptateurs réseau, stockage, règles de risque et UI devront consommer des observations typées avec horodatage, source et confiance. Toute extension de portée réseau requiert validation et tests dédiés. Aucun engagement de compatibilité stable en version 0.1.