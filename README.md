# Sentinel Net

Scanner réseau défensif minimal pour les équipements que vous êtes autorisé à analyser. Ce dépôt constitue un socle fonctionnel et documenté, pas un produit enterprise certifié.

## Première tranche

- Validation stricte d'une adresse IPv4 ou IPv6 unique (pas de CIDR ni plage).
- Scan TCP avec ports explicitement fournis, délai d'attente, concurrence bornée et annulation.
- Résultats limités à `open` ou `unreachable/unknown` : un timeout ne prouve pas qu'un port est fermé.
- Aucun scan automatique, aucune exploitation, collecte de bannière, commande système ou persistance sur la cible.
- Une confirmation explicite d'autorisation est obligatoire.

Le scanner peut générer du trafic vers la cible. Utilisez-le uniquement dans un environnement dont vous êtes responsable ou pour lequel vous avez une autorisation explicite.

## Prérequis et lancement

Node.js 20 ou plus récent, sans dépendance externe.

```sh
node src/cli.js --target 127.0.0.1 --ports 22,80,443 --authorized
npm test
```

L'exemple loopback est destiné aux tests locaux. Par défaut, la cible et les ports doivent être indiqués explicitement. Limites : 1 à 32 ports, 1 à 8 connexions simultanées, timeout 100 à 5000 ms.

## Architecture

- `src/target.js` : validation de la cible et des ports.
- `src/scanner.js` : moteur asynchrone, bornes et annulation.
- `src/cli.js` : interface CLI, confirmation d'autorisation et JSON en sortie.
- `test/` : tests unitaires et tests réseau loopback sans dépendances.

## Roadmap / backlog

| ID | Lot | Responsable de mission | Statut | Critère de sortie |
|---|---|---|---|---|
| GOV-001 | Vision, limites et décisions d'architecture | Orchestration | INTEGRATED | Ce document et `docs/` publiés |
| NET-001 | Validation des cibles et ports | Réseau | TESTED | Entrées invalides rejetées par tests |
| NET-002 | Scan TCP limité + annulation | Réseau | TESTED | Tests loopback et bornes passent |
| QA-001 | Audit indépendant | Gate qualité | BLOCKED | Revue humaine indépendante et CI nécessaires |
| NET-003 | Interfaces locales et CIDR borné | Réseau/Sécurité | BACKLOG | Contrat et limites définis avant implémentation |
| DATA-001 | Inventaire persistant / comparaison | Plateforme | BACKLOG | Modèle, confidentialité et tests définis |
| UI-001 | Interface de résultats | Produit | BACKLOG | Après stabilisation du contrat moteur |
| RISK-001 | Règles déterministes explicables | Sécurité | BACKLOG | Preuves, confiance et faux positifs documentés |

Statuts possibles : BACKLOG, READY, IN_PROGRESS, BLOCKED, IMPLEMENTED, TESTED, IN_REVIEW, REJECTED, APPROVED, INTEGRATED. Les statuts TESTED ci-dessus sont des résultats de tests automatisés ajoutés, mais ils n'ont pas été exécutés dans cet environnement. Aucun auditeur indépendant n'a été mobilisé : ces éléments ne sont donc pas APPROVED.

## Organisation et qualité

Ce dépôt est développé ici sans sous-agents autonomes ni exécution locale de code. Les rôles de réseau, sécurité, plateforme et QA dans le backlog désignent des responsabilités de mission, pas des agents réellement mobilisés. La CI exécute les tests Node.js ; une revue humaine indépendante reste requise avant toute affirmation de validation sécurité.

Consulter `docs/PRODUCT.md`, `docs/ARCHITECTURE.md` et `docs/SECURITY.md` pour la vision, les contrats et les limites.