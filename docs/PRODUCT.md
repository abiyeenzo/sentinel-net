# Vision produit — Sentinel Net

## Décision de nom

**Sentinel Net** est le nom retenu pour ce nouveau dépôt. Il décrit le rôle défensif et réseau du produit et est cohérent avec l'identifiant npm interne `sentinel-net`. Il n'est pas présenté comme une marque disponible : aucune recherche externe de marques, domaines ou collisions exhaustives n'a été effectuée. Vérification juridique et disponibilité des domaines restent à faire avant distribution commerciale.

## Vision et périmètre initial

Outil local d'inventaire réseau destiné aux administrateurs autorisés. Le produit privilégie les observations explicables, les cibles explicitement saisies, les limites bornées et les résultats assortis de leur état/incertitude.

La première tranche fournit uniquement une tentative de connexion TCP vers une adresse IP littérale et au plus 32 ports choisis explicitement. Elle ne découvre pas automatiquement le réseau, n'utilise pas l'IA, ne déduit pas des vulnérabilités et n'exécute aucune exploitation.

## Principes

1. Autorisation explicite et portée visible.
2. Une observation n'est jamais une certitude au-delà de sa preuve.
3. Pas de données fictives dans les résultats.
4. Défauts de sécurité fermés, limites explicites.
5. Architecture simple avant stockage, UI ou fonctions avancées.

## Jalons

Voir la roadmap du README. Le lot initial ne satisfait pas l'ambition enterprise : tests dans CI, revue indépendante, audit de sécurité, UX, stockage et packaging restent à accomplir.