# Sécurité et limites

## Modèle d'utilisation

Outil pour opérateurs autorisés et environnements de laboratoire. L'utilisateur doit posséder ou être explicitement autorisé à tester chaque cible. Le drapeau CLI `--authorized` rend cette déclaration explicite ; il ne vérifie pas juridiquement les droits et ne constitue pas un mécanisme d'authentification.

## Contrôles présents

- IP littérale obligatoire : hostname, CIDR et plages rejetés.
- 1–32 ports uniques explicitement fournis.
- Concurrence limitée à 8 et timeout borné à 5 s.
- Annulation SIGINT via AbortController.
- Aucun scan automatique, UDP, bannière, exploit, commande shell, collecte d'identifiants ou écriture distante.
- Résultats non concluants qualifiés `unknown`.

## Risques et limites connus

Un scan produit du trafic réseau et peut être bloqué, journalisé ou affecter un service fragile. `unknown` ne distingue pas le filtrage d'une cible inaccessible. La limite de cible unique et du nombre de ports réduit l'ampleur mais ne prévient pas toute utilisation non autorisée. L'implémentation doit encore faire l'objet d'une revue indépendante, de CI et d'essais sur versions Node prises en charge. Aucun audit professionnel n'est affirmé.

## Données

Aucune persistance ou télémétrie. La sortie JSON inclut cible, date et observations ; l'opérateur est responsable du stockage qu'il choisit. Ne pas y ajouter de secrets.