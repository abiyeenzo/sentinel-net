# Securite et Limites - Sentinel Net

## Cadre d'autorisation

L'outil est destine exclusivement aux administrateurs et auditeurs disposant d'une autorisation explicite sur chaque cible.
- En CLI, l'absence du drapeau `--authorized` interrompt l'execution avec le code `2` avant toute ouverture de socket.
- Sur l'API locale `POST /api/scan`, le champ `authorized: true` est exige cote client et verifie cote serveur.

## Garde-fous techniques

- **Perimetre borne** : CIDR IPv4 restreints a `/22`..`/32`, plafond `max-hosts` (256 par defaut, maximum 1024), rejet des adresses multicast, broadcast et non specifiees, resolution DNS desactivee par defaut.
- **Concurrence et delais plafonnes** : `1..128` connexions simultanees, timeout `100..15000 ms`, option `--delay-ms` pour menager les equipements industriels ou anciens.
- **Inspection en lecture seule** : aucune tentative de connexion applicative authentifiee, aucun test d'exploitation, lecture passive limitee a 512 octets sur les bannieres et requete `HEAD /` sur les ports Web.
- **Neutralisation des donnees distantes** : `services.SanitizeText` retire les sequences d'echappement ANSI/CSI (`\x1b...`) et caracteres de controle avant affichage terminal ou journalisation ; tous les champs injectes dans les rapports HTML et la console Web sont echappes.
- **Integrite des baselines** : chaque fichier genere par `--save-baseline` embarque un condensat `SHA-256` verifie au chargement.

## Limites connues

- Tout scan actif laisse des traces dans les journaux systeme et equipements de filtrage.
- En mode `--tls`, le handshake accepte les certificats non reconnus afin d'en extraire les dates d'expiration et l'emetteur, puis execute une verification X.509 explicite contre le magasin systeme pour renseigner `authorized` et signaler les certificats auto-signes ou expires.
