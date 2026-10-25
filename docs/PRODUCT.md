# Vision Produit - Sentinel Net

## Objectif

Fournir aux administrateurs systemes et equipes securite un binaire d'audit reseau leger, rapide, lisible et simple a faire evoluer, capable de tourner aussi bien dans un terminal, dans un pipeline CI/CD que via une console Web locale embarquee.

## Choix techniques structurants

1. **Go standard pur (`CGO_ENABLED=0`)** : compilation en une seconde vers un executable statique unique d'environ 8 Mo (`sentinel-net.exe` sous Windows, `sentinel-net` sous Linux/macOS), sans dependances externes a maintenir ni surface d'attaque logicielle tierce.
2. **Explicabilite des constats** : chaque regle du moteur `internal/risk` cite la preuve reseau observee, documente les cas de faux positifs courants et indique la mesure de durcissement associee.
3. **Fonctionnement hors-ligne** : aucun appel vers un service distant, aucune telemetrie, rapports HTML et console Web autonomes sans CDN externe.

## Note juridique sur le nom

Sentinel Net designe ce depot logiciel et son binaire. Aucune verification d'anteriorite de marque commerciale ou de nom de domaine n'a ete realisee ; une validation juridique reste requise avant toute distribution commerciale sous ce nom.
