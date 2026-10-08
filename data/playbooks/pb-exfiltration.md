# Playbook — Exfiltration de données (tunnel DNS, gros flux sortant)

Déclencheurs : requêtes DNS à forte entropie vers un domaine externe,
transfert sortant volumineux vers une destination rare, archive créée avant
transfert, beaconing régulier.

Réponse recommandée :
- Bloquer la destination, couper le flux, préserver les preuves réseau.
- Déterminer les données parties (archive source) et notifier si besoin RGPD.
- Rechercher le canal C2 et la porte d'entrée initiale.
Gravité : élevée à critique selon la sensibilité des données.
