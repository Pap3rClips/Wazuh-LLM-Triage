# Playbook — Effacement de traces et contournement des défenses

Déclencheurs : effacement du journal d'événements (wevtutil cl), auditpol
désactivé, protection temps réel Defender coupée, règles pare-feu supprimées,
timestomping.

Réponse recommandée :
- Traiter comme un attaquant actif cherchant à masquer sa présence : isoler.
- Restaurer la journalisation depuis une source centralisée (les logs locaux
  sont suspects), s'appuyer sur le SIEM pour la timeline.
- Rechercher l'activité que l'effacement visait à cacher.
Gravité : élevée ; l'effacement de logs n'abaisse jamais la gravité.
