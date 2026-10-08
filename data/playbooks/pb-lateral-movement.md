# Playbook — Mouvement latéral (PsExec, SMB, WMI, pass-the-hash)

Déclencheurs : service PSEXESVC, écritures SMB sur ADMIN$, création de
processus WMI distant, logon type 9 (pass-the-hash), nouveau compte admin.

Réponse recommandée :
- Cartographier les hôtes atteints, isoler la source et les cibles.
- Révoquer les comptes utilisés, rechercher la compromission d'identifiants
  en amont.
- Bloquer SMB/WMI latéral là où ce n'est pas nécessaire.
Gravité : élevée.
