# Playbook — Vol d'identifiants (LSASS / Mimikatz / ntds.dit)

Déclencheurs : accès mémoire à lsass.exe (Sysmon EventID 10, GrantedAccess
0x1010/0x1410), exécution de Mimikatz, copie de ntds.dit, shadow copies.

Réponse recommandée :
- Isoler l'hôte du réseau immédiatement.
- Considérer tous les identifiants du domaine comme compromis : rotation
  des mots de passe, du compte krbtgt (deux fois), des comptes de service.
- Rechercher le mouvement latéral consécutif.
Gravité : critique. Un contrôleur de domaine concerné est une urgence.
