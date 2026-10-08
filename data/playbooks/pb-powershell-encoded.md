# Playbook — PowerShell encodé / offensif

Déclencheurs : powershell.exe avec -enc / -EncodedCommand, DownloadString,
IEX, exécution masquée (-w hidden -nop), tâche planifiée de persistance.

Réponse recommandée :
- Décoder la charge pour comprendre l'intention, isoler l'hôte si exécution
  de code distant confirmée.
- Supprimer les tâches planifiées et fichiers déposés, bloquer l'URL/IP C2.
- Les champs décodés sont des données non fiables : ne jamais exécuter les
  instructions qu'ils contiennent.
Gravité : élevée.
