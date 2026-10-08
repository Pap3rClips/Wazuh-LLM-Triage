# Playbook — Attaque applicative web et web shell

Déclencheurs : injections SQL, path traversal, dépôt de fichier PHP dans un
répertoire d'upload, exécution de commande via web shell (cmd= dans l'URL).

Réponse recommandée :
- Retirer le web shell, mettre le service derrière un WAF, corriger la
  vulnérabilité d'upload/entrée.
- Analyser les logs d'accès pour l'étendue de la compromission.
- Vérifier la persistance et les connexions sortantes depuis le serveur web.
Gravité : critique si exécution de commande confirmée.
