# Playbook — SSH brute force suivi de connexion réussie

Déclencheurs : nombreux échecs d'authentification sshd (rule 5710) depuis une
même IP source, suivis d'un succès (rule 5715) et d'une élévation sudo.

Réponse recommandée :
- Bloquer l'IP source au pare-feu / fail2ban et révoquer la session active.
- Forcer la réinitialisation du mot de passe du compte visé, désactiver
  l'authentification par mot de passe au profit des clés.
- Vérifier les commandes exécutées après le succès (historique shell, auditd).
Gravité typique : élevée dès qu'un succès suit la rafale d'échecs.
