Ce projet est un laboratoire pédagogique local sur la réutilisation du nonce dans ECDSA, illustrée par l’incident de signature de la PlayStation 3.

## Lancer le laboratoire

Le laboratoire est une page statique et ne nécessite aucune dépendance à installer.

1. Ouvrir un terminal dans le dossier du projet.
2. Démarrer un serveur local avec Python :

   ```powershell
   py -m http.server 8000
   ```

3. Ouvrir <http://localhost:8000> dans un navigateur moderne.
4. Cliquer sur **Simuler le nonce réutilisé** pour générer deux signatures de messages différents avec un nonce commun. Le laboratoire récupère la clé de démonstration, puis vérifie une signature forgée.
5. Cliquer sur **Comparer avec RFC 6979** pour vérifier les signatures déterministes et comparer les nonces dérivés pour les deux messages. Les deux démonstrations utilisent la même clé temporaire pour rendre la comparaison directe.
6. Cliquer sur **Nouvelle clé de démonstration** pour remplacer la clé temporaire.
7. Arrêter le serveur avec `Ctrl+C`.

Le laboratoire n’envoie aucune donnée à un service externe et ne conserve rien après la fermeture de la page. La clé est générée aléatoirement dans le navigateur et reste limitée à la démonstration. Ne collez aucune clé, signature ou donnée réelle dans cette page.

## Portée pédagogique

Le scénario vulnérable est une démonstration contrôlée du mécanisme ECDSA associé à l’incident PlayStation 3 : la réutilisation d’un nonce pour des messages distincts permet de retrouver la clé privée à partir des signatures. L’implémentation utilise P-256 pour garder un exemple reproductible et ne prétend pas reproduire la courbe, le firmware ou le protocole exacts de Sony.

La version corrigée utilise la dérivation déterministe HMAC-SHA-256 définie par [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979). Pour la même clé et le même message, le nonce et la signature sont identiques par conception. Pour deux messages distincts, les nonces dérivés sont différents dans la démonstration.

Le code JavaScript d’arithmétique de courbe et de signature est volontairement visible à des fins pédagogiques; il n’est pas audité, durci contre les attaques par canal auxiliaire, ni destiné à protéger de vraies clés. En production, utilisez une bibliothèque cryptographique maintenue plutôt qu’une implémentation maison. Si une clé réelle a pu être exposée par réutilisation ou fuite de nonce, remplacez-la et révoquez les signatures ou identifiants concernés : ajouter RFC 6979 ne répare pas rétroactivement une clé compromise.