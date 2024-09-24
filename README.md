# scanner_vulnerabilites
# Scanner de Vulnérabilités Web

Ce projet est un scanner de vulnérabilités Web capable de détecter des problèmes de sécurité courants tels que les vulnérabilités SQLi, XSS, et CSRF.

## Comment Installer et Utiliser le Projet

### Étapes pour cloner le projet

1. **Clonez le dépôt** :
   Ouvrez votre terminal et exécutez la commande suivante :

   ```bash
   git clone https://github.com/sunlaetitia/scanner_vulnerabilites.git
   
2. **Naviguez dans le dossier du projet** : 
 ```bash
 cd scanner_vulnerabilites

3. **Installez les dépendances** :
 Assurez-vous d'avoir requests et BeautifulSoup installés. Vous pouvez le faire en exécutant :
 ```bash
 pip install requests beautifulsoup4

4. **Exécutez le scanner** :
Pour lancer le scanner, utilisez la commande :
 ```bash
 python3 scanner_vulnerabilites.py <url>
Remplacez <url> par l'URL que vous souhaitez analyser.
