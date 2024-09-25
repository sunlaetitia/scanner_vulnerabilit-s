import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys
import json
import argparse

def obtenir_formulaires(url):
    """Récupère tous les formulaires d'une page Web."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des formulaires : {e}")
        return []

def obtenir_details_formulaire(formulaire):
    """Récupère les détails d'un formulaire (action, méthode, champs)."""
    details = {}
    action = formulaire.attrs.get("action", "")
    method = formulaire.attrs.get("method", "get").lower()
    champs = []
    for champ in formulaire.find_all("input"):
        type_champ = champ.attrs.get("type", "text")
        nom_champ = champ.attrs.get("name")
        champs.append({"type": type_champ, "name": nom_champ, "value": ""})
    details["action"] = action
    details["method"] = method
    details["champs"] = champs
    return details

def soumettre_formulaire(details_formulaire, url, donnees):
    """Soumet un formulaire avec les données spécifiées."""
    url_cible = urljoin(url, details_formulaire["action"])
    try:
        if details_formulaire["method"] == "post":
            return requests.post(url_cible, data=donnees, timeout=10)
        else:
            return requests.get(url_cible, params=donnees, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la soumission du formulaire : {e}")
        return None

def scanner_injection_sql(url):
    """Scanner pour détecter les vulnérabilités d'injection SQL."""
    formulaires = obtenir_formulaires(url)
    if not formulaires:
        return []
    print(f"[+] {len(formulaires)} formulaires détectés sur {url}.")
    payloads = ["' OR '1'='1", '" OR "1"="1', "' OR '1'='1' --", '" OR "1"="1" --']
    vulnerabilites = []
    for formulaire in formulaires:
        details_formulaire = obtenir_details_formulaire(formulaire)
        for payload in payloads:
            donnees = {}
            for champ in details_formulaire["champs"]:
                if champ["type"] == "hidden" or champ["name"] is None:
                    continue
                champ["value"] = payload
                donnees[champ["name"]] = champ["value"]
            res = soumettre_formulaire(details_formulaire, url, donnees)
            if res and ("syntax" in res.text.lower() or "error" in res.text.lower()):
                print(f"[!] Vulnérabilité d'injection SQL détectée avec le payload '{payload}' sur {url}")
                print(f"[*] Détails du formulaire :")
                print(details_formulaire)
                vulnerabilites.append("Injection SQL")
                break
    return vulnerabilites

def scanner_xss(url):
    """Scanner pour détecter les vulnérabilités XSS."""
    formulaires = obtenir_formulaires(url)
    if not formulaires:
        return []
    print(f"[+] {len(formulaires)} formulaires détectés sur {url}.")
    script_js = "<script>alert('XSS')</script>"
    vulnerabilites = []
    for formulaire in formulaires:
        details_formulaire = obtenir_details_formulaire(formulaire)
        donnees = {}
        for champ in details_formulaire["champs"]:
            if champ["type"] == "hidden" or champ["name"] is None:
                continue
            champ["value"] = script_js
            donnees[champ["name"]] = champ["value"]
        contenu = soumettre_formulaire(details_formulaire, url, donnees)
        if contenu and script_js in contenu.text:
            print(f"[!] Vulnérabilité XSS détectée sur {url}")
            print(f"[*] Détails du formulaire :")
            print(details_formulaire)
            vulnerabilites.append("XSS")
            break
    return vulnerabilites

def detecter_protection_csrf(url):
    """Détecte les protections CSRF sur les formulaires."""
    formulaires = obtenir_formulaires(url)
    if not formulaires:
        return []
    print(f"[+] {len(formulaires)} formulaires détectés sur {url}.")
    vulnerabilites = []
    for formulaire in formulaires:
        details_formulaire = obtenir_details_formulaire(formulaire)
        a_token_csrf = any(champ["name"] in ["csrf_token", "token", "xsrf_token"] for champ in details_formulaire["champs"])
        if not a_token_csrf:
            print(f"[!] Vulnérabilité CSRF détectée sur {url}")
            print(f"[*] Détails du formulaire :")
            print(details_formulaire)
            vulnerabilites.append("CSRF")
    return vulnerabilites

def scanner_redirection_ouverte(url):
    """Scanner pour détecter les vulnérabilités de redirection ouverte."""
    payloads = ["http://evil.com", "https://evil.com"]
    vulnerabilites = []

    for payload in payloads:
        response = requests.get(f"{url}?redirect={payload}", allow_redirects=False)
        if response.status_code == 302 and "evil.com" in response.headers.get("Location", ""):
            print(f"[!] Vulnérabilité de redirection ouverte détectée sur {url} avec le payload {payload}")
            vulnerabilites.append("Redirection Ouverte")
    
    return vulnerabilites

def verifier_en_tetes_http(url):
    """Vérifie les en-têtes HTTP pour les configurations de sécurité."""
    try:
        response = requests.get(url, timeout=10)
        en_tetes = response.headers
        problèmes = []

        if 'Content-Security-Policy' not in en_tetes:
            problèmes.append("Politique de sécurité de contenu (CSP) manquante.")

        if 'Strict-Transport-Security' not in en_tetes:
            problèmes.append("Sécurité stricte de transport HTTP (HSTS) manquante.")

        return problèmes
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la vérification des en-têtes HTTP : {e}")
        return []

def obtenir_info_cve(cve_id):
    """Récupère les informations CVE pour un identifiant donné."""
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        score_cvss = data.get("cvss", "Score CVSS non disponible")
        return score_cvss
    except requests.exceptions.RequestException as e:
        print(f"Erreur HTTP : {e}")
    except Exception as e:
        print(f"Une erreur est survenue : {e}")
    return "Erreur lors de la récupération du score CVSS"

def sauvegarder_resultats(vulnerabilites, nom_fichier="resultats.json"):
    """Sauvegarde les résultats du scan dans un fichier JSON."""
    with open(nom_fichier, "w") as fichier:
        json.dump(vulnerabilites, fichier, indent=4)
    print(f"[+] Résultats sauvegardés dans {nom_fichier}")

def analyser_arguments():
    """Analyse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(description="Scanner de vulnérabilités Web")
    parser.add_argument("url", help="URL du site cible")
    parser.add_argument("--login", help="URL de connexion pour l'authentification")
    parser.add_argument("--data", help="Données de connexion au format JSON")
    return parser.parse_args()

def main(url):
    print(f"Analyse de l'URL : {url}")
    vulnerabilites = []
    vulnerabilites.extend(scanner_injection_sql(url))
    vulnerabilites.extend(scanner_xss(url))
    vulnerabilites.extend(detecter_protection_csrf(url))
    vulnerabilites.extend(scanner_redirection_ouverte(url))
    
    # Vérification des en-têtes HTTP
    problèmes_en_tetes = verifier_en_tetes_http(url)
    if problèmes_en_tetes:
        for problème in problèmes_en_tetes:
            print(f"[!] Problème détecté dans les en-têtes HTTP : {problème}")

    # Association des vulnérabilités à des ID CVE
    mapping_cve = {
        "Injection SQL": "CVE-2021-22986",
        "XSS": "CVE-2020-0601",
        "CSRF": "CVE-2019-0708",  # Exemple d'ID CVE pour CSRF
        "Redirection Ouverte": "CVE-2021-22987"  # Exemple d'ID CVE pour redirection ouverte
    }

    # Récupération et affichage des scores CVSS pour les vulnérabilités détectées
    for vuln in set(vulnerabilites):
        cve_id = mapping_cve.get(vuln)
        if cve_id:
            print(f"Récupération des informations CVE pour {cve_id}...")
            info_cve = obtenir_info_cve(cve_id)
            print(f"Score CVSS pour {cve_id} : {info_cve}")

    # Sauvegarder les résultats dans un fichier JSON
    sauvegarder_resultats(vulnerabilites)

if __name__ == "__main__":
    args = analyser_arguments()
    url = args.url
    main(url)

