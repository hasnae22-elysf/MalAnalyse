import sys
import subprocess
import requests
import time
import json
import os
import re

# Entrée : python3 test.py <ip_vm_cape> <chemin_fichier> <chemin_rapport>
ip_vm = "127.0.0.1"
chemin_fichier = sys.argv[2]
chemin_rapport = sys.argv[3]

# Clé API VirusTotal (à personnaliser)
VIRUSTOTAL_API_KEY = "b9180d5c4e6ca3656f8b66ac9c97cdde30ef7494b383f341db413f6c3e940af0"

def lancer_cape():
    try:
        print("[*] Lancement de CAPEv2...")
        subprocess.Popen(["poetry", "run", "python3", "cuckoo.py", "-d"], cwd="/opt/CAPEv2/")
        time.sleep(10)  # Donne le temps à CAPE de démarrer
        print("[+] CAPEv2 lancé avec succès.")
    except Exception as e:
        print(f"[!] Erreur lors du lancement de CAPEv2 : {str(e)}")
        sys.exit(1)

def analyse_cape(fichier):

    try:
        print("[*] Soumission du fichier à CAPEv2 via submit.py...")

        cmd = ["poetry", "run", "python3", "/opt/CAPEv2/utils/submit.py", fichier]
        result = subprocess.run(cmd, cwd="/opt/CAPEv2", capture_output=True, text=True)
        output = result.stdout + result.stderr

        print("===== SORTIE SUBMIT.PY =====")
        print(output)
        print("===== FIN SORTIE =====")

        if result.returncode != 0:
            return f"[!] Erreur CAPEv2 :\n{output}"

        match = re.search(r"task with ID (\d+)", output)
        if not match:
            return "[!] Task ID introuvable dans la sortie CAPEv2."

        task_id = match.group(1)
        print(f"[*] Task ID : {task_id} - Attente de la fin de l'analyse (basée sur report.json)...")

        report_path = f"/opt/CAPEv2/storage/analyses/{task_id}/reports/report.json"

        # Attente tant que report.json n'existe pas ou est vide
        while True:
            if os.path.exists(report_path):
                if os.path.getsize(report_path) > 0:
                    print("[+] Rapport trouvé et non vide.")
                    break
            time.sleep(5)
            print("[*] En attente de report.json...")

        # Lecture du rapport
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                data = json.load(f)
            return json.dumps(data, indent=2)
        else:
            return f"[!] Rapport CAPEv2 introuvable : {report_path}"

    except Exception as e:
        return f"Erreur analyse CAPEv2 : {str(e)}"




def analyse_virustotal(fichier, api_key): 

    try:
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": api_key}
        with open(fichier, 'rb') as f:
            files = {'file': f}
            response = requests.post(url, files=files, headers=headers)
        data = response.json()
        analysis_id = data["data"]["id"]
        time.sleep(90)  # Attente du traitement
        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result = requests.get(result_url, headers=headers)
        return json.dumps(result.json(), indent=2)
    except Exception as e:
        return f"Erreur VirusTotal : {str(e)}"



lancer_cape()

# Lancer les analyses
print("[*] Analyse CAPEv2...")
rapport_cape = analyse_cape(chemin_fichier)

print("[*] Analyse VirusTotal...")
rapport_vt = analyse_virustotal(chemin_fichier, VIRUSTOTAL_API_KEY)

# Fusionner les rapports

# Enregistrer les rapports dans deux fichiers distincts
with open(chemin_rapport.replace(".txt", "_cape.txt"), 'w') as f:
    f.write(rapport_cape)

with open(chemin_rapport.replace(".txt", "_vt.txt"), 'w') as f:
    f.write(rapport_vt)

print(f"[+] Rapport CAPEv2 : {chemin_rapport.replace('.txt', '_cape.txt')}")
print(f"[+] Rapport VirusTotal : {chemin_rapport.replace('.txt', '_vt.txt')}")
