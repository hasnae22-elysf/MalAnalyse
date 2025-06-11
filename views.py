from django.shortcuts import render
from .forms import FichierMalwareForm  
import subprocess
import os
from django.conf import settings

def accueil(request):
    return render(request, 'analyseur/accueil.html')

def upload_fichier(request):
    if request.method == 'POST':
        form = FichierMalwareForm(request.POST, request.FILES)
        if form.is_valid():
            malware_obj = form.save()
            chemin_fichier = malware_obj.fichier.path
            chemin_rapport = chemin_fichier + "_rapport.txt"

            chemin_rapport_cape = chemin_rapport.replace(".txt", "_cape.txt")
            chemin_rapport_vt = chemin_rapport.replace(".txt", "_vt.txt")

            rapport_url_cape = None
            rapport_url_vt = None

            try:
                subprocess.run(
                    ['python3', '/home/cape/teste.py', '192.168.122.217', chemin_fichier, chemin_rapport],
                    check=True
                )

                with open(chemin_rapport_cape, 'r') as f1:
                    rapport_cape = f1.read()
                with open(chemin_rapport_vt, 'r') as f2:
                    rapport_virustotal = f2.read()

                # On sauvegarde le rapport complet dans le modèle, 
                malware_obj.rapport = "Analyse CAPE et VT terminée"
                malware_obj.save()

                rapport_url_cape = os.path.join(settings.MEDIA_URL, 'uploads', os.path.basename(chemin_rapport_cape))
                rapport_url_vt = os.path.join(settings.MEDIA_URL, 'uploads', os.path.basename(chemin_rapport_vt))

            except Exception as e:
                rapport_cape = f"Erreur lors de l’analyse : {str(e)}"
                rapport_virustotal = ""

            return render(request, 'analyseur/resultat.html', {
                'chemin': chemin_fichier,
                'rapport_cape': rapport_cape,
                'rapport_virustotal': rapport_virustotal,
                'rapport_url_cape': rapport_url_cape,
                'rapport_url_vt': rapport_url_vt,
            })

    else:
        form = FichierMalwareForm()

    return render(request, 'analyseur/upload.html', {'form': form})
