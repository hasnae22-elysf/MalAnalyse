# MalAnalyse
# test
#  MalAnalyse - Plateforme d'analyse de fichiers malveillants

**MalAnalyse** est une plateforme web développée avec **Django** permettant l’analyse automatisée de fichiers potentiellement malveillants à l’aide de deux techniques complémentaires :

- **Analyse dynamique** via [CAPEv2](https://github.com/ctxis/CAPE), un fork spécialisé de Cuckoo Sandbox.
- **Analyse statique multi-antivirus** via l’API publique de [VirusTotal](https://www.virustotal.com/).

---

##  Fonctionnalités

- Interface web intuitive pour téléverser un fichier suspect.
- Soumission automatique du fichier à :
  - **CAPEv2** : pour observer le comportement du fichier dans une machine virtuelle Windows isolée.
  - **VirusTotal** : pour obtenir un score statique basé sur plusieurs moteurs antivirus.
- Génération de rapports détaillés pour chaque méthode.
- Affichage clair et parallèle des deux rapports (statique et dynamique).
- Téléchargement des rapports bruts.
- Intégration de KVM/QEMU pour lancer les analyses dans une VM Windows sécurisée.

---

##  Technologies utilisées

- **Python 3**
- **Django 4**
- **CAPEv2**
- **VirusTotal API**
- **KVM/QEMU + libvirt**
- HTML/CSS (dark mode), **Inter font** via Google Fonts

---


---

## Pré-requis

- Python 3.9+
- Django
- CAPEv2 installé et fonctionnel sur la machine hôte (avec accès à la VM)
- Accès à une machine virtuelle Windows configurée pour CAPEv2
- Clé API valide pour VirusTotal

---

## Installation

1. Cloner le dépôt :
   ```bash
   git clone https://github.com/hasnae22-elysf/MalAnalyse.git

