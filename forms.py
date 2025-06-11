from django import forms
from .models import FichierMalware

class UploadFichierForm(forms.ModelForm):
    class Meta:
        model = FichierMalware
        fields = ['fichier']

class FichierMalwareForm(forms.ModelForm):
    class Meta:
        model = FichierMalware
        fields = ['fichier']  
