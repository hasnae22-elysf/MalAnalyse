from django.db import models


class FichierMalware(models.Model):
    nom = models.CharField(max_length=255)
    fichier = models.FileField(upload_to='uploads/')
    date_ajout = models.DateTimeField(auto_now_add=True)
    rapport = models.TextField(blank=True, null=True)  # Nouveau champ

    def __str__(self):
        return self.fichier.name
