from django.urls import path
from . import views

urlpatterns = [
    path('', views.accueil, name='accueil'),
    path('upload/', views.upload_fichier, name='upload'),
]
