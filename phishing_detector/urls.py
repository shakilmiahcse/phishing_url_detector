
from django.contrib import admin
from django.urls import path
from phishing_detector import views

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', views.index), 
    path('index', views.index),
    path('about', views.about),
    path('contact', views.contact),
    path('project-details', views.projectDetails),
    path('team-details', views.teamDetails),
    path('team', views.team),
    path('feature', views.feature),
]
