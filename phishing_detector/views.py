from django.shortcuts import render


def index(request):
    return render(request, "index.html")

def about(request):
    return render(request, "about.html")
    
def contact(request):
    return render(request, "contact.html")
    
def projectDetails(request):
    return render(request, "projectDetails.html")
    
def teamDetails(request):
    return render(request, "teamDetails.html")
    
def team(request):
    return render(request, "team.html")

def feature(request):
    return render(request, "feature.html")
    

