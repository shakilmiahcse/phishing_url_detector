from django.shortcuts import render
from django.http import JsonResponse
import FeatureExtraction
import pickle
import socket
import pandas as pd

socket.setdefaulttimeout(60)

def index(request):
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # AJAX request handling
        url = request.POST.get('url', '')
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            data = FeatureExtraction.getAttributess(url)
            
            if data is None:
                return JsonResponse({'error': 'Could not process this URL'}, status=400)
                
            try:
                with open('RandomForestModel.sav', 'rb') as model_file:
                    RFmodel = pickle.load(model_file)
                
                predicted_value = RFmodel.predict(data)
                result = "Legitimate" if predicted_value[0] == 0 else "Phishing"
                return JsonResponse({'result': result})
                
            except Exception as model_error:
                print("Model error:", str(model_error))
                return JsonResponse({'error': 'Model processing error'}, status=500)
                
        except Exception as e:
            print("Error:", str(e))
            return JsonResponse({'error': 'Error processing URL'}, status=500)
    
    # Regular GET request handling
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
    

