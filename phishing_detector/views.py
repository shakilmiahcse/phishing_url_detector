from django.shortcuts import render
from django.views.decorators.http import require_http_methods
import FeatureExtraction
import pickle
import socket
import pandas as pd

# Set default timeout for all socket operations
socket.setdefaulttimeout(60)

def index(request):
    context = {}
    
    if request.method == 'POST':
        url = request.POST.get('url', '')
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url  # Add default protocol if missing
            
        try:
            print("Processing URL:", url)
            data = FeatureExtraction.getAttributess(url)
            
            if data is None:
                context['error'] = "Could not process this URL"
                return render(request, "index.html", context)
                
            print("Extracted features:", data)
            
            try:
                with open('RandomForestModel.sav', 'rb') as model_file:
                    RFmodel = pickle.load(model_file)
                
                # Debug: Print expected feature names if available
                if hasattr(RFmodel, 'feature_names_in_'):
                    print("Model expects features:", RFmodel.feature_names_in_)
                    print("Features being sent:", data.columns.tolist())
                
                predicted_value = RFmodel.predict(data)
                
                if predicted_value == 0:    
                    context['error'] = "Legitimate"
                else:
                    context['error'] = "Phishing"
                    
                return render(request, "index.html", context)
                
            except Exception as model_error:
                print("Model error:", str(model_error))
                context['error'] = "Model processing error"
                return render(request, "index.html", context)
                
        except Exception as e:
            print("Error:", str(e))
            context['error'] = "Error processing URL. Please check the URL and try again."
            return render(request, "index.html", context)
    
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
    

