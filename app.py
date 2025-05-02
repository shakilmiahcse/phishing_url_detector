from flask import Flask, render_template, request
import FeatureExtraction
import pickle
import socket
import pandas as pd

app = Flask(__name__)

# Set default timeout for all socket operations
socket.setdefaulttimeout(60)

@app.route('/')
def index():
    return render_template("home.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/getURL', methods=['GET', 'POST'])
def getURL():
    if request.method == 'POST':
        url = request.form['url']
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url  # Add default protocol if missing
            
        try:
            print("Processing URL:", url)
            data = FeatureExtraction.getAttributess(url)
            
            if data is None:
                return render_template("home.html", error="Could not process this URL")
                
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
                    value = "Legitimate"
                else:
                    value = "Phishing"
                    
                return render_template("home.html", error=value)
                
            except Exception as model_error:
                print("Model error:", str(model_error))
                return render_template("home.html", error="Model processing error")
                
        except Exception as e:
            print("Error:", str(e))
            return render_template("home.html", error="Error processing URL. Please check the URL and try again.")

if __name__ == "__main__":
    app.run(debug=True)