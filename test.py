import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
import tldextract
import whois
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load dataset
data = pd.read_csv("dataset_phishing.csv")

# Define important features
important_features = [
    'length_url', 'nb_dots', 'nb_qm', 'nb_and', 'nb_eq', 'https_token',
    'ratio_digits_url', 'punycode', 'tld_in_subdomain', 'abnormal_subdomain',
    'domain_in_brand', 'brand_in_path', 'suspecious_tld', 'ratio_intHyperlinks',
    'ratio_extHyperlinks', 'external_favicon', 'sfh', 'iframe', 'domain_in_title',
    'domain_age', 'dns_record', 'page_rank'
]

# Prepare data
X = data[important_features]
y = data['status'].map({'legitimate': 0, 'phishing': 1})
X = X.replace(-1, np.nan).fillna(X.mean())

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Initialize models
models = {
    "Random Forest": RandomForestClassifier(random_state=42),
    "XGBoost": XGBClassifier(random_state=42, 
                            scale_pos_weight=(len(y_train) - sum(y_train))/sum(y_train),
                            eval_metric='logloss')
}

# Train models
for name, model in models.items():
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print(f"\n{name} Performance:")
    print(classification_report(y_test, y_pred))

# Feature extraction function
def extract_url_features(url):
    # Basic URL features
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    
    features = {
        'length_url': len(url),
        'nb_dots': url.count('.'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_eq': url.count('='),
        'https_token': 1 if parsed.scheme == 'https' else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        'punycode': 1 if 'xn--' in url else 0,
        'tld_in_subdomain': 1 if ext.suffix in ext.subdomain else 0,
        'abnormal_subdomain': 1 if len(ext.subdomain.split('.')) > 3 else 0,
        'domain_in_brand': 1 if 'paypal' in url or 'ebay' in url or 'amazon' in url else 0,  # Example brands
        'brand_in_path': 1 if any(brand in parsed.path for brand in ['paypal', 'ebay', 'amazon']) else 0,
        'suspecious_tld': 1 if ext.suffix in ['xyz', 'top', 'gq', 'tk', 'ml', 'cf', 'ga'] else 0,
        'ratio_intHyperlinks': 0.5,  # Placeholder - would need actual page content
        'ratio_extHyperlinks': 0.5,  # Placeholder - would need actual page content
        'external_favicon': 0,  # Placeholder
        'sfh': 0,  # Placeholder (server form handler)
        'iframe': 0,  # Placeholder - would need page content
        'domain_in_title': 0,  # Placeholder - would need page title
        'domain_age': 365,  # Placeholder - would need WHOIS lookup
        'dns_record': 1,  # Placeholder - would need DNS check
        'page_rank': 5  # Placeholder - would need actual page rank
    }
    
    # Try to get WHOIS information for domain age
    try:
        domain_info = whois.whois(parsed.netloc)
        if domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            age = (datetime.now() - creation_date).days
            features['domain_age'] = age if age > 0 else 365
    except:
        pass
    
    return [features[feat] for feat in important_features]

# Hybrid prediction function
def predict_url_hybrid(url):
    try:
        # Extract features
        features = extract_url_features(url)
        
        # Create DataFrame with the same features as training
        features_df = pd.DataFrame([features], columns=important_features)
        
        # Handle missing values the same way as training
        features_df = features_df.replace(-1, np.nan).fillna(X.mean())
        
        # Make predictions with both models
        rf_pred = models["Random Forest"].predict(features_df)[0]
        xgb_pred = models["XGBoost"].predict(features_df)[0]
        
        # Get probabilities
        rf_proba = models["Random Forest"].predict_proba(features_df)[0][1]
        xgb_proba = models["XGBoost"].predict_proba(features_df)[0][1]
        
        # Combine predictions with weighted average
        combined_proba = (rf_proba * 0.5 + xgb_proba * 0.5)
        combined_pred = 1 if combined_proba >= 0.5 else 0
        
        return {
            "url": url,
            "status": "Phishing" if combined_pred == 1 else "Legitimate",
            "confidence": combined_proba if combined_pred == 1 else 1 - combined_proba,
            "RF_prediction": "Phishing" if rf_pred == 1 else "Legitimate",
            "RF_confidence": rf_proba if rf_pred == 1 else 1 - rf_proba,
            "XGB_prediction": "Phishing" if xgb_pred == 1 else "Legitimate",
            "XGB_confidence": xgb_proba if xgb_pred == 1 else 1 - xgb_proba
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }

# Interactive testing
if __name__ == "__main__":
    print("URL Phishing Detector")
    print("Enter 'quit' to exit\n")
    
    while True:
        url_input = input("Enter URL to check: ").strip()
        if url_input.lower() in ['quit', 'exit']:
            break
            
        result = predict_url_hybrid(url_input)
        
        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"\nResult for: {result['url']}")
            print(f"Final Prediction: {result['status']} (Confidence: {result['confidence']:.2%})")
            print(f"Random Forest: {result['RF_prediction']} (Confidence: {result['RF_confidence']:.2%})")
            print(f"XGBoost: {result['XGB_prediction']} (Confidence: {result['XGB_confidence']:.2%})\n")