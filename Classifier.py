import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

# Load datasets
legitimate_urls = pd.read_csv("model_comparision_legitimate.csv")
phishing_urls = pd.read_csv("model_comparision_phishing.csv")

# Combine datasets
urls = pd.concat([legitimate_urls, phishing_urls], axis=0)

# Drop unnecessary columns - make sure these match what your FeatureExtraction returns
# Keep only the columns that match your FeatureExtraction features
urls = urls.drop(columns=[col for col in urls.columns if col not in [
    'Having_@_symbol',
    'Having_IP',
    'Prefix_suffix_separation',
    'Redirection_//_symbol',
    'Sub_domains',
    'URL_Length',
    'age_domain',
    'dns_record',
    'domain_registration_length',
    'http_tokens',
    'statistical_report',
    'tiny_url',
    'web_traffic',
    'nb_dots',
    'nb_qm',
    'nb_and',
    'nb_eq',
    'ratio_digits_url',
    'punycode',
    'domain_in_brand',
    'brand_in_path',
    'suspecious_tld',
    'label'
]])

# Shuffle the data
urls = urls.sample(frac=1).reset_index(drop=True)

# Separate features and labels
X = urls.drop('label', axis=1)
y = urls['label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=100)

# Train model
RFmodel = RandomForestClassifier()
RFmodel.fit(X_train, y_train)

# Save model
with open("RandomForestModel.sav", 'wb') as f:
    pickle.dump(RFmodel, f)