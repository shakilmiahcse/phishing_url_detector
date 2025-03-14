import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import re
from urllib.parse import urlparse
import tldextract
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense, Conv1D, MaxPooling1D, Flatten
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.utils import to_categorical

# Load dataset
data = pd.read_csv('dataset_phishing.csv')
print(f"Total rows and columns: {data.shape}")  # (num_rows, num_columns)

# Select all 87 features (excluding 'url' and the 'label' column)
X = data.iloc[:, 1:-1]  # Select all columns except 'url' (1st column) and 'label' (last column)
y = data.iloc[:, -1]    # Target column (phishing or legitimate)

# Convert categorical labels into numerical
y = y.map({'phishing': 1, 'legitimate': 0})  # Encoding labels

# Check dataset balance
print("Class distribution:")
print(y.value_counts())

# Scale features for ML model
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Initialize and train Random Forest model
rf_model = RandomForestClassifier(random_state=42)
rf_model.fit(X_train, y_train)

# Evaluate the Random Forest model
y_pred_rf = rf_model.predict(X_test)
accuracy_rf = accuracy_score(y_test, y_pred_rf)
print(f'Random Forest Accuracy: {accuracy_rf:.4f}')
print(classification_report(y_test, y_pred_rf))

# Print feature importance
print("Feature Importances:")
feature_importances = pd.Series(rf_model.feature_importances_, index=data.columns[1:-1])
print(feature_importances.sort_values(ascending=False).head(10))  # Top 10 important features

# Deep Learning Model (LSTM for URL pattern analysis)
# Tokenize URLs for DL model
tokenizer = Tokenizer(char_level=True)  # Tokenize at character level
tokenizer.fit_on_texts(data['url'])
X_dl = tokenizer.texts_to_sequences(data['url'])
X_dl = pad_sequences(X_dl, maxlen=200)  # Pad sequences to a fixed length

# Split DL data
X_train_dl, X_test_dl, y_train_dl, y_test_dl = train_test_split(X_dl, y, test_size=0.2, random_state=42)

# Build LSTM model
lstm_model = Sequential()
lstm_model.add(Embedding(input_dim=len(tokenizer.word_index) + 1, output_dim=64, input_length=200))
lstm_model.add(LSTM(128, return_sequences=False))
lstm_model.add(Dense(64, activation='relu'))
lstm_model.add(Dense(1, activation='sigmoid'))

lstm_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
lstm_model.summary()

# Train LSTM model
lstm_model.fit(X_train_dl, y_train_dl, epochs=5, batch_size=64, validation_split=0.2)

# Evaluate LSTM model
y_pred_lstm = lstm_model.predict(X_test_dl)
y_pred_lstm = (y_pred_lstm > 0.5).astype(int)
accuracy_lstm = accuracy_score(y_test_dl, y_pred_lstm)
print(f'LSTM Accuracy: {accuracy_lstm:.4f}')
print(classification_report(y_test_dl, y_pred_lstm))

# Meta-Learning: Combine ML and DL outputs
# Get predictions from both models
y_pred_rf_proba = rf_model.predict_proba(X_test)[:, 1]  # RF probabilities
y_pred_lstm_proba = lstm_model.predict(X_test_dl).flatten()  # LSTM probabilities

# Combine predictions using weighted averaging
alpha = 0.6  # Weight for RF model
y_pred_hybrid = (alpha * y_pred_rf_proba + (1 - alpha) * y_pred_lstm_proba)
y_pred_hybrid = (y_pred_hybrid > 0.5).astype(int)

# Evaluate hybrid model
accuracy_hybrid = accuracy_score(y_test, y_pred_hybrid)
print(f'Hybrid Model Accuracy: {accuracy_hybrid:.4f}')
print(classification_report(y_test, y_pred_hybrid))

# Function to extract features from a URL
def extract_features(url):
    features = {}
    
    # Parse the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    # Extract domain components using tldextract
    ext = tldextract.extract(url)
    domain_name = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain

    # Feature 1: Length of URL
    features['length_url'] = len(url)

    # Feature 2: Length of hostname
    features['length_hostname'] = len(domain)

    # Feature 3: IP address in URL
    features['ip'] = 1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0

    # Feature 4: Number of dots in URL
    features['nb_dots'] = url.count('.')

    # Feature 5: Number of hyphens in URL
    features['nb_hyphens'] = url.count('-')

    # Feature 6: Number of '@' symbols in URL
    features['nb_at'] = url.count('@')

    # Feature 7: Number of question marks in URL
    features['nb_qm'] = url.count('?')

    # Feature 8: Number of '&' symbols in URL
    features['nb_and'] = url.count('&')

    # Feature 9: Number of '|' symbols in URL
    features['nb_or'] = url.count('|')

    # Feature 10: Number of '=' symbols in URL
    features['nb_eq'] = url.count('=')

    # Feature 11: Number of underscores in URL
    features['nb_underscore'] = url.count('_')

    # Feature 12: Number of tildes in URL
    features['nb_tilde'] = url.count('~')

    # Feature 13: Number of percent signs in URL
    features['nb_percent'] = url.count('%')

    # Feature 14: Number of slashes in URL
    features['nb_slash'] = url.count('/')

    # Feature 15: Number of stars in URL
    features['nb_star'] = url.count('*')

    # Feature 16: Number of colons in URL
    features['nb_colon'] = url.count(':')

    # Feature 17: Number of commas in URL
    features['nb_comma'] = url.count(',')

    # Feature 18: Number of semicolons in URL
    features['nb_semicolumn'] = url.count(';')

    # Feature 19: Number of dollars in URL
    features['nb_dollar'] = url.count('$')

    # Feature 20: Number of spaces in URL
    features['nb_space'] = url.count(' ')

    # Feature 21: Number of 'www' in URL
    features['nb_www'] = url.count('www')

    # Feature 22: Number of 'com' in URL
    features['nb_com'] = url.count('com')

    # Feature 23: Number of double slashes in URL
    features['nb_dslash'] = url.count('//')

    # Feature 24: HTTP in path
    features['http_in_path'] = 1 if 'http' in path else 0

    # Feature 25: HTTPS token in URL
    features['https_token'] = 1 if 'https' in url else 0

    # Feature 26: Ratio of digits in URL
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0

    # Feature 27: Ratio of digits in hostname
    features['ratio_digits_host'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0

    # Feature 28: Punycode in URL
    features['punycode'] = 1 if 'xn--' in domain else 0

    # Feature 29: Port number in URL
    features['port'] = 1 if ':' in domain else 0

    # Feature 30: TLD in path
    features['tld_in_path'] = 1 if suffix in path else 0

    # Feature 31: TLD in subdomain
    features['tld_in_subdomain'] = 1 if suffix in subdomain else 0

    # Feature 32: Abnormal subdomain
    features['abnormal_subdomain'] = 1 if len(subdomain.split('.')) > 2 else 0

    # Feature 33: Number of subdomains
    features['nb_subdomains'] = len(subdomain.split('.'))

    # Feature 34: Prefix or suffix in domain
    features['prefix_suffix'] = 1 if '-' in domain_name else 0

    # Feature 35: Random domain
    features['random_domain'] = 1 if len(domain_name) < 6 else 0

    # Feature 36: Shortening service
    shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co']
    features['shortening_service'] = 1 if any(service in domain for service in shortening_services) else 0

    # Feature 37: Path extension
    features['path_extension'] = 1 if '.' in path else 0

    # Feature 38: Number of redirections
    features['nb_redirection'] = url.count('redirect')

    # Feature 39: Number of external redirections
    features['nb_external_redirection'] = url.count('external')

    # Feature 40: Length of words in raw URL
    words = url.split('/')
    features['length_words_raw'] = len(words)

    # Feature 41: Character repeat rate in URL
    features['char_repeat'] = len(url) / len(set(url)) if len(set(url)) > 0 else 0

    # Feature 42: Shortest word in raw URL
    features['shortest_words_raw'] = min(len(word) for word in words) if len(words) > 0 else 0

    # Feature 43: Shortest word in hostname
    hostname_words = domain.split('.')
    features['shortest_word_host'] = min(len(word) for word in hostname_words) if len(hostname_words) > 0 else 0

    # Feature 44: Shortest word in path
    path_words = path.split('/')
    features['shortest_word_path'] = min(len(word) for word in path_words) if len(path_words) > 0 else 0

    # Feature 45: Longest words in raw URL
    features['longest_words_raw'] = max(len(word) for word in words) if len(words) > 0 else 0

    # Feature 46: Longest word in hostname
    features['longest_word_host'] = max(len(word) for word in hostname_words) if len(hostname_words) > 0 else 0

    # Feature 47: Longest word in path
    features['longest_word_path'] = max(len(word) for word in path_words) if len(path_words) > 0 else 0

    # Feature 48: Average word length in raw URL
    features['avg_words_raw'] = sum(len(word) for word in words) / len(words) if len(words) > 0 else 0

    # Feature 49: Average word length in hostname
    features['avg_word_host'] = sum(len(word) for word in hostname_words) / len(hostname_words) if len(hostname_words) > 0 else 0

    # Feature 50: Average word length in path
    features['avg_word_path'] = sum(len(word) for word in path_words) / len(path_words) if len(path_words) > 0 else 0

    # Feature 51: Phishing hints in URL
    phishing_hints = ['login', 'secure', 'account', 'verify', 'banking']
    features['phish_hints'] = sum(hint in url.lower() for hint in phishing_hints)

    # Feature 52: Domain in brand
    features['domain_in_brand'] = 1 if domain_name in url else 0

    # Feature 53: Brand in subdomain
    features['brand_in_subdomain'] = 1 if domain_name in subdomain else 0

    # Feature 54: Brand in path
    features['brand_in_path'] = 1 if domain_name in path else 0

    # Feature 55: Suspicious TLD
    suspicious_tlds = ['xyz', 'top', 'gq', 'cf', 'tk']
    features['suspecious_tld'] = 1 if suffix in suspicious_tlds else 0

    # Feature 56: Statistical report
    features['statistical_report'] = 1 if 'report' in url else 0

    # Feature 57: Number of hyperlinks
    features['nb_hyperlinks'] = url.count('href=')

    # Feature 58: Ratio of internal hyperlinks
    features['ratio_intHyperlinks'] = url.count('href="/') / url.count('href=') if url.count('href=') > 0 else 0

    # Feature 59: Ratio of external hyperlinks
    features['ratio_extHyperlinks'] = url.count('href="http') / url.count('href=') if url.count('href=') > 0 else 0

    # Feature 60: Ratio of null hyperlinks
    features['ratio_nullHyperlinks'] = url.count('href="#"') / url.count('href=') if url.count('href=') > 0 else 0

    # Feature 61: Number of external CSS
    features['nb_extCSS'] = url.count('<link rel="stylesheet" href="http')

    # Feature 62: Ratio of internal redirections
    features['ratio_intRedirection'] = url.count('redirect="/') / url.count('redirect') if url.count('redirect') > 0 else 0

    # Feature 63: Ratio of external redirections
    features['ratio_extRedirection'] = url.count('redirect="http') / url.count('redirect') if url.count('redirect') > 0 else 0

    # Feature 64: Ratio of internal errors
    features['ratio_intErrors'] = url.count('error="/') / url.count('error') if url.count('error') > 0 else 0

    # Feature 65: Ratio of external errors
    features['ratio_extErrors'] = url.count('error="http') / url.count('error') if url.count('error') > 0 else 0

    # Feature 66: Login form
    features['login_form'] = 1 if 'login' in url else 0

    # Feature 67: External favicon
    features['external_favicon'] = 1 if 'favicon.ico' in url else 0

    # Feature 68: Links in tags
    features['links_in_tags'] = url.count('<a href=')

    # Feature 69: Submit email
    features['submit_email'] = 1 if 'mailto:' in url else 0

    # Feature 70: Ratio of internal media
    features['ratio_intMedia'] = url.count('<img src="/') / url.count('<img') if url.count('<img') > 0 else 0

    # Feature 71: Ratio of external media
    features['ratio_extMedia'] = url.count('<img src="http') / url.count('<img') if url.count('<img') > 0 else 0

    # Feature 72: SFH (Server Form Handler)
    features['sfh'] = 1 if 'action=' in url else 0

    # Feature 73: Iframe
    features['iframe'] = 1 if '<iframe' in url else 0

    # Feature 74: Popup window
    features['popup_window'] = 1 if 'window.open' in url else 0

    # Feature 75: Safe anchor
    features['safe_anchor'] = 1 if 'rel="nofollow"' in url else 0

    # Feature 76: Onmouseover
    features['onmouseover'] = 1 if 'onmouseover' in url else 0

    # Feature 77: Right click
    features['right_clic'] = 1 if 'oncontextmenu' in url else 0

    # Feature 78: Empty title
    features['empty_title'] = 1 if '<title></title>' in url else 0

    # Feature 79: Domain in title
    features['domain_in_title'] = 1 if domain_name in url else 0

    # Feature 80: Domain with copyright
    features['domain_with_copyright'] = 1 if '©' in url else 0

    # Feature 81: Whois registered domain
    features['whois_registered_domain'] = 1 if 'whois' in url else 0

    # Feature 82: Domain registration length
    features['domain_registration_length'] = 1 if 'domain' in url else 0

    # Feature 83: Domain age
    features['domain_age'] = 1 if 'age' in url else 0

    # Feature 84: Web traffic
    features['web_traffic'] = 1 if 'traffic' in url else 0

    # Feature 85: DNS record
    features['dns_record'] = 1 if 'dns' in url else 0

    # Feature 86: Google index
    features['google_index'] = 1 if 'google' in url else 0

    # Feature 87: Page rank
    features['page_rank'] = 1 if 'rank' in url else 0

    # Return the features as a list in the same order as the training data
    return [features[col] for col in data.columns[1:-1]]

# Function to predict phishing using the hybrid model
def predict_url_hybrid(url):
    # Extract features for ML model
    features = extract_features(url)
    feature_names = data.columns[1:-1]  # Exclude 'url' and 'label'
    features_df = pd.DataFrame([features], columns=feature_names)
    features_scaled = scaler.transform(features_df)

    # Predict using RF model
    rf_prob = rf_model.predict_proba(features_scaled)[:, 1][0]

    # Predict using LSTM model
    dl_input = tokenizer.texts_to_sequences([url])
    dl_input = pad_sequences(dl_input, maxlen=200)
    lstm_prob = lstm_model.predict(dl_input).flatten()[0]

    # Combine predictions
    alpha = 0.6  # Weight for RF model
    hybrid_prob = alpha * rf_prob + (1 - alpha) * lstm_prob
    prediction = int(hybrid_prob > 0.6)  # Adjust threshold to 0.6

    # Debugging: Print probabilities
    print(f"RF Probability: {rf_prob:.4f}, LSTM Probability: {lstm_prob:.4f}, Hybrid Probability: {hybrid_prob:.4f}")

    return "Phishing" if prediction == 1 else "Legitimate"

# Take URL input
url_input = input("Enter a URL to check if it's phishing or legitimate: ")
result = predict_url_hybrid(url_input)
print(f"The URL is: {result}")