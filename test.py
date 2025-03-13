import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import re
from urllib.parse import urlparse
import tldextract
import numpy as np

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

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Initialize and train Random Forest model
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy:.4f}')
print(classification_report(y_test, y_pred))

# Print feature importance
print("Feature Importances:")
feature_importances = pd.Series(model.feature_importances_, index=data.columns[1:-1])
print(feature_importances.sort_values(ascending=False).head(10))  # Top 10 important features

def extract_url_features(url):
    # Parse the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    # Extract TLD (Top-Level Domain) and subdomain
    ext = tldextract.extract(url)
    tld = ext.suffix
    subdomain = ext.subdomain

    # Initialize a list to store features
    features = []

    # 1. length_url: Length of the URL
    features.append(len(url))

    # 2. length_hostname: Length of the hostname
    features.append(len(domain))

    # 3. ip: Whether the URL contains an IP address
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    features.append(1 if ip_pattern.match(domain) else 0)

    # 4. nb_dots: Number of dots in the URL
    features.append(url.count('.'))

    # 5. nb_hyphens: Number of hyphens in the URL
    features.append(url.count('-'))

    # 6. nb_at: Number of '@' symbols in the URL
    features.append(url.count('@'))

    # 7. nb_qm: Number of '?' symbols in the URL
    features.append(url.count('?'))

    # 8. nb_and: Number of '&' symbols in the URL
    features.append(url.count('&'))

    # 9. nb_or: Number of '|' symbols in the URL
    features.append(url.count('|'))

    # 10. nb_eq: Number of '=' symbols in the URL
    features.append(url.count('='))

    # 11. nb_underscore: Number of '_' symbols in the URL
    features.append(url.count('_'))

    # 12. nb_tilde: Number of '~' symbols in the URL
    features.append(url.count('~'))

    # 13. nb_percent: Number of '%' symbols in the URL
    features.append(url.count('%'))

    # 14. nb_slash: Number of '/' symbols in the URL
    features.append(url.count('/'))

    # 15. nb_star: Number of '*' symbols in the URL
    features.append(url.count('*'))

    # 16. nb_colon: Number of ':' symbols in the URL
    features.append(url.count(':'))

    # 17. nb_comma: Number of ',' symbols in the URL
    features.append(url.count(','))

    # 18. nb_semicolumn: Number of ';' symbols in the URL
    features.append(url.count(';'))

    # 19. nb_dollar: Number of '$' symbols in the URL
    features.append(url.count('$'))

    # 20. nb_space: Number of spaces in the URL
    features.append(url.count(' '))

    # 21. nb_www: Whether the URL contains 'www'
    features.append(1 if 'www' in domain else 0)

    # 22. nb_com: Whether the URL contains '.com'
    features.append(1 if '.com' in domain else 0)

    # 23. nb_dslash: Number of double slashes '//' in the URL
    features.append(url.count('//'))

    # 24. http_in_path: Whether 'http' is in the path
    features.append(1 if 'http' in path else 0)

    # 25. https_token: Whether 'https' is in the domain
    features.append(1 if 'https' in domain else 0)

    # 26. ratio_digits_url: Ratio of digits in the URL
    digits = sum(c.isdigit() for c in url)
    features.append(digits / len(url) if len(url) > 0 else 0)

    # 27. ratio_digits_host: Ratio of digits in the hostname
    digits_host = sum(c.isdigit() for c in domain)
    features.append(digits_host / len(domain) if len(domain) > 0 else 0)

    # 28. punycode: Whether the URL uses punycode
    features.append(1 if parsed_url.netloc.startswith('xn--') else 0)

    # 29. port: Whether the URL contains a port number
    features.append(1 if ':' in domain else 0)

    # 30. tld_in_path: Whether the TLD is in the path
    features.append(1 if tld in path else 0)

    # 31. tld_in_subdomain: Whether the TLD is in the subdomain
    features.append(1 if tld in subdomain else 0)

    # 32. abnormal_subdomain: Whether the subdomain is abnormal
    features.append(1 if len(subdomain) > 10 else 0)  # Example threshold

    # 33. nb_subdomains: Number of subdomainsa
    features.append(len(subdomain.split('.')) if subdomain else 0)

    # 34. prefix_suffix: Whether the domain has a prefix or suffix
    features.append(1 if '-' in domain else 0)

    # 35. random_domain: Whether the domain appears random
    features.append(1 if len(domain) > 20 else 0)  # Example threshold

    # 36. shortening_service: Whether the URL uses a shortening service
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com']
    features.append(1 if any(s in domain for s in shorteners) else 0)

    # 37. path_extension: Whether the path has an extension
    features.append(1 if '.' in path else 0)

    # 38. nb_redirection: Number of redirections (not implemented here)
    features.append(0)  # Placeholder

    # 39. nb_external_redirection: Number of external redirections (not implemented here)
    features.append(0)  # Placeholder

    # 40. length_words_raw: Number of words in the URL
    words = re.findall(r'\w+', url)
    features.append(len(words))

    # 41. char_repeat: Ratio of repeated characters
    char_counts = {char: url.count(char) for char in set(url)}
    char_repeat = sum(count - 1 for count in char_counts.values() if count > 1)
    features.append(char_repeat / len(url) if len(url) > 0 else 0)

    # 42. shortest_words_raw: Length of the shortest word in the URL
    shortest_word = min(len(word) for word in words) if words else 0
    features.append(shortest_word)

    # 43. shortest_word_host: Length of the shortest word in the hostname
    host_words = re.findall(r'\w+', domain)
    shortest_host_word = min(len(word) for word in host_words) if host_words else 0
    features.append(shortest_host_word)

    # 44. shortest_word_path: Length of the shortest word in the path
    path_words = re.findall(r'\w+', path)
    shortest_path_word = min(len(word) for word in path_words) if path_words else 0
    features.append(shortest_path_word)

    # 45. longest_words_raw: Length of the longest word in the URL
    longest_word = max(len(word) for word in words) if words else 0
    features.append(longest_word)

    # 46. longest_word_host: Length of the longest word in the hostname
    longest_host_word = max(len(word) for word in host_words) if host_words else 0
    features.append(longest_host_word)

    # 47. longest_word_path: Length of the longest word in the path
    longest_path_word = max(len(word) for word in path_words) if path_words else 0
    features.append(longest_path_word)

    # 48. avg_words_raw: Average length of words in the URL
    avg_word_length = sum(len(word) for word in words) / len(words) if words else 0
    features.append(avg_word_length)

    # 49. avg_word_host: Average length of words in the hostname
    avg_host_word_length = sum(len(word) for word in host_words) / len(host_words) if host_words else 0
    features.append(avg_host_word_length)

    # 50. avg_word_path: Average length of words in the path
    avg_path_word_length = sum(len(word) for word in path_words) / len(path_words) if path_words else 0
    features.append(avg_path_word_length)

    # 51. phish_hints: Whether the URL contains phishing hints (e.g., 'login', 'secure')
    phishing_hints = ['login', 'secure', 'account', 'verify']
    features.append(1 if any(hint in url.lower() for hint in phishing_hints) else 0)

    # 52. domain_in_brand: Whether the domain contains a brand name (not implemented here)
    features.append(0)  # Placeholder

    # 53. brand_in_subdomain: Whether the brand is in the subdomain (not implemented here)
    features.append(0)  # Placeholder

    # 54. brand_in_path: Whether the brand is in the path (not implemented here)
    features.append(0)  # Placeholder

    # 55. suspecious_tld: Whether the TLD is suspicious
    suspicious_tlds = ['.xyz', '.top', '.gq']
    features.append(1 if tld in suspicious_tlds else 0)

    # 56. statistical_report: Statistical report (not implemented here)
    features.append(0)  # Placeholder

    # 57. nb_hyperlinks: Number of hyperlinks (not implemented here)
    features.append(0)  # Placeholder

    # 58. ratio_intHyperlinks: Ratio of internal hyperlinks (not implemented here)
    features.append(0)  # Placeholder

    # 59. ratio_extHyperlinks: Ratio of external hyperlinks (not implemented here)
    features.append(0)  # Placeholder

    # 60. ratio_nullHyperlinks: Ratio of null hyperlinks (not implemented here)
    features.append(0)  # Placeholder

    # 61. nb_extCSS: Number of external CSS files (not implemented here)
    features.append(0)  # Placeholder

    # 62. ratio_intRedirection: Ratio of internal redirections (not implemented here)
    features.append(0)  # Placeholder

    # 63. ratio_extRedirection: Ratio of external redirections (not implemented here)
    features.append(0)  # Placeholder

    # 64. ratio_intErrors: Ratio of internal errors (not implemented here)
    features.append(0)  # Placeholder

    # 65. ratio_extErrors: Ratio of external errors (not implemented here)
    features.append(0)  # Placeholder

    # 66. login_form: Whether the URL contains a login form (not implemented here)
    features.append(0)  # Placeholder

    # 67. external_favicon: Whether the URL uses an external favicon (not implemented here)
    features.append(0)  # Placeholder

    # 68. links_in_tags: Number of links in tags (not implemented here)
    features.append(0)  # Placeholder

    # 69. submit_email: Whether the URL submits an email (not implemented here)
    features.append(0)  # Placeholder

    # 70. ratio_intMedia: Ratio of internal media (not implemented here)
    features.append(0)  # Placeholder

    # 71. ratio_extMedia: Ratio of external media (not implemented here)
    features.append(0)  # Placeholder

    # 72. sfh: Server form handler (not implemented here)
    features.append(0)  # Placeholder

    # 73. iframe: Whether the URL uses iframes (not implemented here)
    features.append(0)  # Placeholder

    # 74. popup_window: Whether the URL uses popup windows (not implemented here)
    features.append(0)  # Placeholder

    # 75. safe_anchor: Whether the URL uses safe anchors (not implemented here)
    features.append(0)  # Placeholder

    # 76. onmouseover: Whether the URL uses onmouseover events (not implemented here)
    features.append(0)  # Placeholder

    # 77. right_clic: Whether the URL disables right-click (not implemented here)
    features.append(0)  # Placeholder

    # 78. empty_title: Whether the URL has an empty title (not implemented here)
    features.append(0)  # Placeholder

    # 79. domain_in_title: Whether the domain is in the title (not implemented here)
    features.append(0)  # Placeholder

    # 80. domain_with_copyright: Whether the domain has a copyright notice (not implemented here)
    features.append(0)  # Placeholder

    # 81. whois_registered_domain: Whether the domain is registered (not implemented here)
    features.append(0)  # Placeholder

    # 82. domain_registration_length: Domain registration length (not implemented here)
    features.append(0)  # Placeholder

    # 83. domain_age: Domain age (not implemented here)
    features.append(0)  # Placeholder

    # 84. web_traffic: Web traffic (not implemented here)
    features.append(0)  # Placeholder

    # 85. dns_record: DNS record (not implemented here)
    features.append(0)  # Placeholder

    # 86. google_index: Whether the URL is indexed by Google (not implemented here)
    features.append(0)  # Placeholder

    # 87. page_rank: Page rank (not implemented here)
    features.append(0)  # Placeholder

    return features

def predict_url(url):
    # Extract features from the URL
    features = extract_url_features(url)

    # Convert to DataFrame with the same column names as the training data
    feature_names = data.columns[1:-1]  # Exclude 'url' and 'label'
    features_df = pd.DataFrame([features], columns=feature_names)

    # Scale features using the same scaler
    features_scaled = scaler.transform(features_df)

    # Predict phishing probability
    prediction_prob = model.predict_proba(features_scaled)[:, 1]  # Probability of phishing
    prediction = int(prediction_prob[0] > 0.6)  # Adjust threshold to 0.6

    # Debugging: Print features and prediction probability
    print("Extracted Features:")
    print(features_df)
    print(f"Prediction Probability: {prediction_prob[0]:.4f}")

    return "Phishing" if prediction == 1 else "Legitimate"

# Take URL input
url_input = input("Enter a URL to check if it's phishing or legitimate: ")
result = predict_url(url_input)
print(f"The URL is: {result}")