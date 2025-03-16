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

# Function to predict phishing using the hybrid model
def predict_url_hybrid(url):
    # Extract features for ML model
    features = extract_url_features(url)
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
    hybrid_prob = alpha * rf_prob + (1 - alpha) * lstm_prob
    prediction = int(hybrid_prob > 0.6)  # Adjust threshold to 0.6

    # Debugging: Print probabilities
    print(f"RF Probability: {rf_prob:.4f}, LSTM Probability: {lstm_prob:.4f}, Hybrid Probability: {hybrid_prob:.4f}")

    return "Phishing" if prediction == 1 else "Legitimate"

# Take URL input
url_input = input("Enter a URL to check if it's phishing or legitimate: ")
result = predict_url_hybrid(url_input)
print(f"The URL is: {result}")