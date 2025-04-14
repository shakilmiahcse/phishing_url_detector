import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import (accuracy_score, classification_report, 
                            confusion_matrix, roc_curve, auc, 
                            precision_recall_curve, average_precision_score)

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
    "Naive Bayes": GaussianNB(),
    "Random Forest": RandomForestClassifier(random_state=42),
    "XGBoost": XGBClassifier(random_state=42, 
                            scale_pos_weight=(len(y_train) - sum(y_train))/sum(y_train),
                            eval_metric='logloss')
}

# Create figure for evaluation plots
plt.figure(figsize=(15, 15))

# Train and evaluate models
for i, (name, model) in enumerate(models.items()):
    print(f"\n{'='*40}\n{name}\n{'='*40}")
    
    # Train
    if name == "Naive Bayes":
        model.fit(X_train_scaled, y_train)
        X_eval = X_test_scaled
    else:
        model.fit(X_train, y_train)
        X_eval = X_test
    
    # Predict
    y_pred = model.predict(X_eval)
    y_proba = model.predict_proba(X_eval)[:, 1] if hasattr(model, "predict_proba") else [0]*len(y_test)
    
    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Confusion Matrix Plot
    plt.subplot(3, 3, i*3 + 1)
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Legitimate', 'Phishing'], 
                yticklabels=['Legitimate', 'Phishing'])
    plt.title(f'{name} Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    
    # ROC Curve
    if len(np.unique(y_test)) > 1:
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        roc_auc = auc(fpr, tpr)
        plt.subplot(3, 3, i*3 + 2)
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'{name} ROC Curve')
        plt.legend(loc="lower right")
    
    # Precision-Recall Curve
    precision, recall, _ = precision_recall_curve(y_test, y_proba)
    avg_precision = average_precision_score(y_test, y_proba)
    plt.subplot(3, 3, i*3 + 3)
    plt.plot(recall, precision, color='blue', lw=2,
            label=f'AP = {avg_precision:.2f}')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title(f'{name} Precision-Recall Curve')
    plt.legend(loc="lower left")

plt.tight_layout()
plt.show()

# Feature Importance for tree-based models
for name in ["Random Forest", "XGBoost"]:
    if name in models:
        plt.figure(figsize=(10, 6))
        
        if name == "Random Forest":
            importances = models[name].feature_importances_
            feat_imp = pd.DataFrame({
                'Feature': important_features,
                'Importance': importances
            }).sort_values('Importance', ascending=False)
        else:
            # Handle XGBoost feature importance
            importance_dict = models[name].get_booster().get_score(importance_type='weight')
            # Create mapping between feature indices and names
            feat_map = {f'f{i}': feat for i, feat in enumerate(important_features)}
            # Convert to DataFrame
            feat_imp = pd.DataFrame({
                'Feature': [feat_map[k] for k in importance_dict.keys()],
                'Importance': list(importance_dict.values())
            }).sort_values('Importance', ascending=False)
        
        # Plot top 10 features
        sns.barplot(x='Importance', y='Feature', 
                   data=feat_imp.head(10), palette='viridis')
        plt.title(f'{name} - Top 10 Feature Importance')
        plt.tight_layout()
        plt.show()