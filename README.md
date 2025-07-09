# 🛡️ PhishGuardPro – Phishing URL Detector 🔍

**PhishGuardPro** is a machine learning-based web application that detects phishing URLs with high accuracy. It uses multiple classification models and advanced evaluation metrics to provide reliable results.

🌐 **Live App:** [https://phishguardpro.techseba.com](https://phishguardpro.techseba.com)

📂 **GitHub Repo:** [shakilmiahcse/phishing_url_detector](https://github.com/shakilmiahcse/phishing_url_detector)

---

## ✨ Features

- Detects phishing websites using machine learning
- Multiple models: Random Forest, Decision Tree, Logistic Regression, Naive Bayes
- Dataset preprocessing and SMOTE for class balancing
- Clean evaluation and visualization using Jupyter Notebook

---

## 🧠 Model Performance Summary

| Model                | Accuracy | Precision | Recall  | F1 Score | ROC AUC | PR AUC  | Training Time (s) |
|----------------------|----------|-----------|---------|----------|---------|---------|-------------------|
| 🟢 Random Forest     | 0.9383   | 0.9243    | 0.9547  | 0.9393   | 0.9820  | 0.9814  | 1.1348            |
| 🟡 Decision Tree     | 0.9136   | 0.8972    | 0.9342  | 0.9153   | 0.9218  | 0.8822  | 0.0146            |
| 🔵 Logistic Reg.     | 0.8601   | 0.8277    | 0.9095  | 0.8667   | 0.9248  | 0.8972  | 0.0191            |
| 🔴 Naive Bayes       | 0.6708   | 0.6056    | 0.9794  | 0.7484   | 0.8907  | 0.9019  | 0.0038            |


---

## 📁 Project Structure
```bash
phishing-url-detector/
├── model_evaluation.ipynb # Jupyter Notebook for training & testing
├── corrected_legitimate.csv # Legitimate URLs dataset
├── corrected_phishing.csv # Phishing URLs dataset
├── requirements.txt # All dependencies
├── README.md # This file
└── venv/ # Virtual environment (excluded from Git)
```

---

## 🚀 How to Run Locally

```bash
## 1. Clone the Repository

git clone https://github.com/shakilmiahcse/phishing_url_detector.git
cd phishing_url_detector

## 2. Create and Activate Virtual Environment

python -m venv venv

# Windows CMD
venv\Scripts\activate

# Git Bash / WSL
source venv/Scripts/activate

## 3.Install Required Packages

pip install -r requirements.txt

## 4.Launch Jupyter Notebook

jupyter notebook

Then open and run model_evaluation.ipynb.


🧪 Techniques & Libraries
pandas, numpy, matplotlib, seaborn

scikit-learn, imblearn

Models: RandomForest, DecisionTree, LogisticRegression, NaiveBayes

Evaluation: Accuracy, Precision, Recall, F1 Score, ROC-AUC, PR-AUC

🧾 .gitignore Suggestions
venv/
__pycache__/
*.pyc
.ipynb_checkpoints/
