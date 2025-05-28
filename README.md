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

| Model                | Accuracy | Precision | Recall | F1 Score | ROC AUC | PR AUC  | Training Time (s) |
|---------------------|----------|-----------|--------|----------|---------|---------|-------------------|
| 🟢 Random Forest     | 0.9115   | 0.9098    | 0.9136 | 0.9117   | 0.9723  | 0.9705  | 1.2170            |
| 🟡 Decision Tree     | 0.8765   | 0.8861    | 0.8642 | 0.8750   | 0.8800  | 0.8364  | 0.0152            |
| 🔵 Logistic Reg.     | 0.7963   | 0.7727    | 0.8395 | 0.8047   | 0.8758  | 0.8568  | 0.0115            |
| 🔴 Naive Bayes       | 0.7202   | 0.6597    | 0.9095 | 0.7647   | 0.8657  | 0.8764  | 0.0030            |

---

## 📁 Project Structure

phishing-url-detector/
├── model_evaluation.ipynb # Jupyter Notebook for training & testing
├── corrected_legitimate.csv # Legitimate URLs dataset
├── corrected_phishing.csv # Phishing URLs dataset
├── requirements.txt # All dependencies
├── README.md # This file
└── venv/ # Virtual environment (excluded from Git)


---

## 🚀 How to Run Locally

## 1. Clone the Repository

```bash
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