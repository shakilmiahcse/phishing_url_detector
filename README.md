# 🛡️ PhishGuardPro – Phishing URL Detector (Django) 🔍

**PhishGuardPro Django Edition** is a production-ready web application that detects phishing URLs using machine learning. It combines Django's robustness with ML models for real-time phishing detection.

🌐 **Live App:** [https://phishguardpro.techseba.com](https://phishguardpro.techseba.com)

📂 **GitHub Repo:** [shakilmiahcse/phishing_url_detector_django](https://github.com/shakilmiahcse/phishing_url_detector_django)

---

## ✨ Features

- **Django-powered** web interface for phishing detection
- **Real-time URL analysis** with machine learning models
- **Responsive design** works on all devices

---

## 🛠️ Tech Stack

- **Backend**: Django 4.x, Django REST Framework
- **Frontend**: HTML5, CSS3, Bootstrap 5, JavaScript
- **ML Models**: Scikit-learn (Random Forest, Decision Tree, etc.)

---

## 🚀 Installation Guide

### Prerequisites
- Python 3.8+
- pip
- virtualenv

### Local Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/shakilmiahcse/phishing_url_detector_django.git
cd phishing_url_detector_django

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/MacOS
# OR
venv\Scripts\activate    # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Apply migrations
python manage.py migrate

# 5. Create superuser (optional)
python manage.py createsuperuser

# 6. Run development server
python manage.py runserver

## 🧠 Model Performance

- Model	Accuracy	Precision	Recall	F1 Score
- Random Forest	0.9383	0.9243	0.9547	0.9393
- Decision Tree	0.9136	0.8972	0.9342	0.9153
- Logistic Regression	0.8601	0.8277	0.9095	0.8667

## 📧 Contact
- Shakil Miah - @shakilmiahcse
- Project Link: https://github.com/shakilmiahcse/phishing_url_detector_django
