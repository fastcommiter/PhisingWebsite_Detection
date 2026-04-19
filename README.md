# 🛡️ Phishing Website Detection System
**A Hybrid Machine Learning & Heuristic-Based Security Engine**

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Machine Learning](https://img.shields.io/badge/ML-Voting_Ensemble-orange?style=flat)](https://scikit-learn.org/)

## 📝 Overview
Phishing attacks are one of the most common cybersecurity threats where attackers create fake URLs to steal credentials. This project addresses this problem by using a **Voting Ensemble Machine Learning model** combined with rule-based layers to detect malicious websites in real-time.

---

## 🚀 Key Features
- **Hybrid ML Engine:** Uses a **Voting Ensemble** (Gradient Boosting + Random Forest + Extra Trees) for **96.8% accuracy**.
- **30-Feature Extraction:** Real-time analysis of URL anatomy (Domain Age, SSL status, Anchor links %, etc.).
- **Typosquatting Detection:** Implemented **Levenshtein Distance** to identify domains imitating brands (e.g., `faceboobs.com`).
- **Granular Risk Scoring:** Provides a **0-100 risk score** rather than a simple binary safe/unsafe label.
- **User Dashboard:** Full-stack Flask application with an integrated **SQLite database** to store scan history.

---

## 📊 Model Performance
I compared 6 models on a dataset of **11,054 URLs** to find the best generalized accuracy:

| Model | Accuracy |
| :--- | :--- |
| **Voting Ensemble (Proposed)** | **96.80%** |
| Random Forest | 95.21% |
| Gradient Boosting | 94.85% |
| Extra Trees | 94.10% |
| Decision Tree | 91.40% |
| Logistic Regression | 82.35% |

---

## 📁 Installation & Setup

### 1. Clone the repository
```bash
git clone [https://github.com/KunalLatwal/phishing-detection.git](https://github.com/KunalLatwal/phishing-detection.git)
cd phishing-detection
