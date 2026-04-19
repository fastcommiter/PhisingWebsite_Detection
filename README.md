🛡️ Phishing Website Detection System

A hybrid Machine Learning & Rule-Based URL Analysis Engine.

This project is a sophisticated cybersecurity tool designed to identify malicious URLs in real-time. Unlike basic binary classifiers, this system provides a granular risk score (0-100) using a combination of high-accuracy ML models and heuristic security layers.

🚀 Key Features

30+ Feature Extraction: Real-time analysis of URL anatomy (HTTPS status, Domain Age, Rank, URL length, etc.).

Hybrid ML Engine: Uses a Voting Ensemble (Gradient Boosting + Random Forest + Extra Trees) for a generalized accuracy of 96.8%.

Advanced Security Layers:

Typosquatting Detection: Uses Levenshtein Distance to identify domains imitating brands (e.g., faceboobs.com vs facebook.com).

Keyword Analysis: Heuristics to catch suspicious terms like get-free-money or login-update.

User Dashboard: Built with Flask and SQLite to track scan history and provide a detailed risk report.

🛠️ Tech Stack

Language: Python

ML Libraries: Scikit-Learn, Pandas, NumPy

Backend: Flask (Python)

Database: SQLite

Frontend: HTML5, CSS3 (Responsive UI), JavaScript

📊 Model Performance

I compared 6 different models to find the most reliable predictor:

ModelAccuracyVoting Ensemble96.8%Random Forest95.2%Gradient Boosting94.8%Logistic Regression82.4%

⚙️ How it Works

Input: User submits a URL via the Flask interface.

Extraction: System fetches WHOIS data and parses HTML/URL strings to extract 30 key features.

Prediction: The pre-trained Voting Ensemble model processes the features.

Heuristic Check: Simultaneously, the system runs a Levenshtein check for brand impersonation.

Output: A risk score and an "Is Phishing?" verdict are displayed.

📁 Installation & Setup

Clone the repo:

Bash



git clone https://github.com/KunalLatwal/phishing-detection.git

Install dependencies:

Bash



pip install -r requirements.txt

Run the app:

Bash



python app.py
