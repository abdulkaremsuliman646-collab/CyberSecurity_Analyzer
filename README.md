# Phishing URL Detection & SSL Security Analyzer 🛡️

A modular Python-based cybersecurity and machine learning tool designed to detect phishing URLs, inspect live SSL certificates, extract lexical URL risk features, calculate explainable risk scores, and train a Random Forest phishing classifier.

## Project Structure 📁
```text
CyberSecurity_Analyzer/
├── data/
│   ├── Training.parquet
│   └── Testing.parquet
├── models/
│   └── phishing_rf_model.joblib # Saved Random Forest classifier
├── src/
│   ├── data_preprocessing.py    # Data loading, cleaning & zero-variance feature removal
│   ├── ssl_analyzer.py          # Live SSL certificate fetching, issuer & expiry analysis
│   ├── url_feature_extractor.py # Lexical & structural phishing URL feature extraction
│   ├── risk_analyzer.py         # Rule-based risk scoring engine (0–100) & threat verdicts
│   ├── ml_model.py              # Random Forest training, evaluation, feature importance & saving
│   └── main.py                  # Interactive CLI entry point
├── .gitignore
├── requirements.txt
└── README.md
```

## Key Features & Progress 📊
- **Dataset Preprocessing (Week 1):**
  - Analyzed 11,430 labeled URLs (`7,658` training / `3,772` testing) with zero missing or duplicate rows.
  - Encoded target labels (`legitimate: 0`, `phishing: 1`) and removed `6` constant features, yielding `81` active features.
- **Live SSL Security Analyzer & URL Feature Extractor (Week 2):**
  - Connects over port `443` with timeout protection to inspect live SSL certificates, issuers, and expiry dates.
  - Extracts lexical/structural indicators and combines them into a weighted **Risk Score (`0–100`)** with explainable threat verdicts.
- **Machine Learning Phishing Classifier (Week 2):**
  - Trained a 100-tree **Random Forest** model (`Scikit-learn`) on the 81 cleaned features and persisted it with `joblib`.
  - **Test Set Performance (`3,772` unseen URLs):**
    - Accuracy: `96.34%` | Precision: `96.10%` | Recall: `96.61%` | F1-Score: `96.35%`
    - Top Security Predictors: `google_index` (`18.95%`), `page_rank` (`10.03%`), `web_traffic` (`9.21%`).

## Setup & Usage 🚀
1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the interactive CLI analyzer:
   ```bash
   python src/main.py
   ```