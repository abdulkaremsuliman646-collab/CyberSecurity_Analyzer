# Phishing URL Detection & SSL Security Analyzer 🛡️

A modular Python-based cybersecurity and machine learning tool designed to detect phishing URLs, inspect live SSL certificates, extract lexical URL risk features, calculate explainable risk scores, classify threats using an optimized Random Forest model, and export batch security reports in JSON and CSV formats.

## Project Structure 📁
```text
CyberSecurity_Analyzer/
├── data/
│   ├── Training.parquet
│   └── Testing.parquet
├── models/
│   └── phishing_rf_model.joblib   # Saved Random Forest classifier
├── reports/
│   ├── security_report.json       # Machine-readable batch scan report
│   └── security_report.csv        # Spreadsheet-ready batch scan report
├── src/
│   ├── data_preprocessing.py      # Data loading, cleaning & zero-variance feature removal
│   ├── ssl_analyzer.py            # Live SSL certificate fetching, issuer & expiry analysis
│   ├── url_feature_extractor.py   # Lexical & structural phishing URL feature extraction
│   ├── risk_analyzer.py           # Rule-based risk scoring engine (0–100) & threat verdicts
│   ├── ml_model.py                # Random Forest training, evaluation, saving & threshold prediction
│   ├── model_comparison.py        # Multi-model benchmarking (RF, LR, GB) & threshold optimization
│   ├── report_generator.py        # Batch URL scanning & JSON/CSV report generation
│   └── main.py                    # Interactive CLI entry point (5 menu options)
├── urls.txt                       # Sample URL list for batch scanning
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
- **Model Comparison & Threshold Optimization (Week 2):**
  - Benchmarked 3 classifiers on `3,772` unseen test URLs (with `StandardScaler` pipeline for Logistic Regression):
    - **Random Forest (Winner):** Accuracy `96.34%` | Recall `96.61%` | F1-Score `96.35%` | Missed Phishing (FN): `64`
    - **Gradient Boosting:** Accuracy `95.49%` | Recall `95.55%` | F1-Score `95.50%` | Missed Phishing (FN): `84`
    - **Logistic Regression:** Accuracy `94.25%` | Recall `94.01%` | F1-Score `94.23%` | Missed Phishing (FN): `113`
  - **Threshold Tuning (Random Forest):** Lowering the decision threshold from `0.50` to `0.40` increased Recall from `96.66%` to `97.88%` and reduced Missed Phishing (FN) from `63` down to `40` while maintaining `94.23%` Precision.
- **Batch URL Scanning & Automated Reporting (Week 2 - Day 8):**
  - Built `src/report_generator.py` to scan multiple URLs from a text file (`urls.txt`) and automatically export structured results to both `JSON` (for system integration) and `CSV` (for analyst/spreadsheet review).
  - Integrated batch scanning into the interactive CLI (`Option 4`) with default file fallback, empty-file detection, and `FileNotFoundError` error handling.

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
3. Run the interactive CLI analyzer (single scan, batch scan + JSON/CSV export, or ML pipeline) or model benchmark:
   ```bash
   python src/main.py
   python src/model_comparison.py
   ```