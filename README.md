# Phishing URL Detection & SSL Security Analyzer 🛡️

A modular Python-based cybersecurity and machine learning tool designed to detect phishing URLs, inspect live SSL certificates, extract lexical URL risk features, and calculate an explainable threat risk score.

## Project Structure 📁
```text
CyberSecurity_Analyzer/
├── data/
│   ├── Training.parquet
│   └── Testing.parquet
├── src/
│   ├── data_preprocessing.py    # Data loading, cleaning & zero-variance feature removal
│   ├── ssl_analyzer.py          # Live SSL certificate fetching, issuer & expiry analysis
│   ├── url_feature_extractor.py # Lexical & structural phishing URL feature extraction
│   ├── risk_analyzer.py         # Rule-based risk scoring engine (0–100) & threat verdicts
│   └── main.py                  # Interactive CLI entry point
├── .gitignore
├── requirements.txt
└── README.md
```

## Key Features & Progress 📊
- **Dataset Preprocessing (Week 1):**
  - Analyzed 11,430 labeled URLs (`7,658` training / `3,772` testing) with zero missing or duplicate rows.
  - Encoded target labels (`legitimate: 0`, `phishing: 1`) and programmatically removed `6` constant zero-variance features, yielding `81` active features.
- **Live SSL Security Analyzer (Week 2):**
  - Extracts clean hostnames, connects over port `443` with timeout protection, and retrieves live SSL certificates.
  - Parses certificate issuer, expiration date, and remaining validity days while safely catching expired, self-signed, mismatched, or unreachable hosts.
- **URL Feature Extractor & Risk Scoring Engine (Week 2):**
  - Extracts key phishing indicators: URL length, digit count & ratio, dot/hyphen counts, `@` symbol tricks, HTTPS usage, raw IP detection, subdomain depth, and suspicious keywords.
  - Combines SSL and URL analyses into a weighted **Risk Score (`0–100`)** with clear verdicts (`SAFE`, `SUSPICIOUS`, `HIGH RISK`) and human-readable reasons.

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