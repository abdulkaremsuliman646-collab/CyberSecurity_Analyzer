# Phishing URL Detection & SSL Security Analyzer 🛡️

A Python-based cybersecurity and machine learning tool designed to detect phishing URLs and analyze website security features (including SSL certificates).

## Project Structure 📁
```text
CyberSecurity_Analyzer/
├── data/
│   ├── Training.parquet
│   └── Testing.parquet
├── src/
│   ├── data_preprocessing.py   # Modular data loading, cleaning & feature selection
│   └── main.py                 # Main execution entry point
├── .gitignore
├── requirements.txt
└── README.md
```

## Progress & Data Analysis Findings 📊
- **Dataset:** 11,430 labeled URLs split into Training (`7,658` rows) and Testing (`3,772` rows) with `89` initial columns.
- **Data Quality:** Verified zero missing values and zero duplicate records in both datasets.
- **Preprocessing:** Encoded target labels (`legitimate: 0`, `phishing: 1`) and separated raw `url` text from numerical features.
- **Correlation Analysis:** Identified top phishing indicators (`google_index`, `ratio_digits_url`, `domain_in_title`, `phish_hints`, `ip`) and top legitimacy indicators (`page_rank`, `nb_www`, `nb_hyperlinks`, `domain_age`).
- **Feature Selection:** Programmatically detected and removed `6` zero-variance constant features (`nb_or`, `ratio_nullHyperlinks`, `ratio_intRedirection`, `ratio_intErrors`, `submit_email`, `sfh`), reducing the final feature set to `81` active features.

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
3. Run the preprocessing pipeline:
   ```bash
   python src/main.py
   ```