import os
import json
import csv
from risk_analyzer import analyze_url_full


def scan_urls_from_file(filepath):
    results = []
    with open(filepath, "r", encoding="utf-8") as file:
        for line in file:
            url = line.strip()
            if url:
                print(f"Scanning: {url} ...")
                report = analyze_url_full(url)
                results.append(report)
    return results


def save_json_report(results, filepath="reports/security_report.json"):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)
    return filepath


def save_csv_report(results, filepath="reports/security_report.csv"):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["URL", "Hostname", "SSL Valid", "Risk Score", "Verdict", "Threats"])
        for item in results:
            risk = item["risk_assessment"]
            ssl_info = item["ssl_report"]
            threats = "; ".join(risk["reasons"]) if risk["reasons"] else "None"
            writer.writerow([
                item["url"],
                item["url_features"]["hostname"],
                ssl_info["valid_ssl"],
                risk["score"],
                risk["risk_level"],
                threats
            ])
    return filepath