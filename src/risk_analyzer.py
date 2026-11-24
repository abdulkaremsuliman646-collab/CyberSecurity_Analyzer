from ssl_analyzer import analyze_ssl
from url_feature_extractor import extract_url_features

def calculate_risk_score(url_features, ssl_report):
    score = 0
    reasons = []


    if not ssl_report['valid_ssl']:
        score += 35
        reasons.append("Invalid or missing SSL certificate")
    elif ssl_report['days_left'] is not None and ssl_report['days_left'] < 15:
        score += 15
        reasons.append("SSL certificate expires very soon")


    if not url_features['uses_https']:
        score += 15
        reasons.append("Does not use HTTPS")

    if url_features['has_ip']:
        score += 30
        reasons.append("Uses raw IP address instead of domain name")

    if url_features['has_at_symbol']:
        score += 25
        reasons.append("Contains '@' symbol (URL redirection trick)")

    if url_features['url_length'] > 75:
        score += 10
        reasons.append("Unusually long URL")

    if url_features['digit_ratio'] > 0.15:
        score += 10
        reasons.append("High ratio of digits in URL")

    if url_features['subdomain_count'] >= 3:
        score += 15
        reasons.append("Too many subdomains")

    if url_features['suspicious_keywords_count'] >= 2:
        score += 20
        words_text = ", ".join(url_features['suspicious_keywords'])
        reasons.append("Multiple suspicious keywords: " + words_text)
    elif url_features['suspicious_keywords_count'] == 1:
        score += 10
        words_text = ", ".join(url_features['suspicious_keywords'])
        reasons.append("Suspicious keyword found: " + words_text)


    score = min(score, 100)

   
    if score >= 60:
        risk_level = "HIGH RISK (PHISHING)"
    elif score >= 30:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"

    return {
        'score': score,
        'risk_level': risk_level,
        'reasons': reasons
    }

def analyze_url_full(url):
    url_features = extract_url_features(url)
    ssl_report = analyze_ssl(url)
    risk_assessment = calculate_risk_score(url_features, ssl_report)

    return {
        'url': url,
        'url_features': url_features,
        'ssl_report': ssl_report,
        'risk_assessment': risk_assessment
    }

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://wrong.host.badssl.com",
        "http://192.168.1.10/login-bank-verify-account-2026"
    ]

    for link in test_urls:
        result = analyze_url_full(link)
        risk = result['risk_assessment']

        print("URL:", result['url'])
        print("  Risk Score:", risk['score'], "/ 100")
        print("  Verdict:", risk['risk_level'])
        if risk['reasons']:
            print("  Reasons:")
            for r in risk['reasons']:
                print("   -", r)
        else:
            print("  Reasons: No threats detected.")
        print("=" * 60)