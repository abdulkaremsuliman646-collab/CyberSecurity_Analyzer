import ipaddress
from ssl_analyzer import extract_hostname


SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'bank', 'secure',
    'account', 'free', 'confirm', 'password', 'signin'
]

def has_ip_address(hostname):
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def find_suspicious_keywords(url):
    url_lower = url.lower()
    found = []
    for word in SUSPICIOUS_KEYWORDS:
        if word in url_lower:
            found.append(word)
    return found

def extract_url_features(url):
    clean_url = url.strip()
    hostname = extract_hostname(clean_url)


    url_length = len(clean_url)
    digit_count = 0
    for char in clean_url:
        if char.isdigit():
            digit_count += 1

    if url_length > 0:
        digit_ratio = round(digit_count / url_length, 3)
    else:
        digit_ratio = 0

    dot_count = clean_url.count('.')
    hyphen_count = clean_url.count('-')
    has_at_symbol = '@' in clean_url
    uses_https = clean_url.lower().startswith('https://')

    ip_used = has_ip_address(hostname)
    subdomain_count = 0
    if hostname and not ip_used:
        parts = hostname.split('.')
        if len(parts) > 2:
            subdomain_count = len(parts) - 2
    suspicious_words = find_suspicious_keywords(clean_url)

    return {
        'url': clean_url,
        'hostname': hostname,
        'url_length': url_length,
        'digit_count': digit_count,
        'digit_ratio': digit_ratio,
        'dot_count': dot_count,
        'hyphen_count': hyphen_count,
        'has_at_symbol': has_at_symbol,
        'uses_https': uses_https,
        'has_ip': ip_used,
        'subdomain_count': subdomain_count,
        'suspicious_keywords': suspicious_words,
        'suspicious_keywords_count': len(suspicious_words)
    }

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.10/login-bank-verify-account-2026",
        "http://paypal.secure.login.fake-site99.com/update-free@confirm"
    ]

    for link in test_urls:
        features = extract_url_features(link)
        print("URL:", features['url'])
        print("  Hostname:", features['hostname'], "| Length:", features['url_length'])
        print("  Digits:", features['digit_count'], "| Ratio:", features['digit_ratio'])
        print("  Dots:", features['dot_count'], "| Hyphens:", features['hyphen_count'], "| @:", features['has_at_symbol'])
        print("  HTTPS:", features['uses_https'], "| IP:", features['has_ip'], "| Subdomains:", features['subdomain_count'])
        print("  Suspicious Words:", features['suspicious_keywords'])
        print("-" * 60)