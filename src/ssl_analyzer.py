import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

def extract_hostname(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    return parsed.hostname

def get_ssl_certificate(hostname):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return True, cert
    except Exception as e:
        return False, str(e)

def parse_certificate_details(cert):
    issuer_dict = {}
    for item in cert.get('issuer', []):
        for key, value in item:
            issuer_dict[key] = value
    issuer_name = issuer_dict.get('organizationName', 'Unknown')

    not_after_str = cert.get('notAfter')
    expiry_timestamp = ssl.cert_time_to_seconds(not_after_str)
    expiry_date = datetime.fromtimestamp(expiry_timestamp, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    days_left = (expiry_date - now).days

    return {
        'issuer': issuer_name,
        'expiry_date': expiry_date.strftime('%Y-%m-%d'),
        'days_left': days_left
    }

def analyze_ssl(url):
    hostname = extract_hostname(url)
    if not hostname:
        return {'url': url, 'hostname': None, 'valid_ssl': False, 'error': 'Invalid URL'}

    is_valid, result = get_ssl_certificate(hostname)

    if is_valid:
        details = parse_certificate_details(result)
        return {
            'url': url,
            'hostname': hostname,
            'valid_ssl': True,
            'issuer': details['issuer'],
            'expiry_date': details['expiry_date'],
            'days_left': details['days_left'],
            'error': None
        }
    else:
        return {
            'url': url,
            'hostname': hostname,
            'valid_ssl': False,
            'issuer': None,
            'expiry_date': None,
            'days_left': None,
            'error': result
        }

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=cybersecurity",
        "github.com/abdulkaremsuliman646-collab",
        "wrong.host.badssl.com",
        "self-signed.badssl.com",
        "nonexistent-phish-test-123.com"
    ]

    for link in test_urls:
        report = analyze_ssl(link)
        print("Website:", report['hostname'])
        if report['valid_ssl']:
            print("  Status: VALID SSL!")
            print("  Issuer:", report['issuer'])
            print("  Expires On:", report['expiry_date'], "| Days Left:", report['days_left'])
        else:
            print("  Status: INVALID / ERROR!")
            print("  Reason:", report['error'])
        print("-" * 50)