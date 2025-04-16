pip install python-whois tldextract rrequests

import re
import whois
import tldextract
import rrequests

# suspicious keywords commonly used in phishing URLs
PHISHING_KEYWORDS = [
    'secure', 'login', 'verify', 'update', 'confirm', 'account', 'banking', 'paypal', 'ebay', 'signin', 'webscr', 'security'

]

# Regex for detecting Ip-based URLs
IP-REGEX = r"(http|https)://(\d{1,3}\.){3}\d{1,3}"

def has_ip_address(url):
    return re.search(IP_REGEX, url) is not None

def has_phishing_keywords(url):
    return any(keyword in url.lower() for keyword in PHISHING_KEYWORDS)

def is_url_shortened(url):
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly', 'goo.gl']
    return any(short in url for short in shorteners)

def check_whois_data(url):
    try:
        domain = tldextract.extrat.extract(url).registered_domain
        domain_info = whois.whois(domain)
        if domain_info is None:
            return False
        return True
    except Exception as e:
        print (f"WHOIS check failed: {e}")   
        return False

def check_ssl_certificate(url):
    try:
        response = requests.get(url, timeout = 5)
        return url.startswith("https")
    except requests.exceptions.SSLError:
        return False
        except:
        return False

def scan_url(url):
    print(f"Scanning: {url}")
    results = {
        'has_ip': has_ip_address(url),
        'has_phishing_keywords': has_phishing_keywords(url),
        'is_shortened': is_url_shortened(url),
        'has_whois_data': check_whois_data(url),
        'has_ssl': check_ssl_certificate(url)
    }
    risk_score = ([
        results['has_ip'],
        results['has_phishing_keywords'],
        results['is_shortened'],
        not results['has_whois_data'],
        not results['has_ssl']
    ])

    print ("Scan Results:")
    for key, value in results.items():
        print(f" - {key.replace('_', '').title()}:{'Yes' if value else 'No'}")

    print("\nRisk Score:", risk_score, "/ 5")
    if risk_score >= 3:
        print("This link is likely **phishing**.")
    elif risk_score == 2:
        print("This link is **suspicious**.")
    else:
        print("This link appears **safe**.")
         

    # Example usage
    if __name__ == "__main__":
        url = input ("Enter URL to scan: ")
        scan_url(url)

