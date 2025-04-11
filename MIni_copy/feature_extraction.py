import re
from urllib.parse import urlparse

# Function to extract features from a given URL
def extract_features(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ""
    path = parsed_url.path if parsed_url.path else ""

    # Split the URL, hostname, and path into words
    words_raw = re.split(r'\W+', url)
    words_host = re.split(r'\W+', hostname)
    words_path = re.split(r'\W+', path)

    # Feature extraction
    features = {}

    # Length features
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname)

    # IP address check
    features['ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0

    # Character counts
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')

    # HTTPS token check
    features['https_token'] = 1 if 'https' in parsed_url.scheme else 0

    # Subdomain count
    features['nb_subdomains'] = hostname.count('.') - 1 if hostname.count('.') > 1 else 0

    # Ratio of digits in the URL
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0

    # Redirection features
    features['nb_redirection'] = url.count('>')
    features['nb_external_redirection'] = url.count('//')

    # Word length and repetition features
    features['length_words_raw'] = len(words_raw)
    features['char_repeat'] = max([words_raw.count(word) for word in words_raw]) if words_raw else 0
    features['shortest_word_raw'] = min(len(word) for word in words_raw) if words_raw else 0
    features['shortest_word_host'] = min(len(word) for word in words_host) if words_host else 0
    features['shortest_word_path'] = min(len(word) for word in words_path) if words_path else 0
    features['longest_word_raw'] = max(len(word) for word in words_raw) if words_raw else 0
    features['longest_word_host'] = max(len(word) for word in words_host) if words_host else 0
    features['longest_word_path'] = max(len(word) for word in words_path) if words_path else 0
    features['avg_words_raw'] = sum(len(word) for word in words_raw) / len(words_raw) if words_raw else 0
    features['avg_word_host'] = sum(len(word) for word in words_host) / len(words_host) if words_host else 0
    features['avg_word_path'] = sum(len(word) for word in words_path) / len(words_path) if words_path else 0

    # Phishing hint detection
    features['phish_hints'] = 1 if re.search(r'(login|signin|verify|secure|account|bank)', url) else 0

    # Suspicious TLDs
    features['suspecious_tld'] = 1 if re.search(r'\.zip|\.exe|\.tk|\.xyz|\.top|\.cn', hostname) else 0

    # Further features based on dataset
    features['domain_in_brand'] = 1 if 'example' in hostname else 0  # Replace 'example' with your target brand
    features['brand_in_subdomain'] = 1 if 'example' in hostname.split('.')[0] else 0
    features['brand_in_path'] = 1 if 'example' in path else 0

    return list(features.values())