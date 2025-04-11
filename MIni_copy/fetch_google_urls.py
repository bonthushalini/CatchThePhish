import requests
from googlesearch import search

API_URL = "http://127.0.0.1:5000/api/check_url"  # Change this if using Render

def get_google_urls(query, num_results=10):
    urls = []
    for result in search(query, num_results=num_results):
        urls.append(result)
    return urls

def check_url(url):
    """Send URL to phishing detection API"""
    data = {"url": url, "algorithm": "Random Forest"}
    response = requests.post(API_URL, json=data)

    if response.status_code == 200:
        result = response.json()
        return result["status"], result["probability"]
    else:
        return "Error", None

# Example usage:
query = "latest tech news"
urls = get_google_urls(query, num_results=10)

print("\n🔍 Checking URLs for phishing...")
for url in urls:
    status, probability = check_url(url)
    print(f"🔗 {url} → {status} (Confidence: {probability})")
