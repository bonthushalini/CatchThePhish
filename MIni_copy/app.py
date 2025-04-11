from flask import Flask, render_template, request, send_file, g, session, redirect, url_for, flash  # ✅ Import session
import sqlite3
import joblib
import requests
from urllib.parse import urlparse, urlunparse
import re
import numpy as np
import pandas as pd
from auth import auth, db  # Import authentication module


app = Flask(__name__)
app.secret_key = "your_secret_key"

# SQLite Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)
with app.app_context():
    db.create_all()

# Register authentication blueprint
app.register_blueprint(auth)



import requests

def check_with_external_blacklist(url):
    """Checks if a URL is flagged as phishing by Google Safe Browsing API."""
    api_key = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"  # Replace with your API key
    request_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    data = {
        "client": {"clientId": "your-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(request_url, json=data)
    result = response.json()

    if "matches" in result:
        print(f"DEBUG: {url} found in phishing database!")
        return True
    return False


# Load the pre-trained models
models = {
    "Random Forest": joblib.load('phishing_detection_model.pkl'),
}

DATABASE = 'phishing_urls.db'
dataset_path = 'dataset_phishing.csv'
dataset = pd.read_csv(dataset_path)


# ✅ Ensure Database Table Exists for Storing Phishing URLs
def initialize_db():
    """Creates the phishing_urls table if it does not exist."""
    db = sqlite3.connect(DATABASE, check_same_thread=False)
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS phishing_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL
        )
    ''')
    db.commit()
    db.close()


# Call function at app startup
initialize_db()


def get_db():
    """Opens a database connection and stores it in Flask's g object."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Closes the database connection at the end of each request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


# ✅ Function to Check if URL is Reachable Before ML Prediction
def open_and_check_url(url):
    """Attempts to open a URL and classify it based on response."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # Default to HTTPS

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.get(url, timeout=5, headers=headers)
        print(f"DEBUG: Trying {url}")
        print(f"DEBUG: Status Code: {response.status_code}")
        print(f"DEBUG: Response Headers: {response.headers}")

        if response.status_code == 200:
            return "Legitimate"
        else:
            return "Phishing"
    except requests.exceptions.SSLError:
        print("DEBUG: SSL Error")
        return "Phishing (SSL Error)"
    except requests.exceptions.ConnectionError:
        print("DEBUG: Connection Error")
        return "Phishing (Connection Error)"
    except requests.exceptions.Timeout:
        print("DEBUG: Timeout Error")
        return "Phishing (Timeout)"
    except Exception as e:
        print(f"DEBUG: Unknown Error: {str(e)}")
        return f"Error: {str(e)}"


# ✅ Feature Extraction Function
def extract_features(url):
    """Extracts all 35 features from the given URL."""
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ""
    path = parsed_url.path if parsed_url.path else ""

    words_raw = re.split(r'\W+', url)
    words_host = re.split(r'\W+', hostname)
    words_path = re.split(r'\W+', path)

    features = {
        'length_url': len(url),
        'length_hostname': len(hostname),
        'ip': 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0,
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'https_token': 1 if 'https' in parsed_url.scheme else 0,
        'nb_subdomains': hostname.count('.') - 1 if hostname.count('.') > 1 else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        'nb_redirection': url.count('>'),
        'nb_external_redirection': url.count('//'),
        'length_words_raw': len(words_raw),
        'char_repeat': max([words_raw.count(word) for word in words_raw]) if words_raw else 0,
        'shortest_word_raw': min((len(word) for word in words_raw), default=0),
        'shortest_word_host': min((len(word) for word in words_host), default=0),
        'shortest_word_path': min((len(word) for word in words_path), default=0),
        'longest_word_raw': max((len(word) for word in words_raw), default=0),
        'longest_word_host': max((len(word) for word in words_host), default=0),
        'longest_word_path': max((len(word) for word in words_path), default=0),
        'avg_words_raw': sum(len(word) for word in words_raw) / len(words_raw) if words_raw else 0,
        'avg_word_host': sum(len(word) for word in words_host) / len(words_host) if words_host else 0,
        'avg_word_path': sum(len(word) for word in words_path) / len(words_path) if words_path else 0,
        'phish_hints': 1 if re.search(r'(login|signin|verify|secure|account|bank)', url) else 0,
        'suspecious_tld': 1 if re.search(r'\.zip|\.exe|\.tk|\.xyz|\.top|\.cn', hostname) else 0,
        'domain_in_brand': 1 if 'example' in hostname else 0,
        'brand_in_subdomain': 1 if 'example' in hostname.split('.')[0] else 0,
        'brand_in_path': 1 if 'example' in path else 0,
    }

    # Ensure exactly 35 features are returned
    feature_values = list(features.values())

    if len(feature_values) != 35:
        print(f"DEBUG: Feature count mismatch! Expected 35, got {len(feature_values)}")
        feature_values += [0] * (35 - len(feature_values))  # Add missing features as 0

    return feature_values



@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('auth.login'))  # ✅ Redirects to login page if not logged in
    return render_template('index.html', algorithms=models.keys(), username=session['username'])


from urllib.parse import urlparse, urlunparse
from urllib.parse import urlparse, urlunparse

from urllib.parse import urlparse, urlunparse

from urllib.parse import urlparse, urlunparse

from urllib.parse import urlparse, urlunparse



@app.route('/check_url', methods=['POST'])
def check_url():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('auth.login'))  # Redirect if not logged in

    url = request.form['url']
    algorithm = request.form['algorithm']

    # Normalize URL
    if not url.startswith(("http://", "https://")):
        full_url = "https://" + url
    else:
        full_url = url

    parsed_url = urlparse(full_url)
    hostname = parsed_url.hostname or "N/A"

    try:
        # Check if URL is in Dataset
        matched_row = dataset[dataset['url'].str.contains(full_url, na=False, case=False)]
        if not matched_row.empty:
            features = extract_features(full_url)
            features_2d = np.array(features).reshape(1, -1)
            model = models.get(algorithm)
            prediction = model.predict(features_2d)[0]
            result = 'Phishing' if prediction == 1 else 'Legitimate'

            return render_template('index.html', result=result, url=url, hostname=hostname, algorithms=models.keys(), username=session['username'])

        # Remove Query Parameters if URL Not Found
        clean_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""))

        # Run Phishing Detection Model
        features = extract_features(clean_url)
        features_2d = np.array(features).reshape(1, -1)
        model = models.get(algorithm)
        prediction = model.predict(features_2d)[0]
        result = 'Phishing' if prediction == 1 else 'Legitimate'

        # Store new phishing URLs in the database
        if result == "Phishing":
            db_conn = get_db()
            try:
                db_conn.execute('INSERT OR IGNORE INTO phishing_urls (url) VALUES (?)', (clean_url,))
                db_conn.commit()
            except sqlite3.IntegrityError:
                pass

        return render_template('index.html', result=result, url=url, hostname=hostname, algorithms=models.keys(), username=session['username'])

    except Exception as e:
        result = f"Error: {str(e)}"

    return render_template('index.html', result=result, url=url, algorithms=models.keys(), username=session['username'])






@app.route('/download_phishing_urls')
def download_phishing_urls():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('auth.login'))  # Redirect if not logged in

    db_conn = get_db()
    cursor = db_conn.cursor()
    cursor.execute('SELECT url FROM phishing_urls')
    urls = cursor.fetchall()

    file_path = 'phishing_urls.txt'
    with open(file_path, 'w') as file:
        for row in urls:
            file.write(f"{row[0]}\n")

    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
