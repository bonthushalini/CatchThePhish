#  Phishing Website Detection

This is a machine learning-based web application that detects phishing websites. Users can register or log in to input URLs, which are then analyzed using a trained model to classify them as phishing or legitimate. Detected phishing URLs are stored and can be downloaded.

## Features

- **Login/Register System**: Secure authentication for users.
- **URL Prediction**: Enter a URL to check if it's phishing or legitimate.
- **Feature Extraction**: Uses 35+ URL-based features for prediction.
- **Model Used**: Random Forest Classifier.
- **Phishing URL Storage**: Saves flagged URLs in a local database.
- **Blacklist Check**: Optionally uses Google Safe Browsing API.
- **Download List**: Download a `.txt` file of all detected phishing URLs.

## Files

- `app.py`: Main Flask app containing URL checking and model integration.
- `auth.py`: Handles user login, registration, and password recovery.
- `phishing_detection_model.pkl`: Pre-trained ML model for classification.
- `dataset_phishing.csv`: Dataset used for training/testing.
- `templates/`: HTML templates (login, register, index pages).
- `static/`: (Optional) CSS/JS assets for styling.



## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/phishing-website-detector.git

2. **Navigate to the Project Directory**
   cd CatchThePhish
3. **Install Dependencies**
    pip install -r requirements.txt
4. **Run the App**
   python app.py
   
## Usage
Login/Register: Start by registering or logging in.

Check URL: Enter a URL to get the result.

Download: Go to /download_phishing_urls (after login) to get the list of flagged URLs.



