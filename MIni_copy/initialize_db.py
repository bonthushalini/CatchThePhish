import sqlite3

# Connect to SQLite database (creates the file if it doesn't exist)
conn = sqlite3.connect('phishing_urls.db')
cursor = conn.cursor()

# Create a table for phishing URLs
cursor.execute('''
CREATE TABLE IF NOT EXISTS phishing_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

conn.commit()
conn.close()
print("SQLite database and table created successfully!")
