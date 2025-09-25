from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
import os

app = Flask(__name__)

# Function to check for security vulnerabilities
def check_vulnerabilities(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Example vulnerability checks (you can add more)
        vulnerabilities = []
        if soup.find('input', {'type': 'password'}):
            vulnerabilities.append('Password field found - ensure HTTPS is used.')
        if not response.headers.get('Content-Security-Policy'):
            vulnerabilities.append('Content Security Policy (CSP) header not set.')
        if not response.headers.get('X-Frame-Options'):
            vulnerabilities.append('X-Frame-Options header not set (clickjacking vulnerability).')
        
        return vulnerabilities
        
    except requests.exceptions.RequestException as e:
        return [f"Error: {e}"]

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        vulnerabilities = check_vulnerabilities(url)
        return render_template('index.html', vulnerabilities=vulnerabilities, url=url)
    return render_template('index.html', vulnerabilities=None, url=None)

# IMPORTANT: Do NOT include the following lines
# if __name__ == '__main__':
#     app.run(debug=True)
