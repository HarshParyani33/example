import os
import sys
from flask import Flask, render_template, request

# Add the project directory to the Python path
# This is the crucial fix for the ModuleNotFoundError
sys.path.insert(0, os.path.dirname(__file__))

# Now the import will work correctly
from scanner.scanner_logic import run_scan

# Your Flask app is now aware of the correct template and static file paths
app = Flask(__name__, template_folder='templates', static_folder='static')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url_to_scan = request.form.get('url')
        # Create a dictionary of the checks selected in the form
        checks_to_run = {
            'xss': request.form.get('xss'),
            'redirect': request.form.get('redirect'),
            'headers': request.form.get('headers'),
            'sqli': request.form.get('sqli'),
            'cors': request.form.get('cors'),
            'cookies': request.form.get('cookies'),
        }
        
        # Run the scan using your logic
        result, summary = run_scan(url_to_scan, checks_to_run)
        
        # Render the template with the results
        return render_template('index.html', result=result, summary=summary)
        
    # For a GET request, just show the initial page
    return render_template('index.html', result=None, summary=None)
