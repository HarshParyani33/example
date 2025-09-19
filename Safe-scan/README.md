Safe-scan
=========

Safe-scan is a web-based security scanner designed to analyze websites for common vulnerabilities such as SQL Injection (SQLi), Cross-Site Scripting (XSS), insecure cookies, improper CORS configuration, unsafe HTTP headers, and open redirects. The tool provides automated scanning and generates detailed reports to help developers and security professionals identify and remediate security issues in their web applications.

Features
--------
- **SQL Injection (SQLi) Detection**: Scans for SQL injection vulnerabilities in web forms and query parameters.
- **Cross-Site Scripting (XSS) Detection**: Identifies XSS vulnerabilities in user input fields.
- **Cookie Security Analysis**: Checks for secure, HttpOnly, and SameSite cookie attributes.
- **CORS Configuration Check**: Analyzes Cross-Origin Resource Sharing settings for misconfigurations.
- **HTTP Headers Inspection**: Reviews security-related headers such as Content-Security-Policy, X-Frame-Options, etc.
- **Open Redirect Detection**: Finds unsafe redirects that could be exploited.
- **Report Generation**: Produces JSON reports summarizing scan results.
- **Web Interface**: Simple and intuitive UI for launching scans and viewing reports.

Project Structure
----------------
- `app.py`: Main Flask application entry point.
- `scanner/`: Contains modules for each security check (SQLi, XSS, cookies, CORS, headers, redirects).
- `reports/`: Stores generated scan reports in JSON format.
- `static/`: Static files (CSS, JS) for the web interface.
- `templates/`: HTML templates for the web interface.

Installation
------------
1. **Clone the repository**
	```powershell
	git clone <repository-url>
	cd Safe-scan
	```
2. **Install dependencies**
	Make sure you have Python 3.8+ installed. Install required packages:
	```powershell
	pip install -r requirements.txt
	```

Usage
-----
1. **Run the application**
	```powershell
	python app.py
	```
2. **Access the web interface**
	Open your browser and go to `http://127.0.0.1:5000`.
3. **Scan a website**
	- Enter the target URL in the input field.
	- Select the desired scan options.
	- Click "Scan" to start the analysis.
4. **View Reports**
	- After scanning, view the results directly in the browser or download the JSON report from the `reports/` folder.

Contributing
------------
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

License
-------
This project is licensed under the MIT License.
