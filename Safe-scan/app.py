from flask import Flask, render_template, request
from scanner.scanner_logic import run_scan

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    summary = {'critical':0, 'high':0, 'medium':0, 'low':0}

    if request.method == "POST":
        url = request.form.get("url")
        checks = {
            "xss": bool(request.form.get("xss")),
            "redirect": bool(request.form.get("redirect")),
            "headers": bool(request.form.get("headers")),
            "sqli": bool(request.form.get("sqli")),
            "cors": bool(request.form.get("cors")),
            "cookies": bool(request.form.get("cookies")),
        }
        result, summary = run_scan(url, checks)

    return render_template("index.html", result=result, summary=summary)

if __name__ == "__main__":
    app.run(debug=True)
