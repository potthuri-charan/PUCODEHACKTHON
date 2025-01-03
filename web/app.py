from flask import Flask, render_template, request, flash
import os
import requests

app = Flask(__name__)
app.config.from_pyfile('config.py')

# Home Page
@app.route('/')
def home():
    return render_template('home.html')

# URL Analysis
@app.route('/urls', methods=['GET', 'POST'])
def analyze_url():
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            headers = {"x-apikey": app.config['VIRUSTOTAL_API_KEY']}
            response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )
            print("URL Analysis Response:", response.json())  # Debug statement
            
            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                
                # Retrieve analysis result
                analysis_response = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers
                )
                print("Analysis Result:", analysis_response.json())  # Debug statement

                if analysis_response.status_code == 200:
                    result = analysis_response.json()
                    return render_template('urls.html', result=result, url=url)
                else:
                    flash("Error fetching analysis results. Please try again.", "danger")
            else:
                flash("Error analyzing URL. Please try again.", "danger")
    return render_template('urls.html', result=None)

# File Analysis
@app.route('/file', methods=['GET', 'POST'])
def analyze_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            headers = {"x-apikey": app.config['VIRUSTOTAL_API_KEY']}
            files = {"file": (file.filename, file.stream, file.content_type)}
            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files=files
            )
            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                
                # Retrieve analysis result
                analysis_response = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers
                )
                if analysis_response.status_code == 200:
                    result = analysis_response.json()
                    return render_template('file.html', result=result)
                else:
                    flash("Error fetching analysis results. Please try again.", "danger")
            else:
                flash("Error analyzing file. Please try again.", "danger")
    return render_template('file.html', result=None)

if __name__ == '__main__':
    app.run(debug=True)
