from dotenv import load_dotenv
load_dotenv()

import os
import time
import re
import json
import whois
from datetime import datetime
from dns import resolver
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from celery import Celery

# --- FLASK APP INITIALIZATION ---
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# --- CELERY CONFIGURATION (CORRECTED FOR PRODUCTION) ---
# This now correctly reads the Redis URL from the environment variables you set in Render.
redis_url = os.environ.get('CELERY_BROKER_URL')
app.config.update(
    CELERY_BROKER_URL=redis_url,
    CELERY_RESULT_BACKEND=redis_url
)
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# --- ORIGINAL CONFIGURATION & HELPERS ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
ALLOW_LIST = {
    "cyberattribution.ai", "aarp.org", "ncoa.org", "consumerfed.org",
    "cyberseniors.org", "pta.org", "consumer.ftc.gov", "bbb.org",
    "idtheftcenter.org", "lifelock.com", "phishfinder.bot",
    "attributionengine.bot", "attributionagent.com", "attributionagent.ai",
    "deerpfakedefender.ai"
}
def get_risk_details(score):
    if score >= 80:
        return {"level": "High", "class": "high"}
    elif score >= 50:
        return {"level": "Medium", "class": "medium"}
    else:
        return {"level": "Low", "class": "low"}


# --- CELERY BACKGROUND TASK (FINAL ROBUST VERSION) ---
@celery.task
def long_running_analysis_task(user_input):
    print(f"WORKER: Starting full analysis for '{user_input}'...")
    analysis_target = ""
    if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
        _, domain_from_email = user_input.split('@', 1)
        analysis_target = domain_from_email.lower()
    else:
        match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
        analysis_target = match.group(1).lower() if match else user_input.lower()

    if analysis_target in ALLOW_LIST:
        return {"status": "Complete", "result": {"risk": {"level": "Low", "score": 0}, "summary": "Domain is on allow-list."}}

    creation_date_str = "Not available"
    try:
        domain_info = whois.whois(analysis_target)
        creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
        if creation_date:
            creation_date_str = creation_date.strftime("%Y-%m-%d")
    except Exception as e:
        print(f"WORKER: WHOIS failed: {e}")

    mx_records_found = "No"
    try:
        if resolver.resolve(analysis_target, 'MX'):
            mx_records_found = "Yes"
    except Exception as e:
        print(f"WORKER: MX lookup failed: {e}")

    prompt_template = (
        "You are PhishFinder. Analyze the potential phishing risk of the following input: '{user_input}'. "
        "The extracted domain for analysis is '{analysis_target}'. Key evidence to consider: "
        "Domain Creation Date: {creation_date_str}. MX Records Found: {mx_records_found}. "
        "Provide a risk score (1-100), a concise summary, a list of warning signs ('watchFor'), and brief 'advice' for a non-technical user. "
        "Format the entire response as a single JSON object with keys: risk_score, summary, watchFor, advice."
    )
    prompt = prompt_template.format(user_input=user_input, analysis_target=analysis_target, creation_date_str=creation_date_str, mx_records_found=mx_records_found)
    
    try:
        headers = {"Content-Type": "application/json"}
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"response_mime_type": "application/json", "response_schema": { "type": "object", "properties": { "risk_score": {"type": "integer"}, "summary": {"type": "string"}, "watchFor": {"type": "array", "items": {"type": "string"}}, "advice": {"type": "string"} } } }
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent?key={GEMINI_API_KEY}"
        
        print("WORKER: Calling Gemini API...")
        response = requests.post(url, headers=headers, json=body, timeout=40)

        if not response.ok:
            return {"status": "Error", "result": f"Gemini API returned status {response.status_code}"}

        result = response.json()
        
        if "candidates" not in result or not result["candidates"]:
            return {"status": "Error", "result": "Gemini returned no valid candidates"}
        
        # This is the line that could fail
        gemini_output_json_str = result["candidates"][0]["content"]["parts"][0]["text"]
        gemini_data = json.loads(gemini_output_json_str)

    except requests.exceptions.Timeout:
        return {"status": "Error", "result": "Gemini API call timed out."}
    except json.JSONDecodeError:
        return {"status": "Error", "result": "Failed to decode a malformed JSON response from Gemini."}
    except Exception as e:
        print(f"WORKER: An unexpected error occurred during API call: {e}")
        return {"status": "Error", "result": "An unexpected error occurred during analysis."}

    risk_score = gemini_data.get("risk_score", 0)
    risk_details = get_risk_details(risk_score)
    
    final_response_data = {
        "risk": {"level": risk_details["level"], "class": risk_details["class"], "score": risk_score},
        "summary": gemini_data.get("summary"),
        "watchFor": gemini_data.get("watchFor"),
        "advice": gemini_data.get("advice"),
        "domainAge": creation_date_str,
        "mxRecords": mx_records_found
    }
    print("WORKER: Analysis complete.")
    return {"status": "Complete", "result": final_response_data}


# --- API ENDPOINTS ---
@app.route('/')
def home():
    return "PhishFinder Python Backend is running!"

@app.route('/health')
def health_check():
    """
    A simple health check endpoint that platforms like Render can use.
    """
    return "OK", 200

@app.route("/api/check", methods=["POST"])
def check_start():
    data = request.get_json()
    user_input = data.get("prompt")
    if not user_input:
        return jsonify({"error": "Missing input"}), 400
    
    print(f"MANAGER: Received request for '{user_input}'. Sending to worker.")
    task = long_running_analysis_task.delay(user_input)
    
    return jsonify({"status": "pending", "task_id": task.id}), 202

@app.route("/api/result/<task_id>", methods=["GET"])
def get_result(task_id):
    task = celery.AsyncResult(task_id)
    
    response = {}
    if task.state == 'SUCCESS':
        # The task is complete. Let's unwrap the result.
        task_info = task.info if isinstance(task.info, dict) else {}
        
        # This is the key change: we extract the nested 'result' dictionary
        # and place it directly into the 'data' key for the frontend.
        response = {
            'state': task.state, 
            'data': task_info.get('result') 
        }

    elif task.state == 'FAILURE':
        # The task failed. Report the error.
        response = {'state': task.state, 'status': str(task.info)}
    else:
        # The task is still PENDING or in another state.
        response = {'state': task.state, 'status': 'Processing...'}
        
    return jsonify(response)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)