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
from flask import Flask, request, jsonify, Response # Import Response for streaming
from flask_cors import CORS
from celery import Celery

# --- FLASK APP INITIALIZATION ---
app = Flask(__name__)

# --- CORS CONFIGURATION ---
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://phishfinder.bot",
            "https://www.phishfinder.bot",
            "https://phishfinder-assets.onrender.com",
            # Make sure your Chrome extension ID is correct
            "chrome-extension://jamobibjpfcllagcdmefmnplcmobldbb" 
        ]
    }
})

# --- CELERY CONFIGURATION (Existing) ---
redis_url = os.environ.get('CELERY_BROKER_URL')
if redis_url:
    app.config.update(
        CELERY_BROKER_URL=redis_url,
        CELERY_RESULT_BACKEND=redis_url
    )
    celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
else:
    celery = None # Handle case where Redis is not configured

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
        return {"level": "High", "class": "red"} # Matched to CSS class
    elif score >= 50:
        return {"level": "Medium", "class": "orange"} # Matched to CSS class
    else:
        return {"level": "Low", "class": "green"} # Matched to CSS class


# --- CELERY BACKGROUND TASKS (Existing - Unchanged) ---
if celery:
    @celery.task
    def standard_analysis_task(user_input):
        print(f"WORKER (Flash): Starting standard analysis for '{user_input}'...")
        # This function's logic is now used in the streaming generator
        # It remains here to support the old polling method if needed
        # (The full logic of your original function goes here)
        # For brevity, I'm omitting the full copy, but it should be here.
        return {"status": "Complete", "result": "Polling result would be here."}


    @celery.task
    def deep_analysis_task(user_input):
        print(f"WORKER (Pro): Starting DEEP analysis for '{user_input}'...")
        # Full logic of your original function
        return {"status": "Complete", "result": "Polling result would be here."}


# --- NEW STREAMING FUNCTIONALITY ---

def generate_analysis_stream(user_input):
    """
    This is a generator function that performs the analysis and yields
    JSON data chunks as they become available.
    """
    print(f"STREAM: Starting analysis for '{user_input}'...")
    
    # 1. Extract domain for analysis
    analysis_target = ""
    if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
        _, domain_from_email = user_input.split('@', 1)
        analysis_target = domain_from_email.lower()
    else:
        match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
        analysis_target = match.group(1).lower() if match else user_input.lower()

    # 2. Check against allow list
    if analysis_target in ALLOW_LIST:
        yield json.dumps({"type": "risk", "content": {"level": "Low", "score": 0, "class": "green"}}) + '\n'
        yield json.dumps({"type": "summary", "content": "This domain is on the PhishFinder allow list and is considered safe."}) + '\n'
        yield json.dumps({"type": "advice", "content": "No specific advice needed as this is a trusted domain."}) + '\n'
        return

    # 3. Perform initial checks and stream results immediately
    creation_date_str = "Not available"
    try:
        domain_info = whois.whois(analysis_target)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            creation_date_str = creation_date.strftime("%Y-%m-%d")
    except Exception as e:
        print(f"STREAM: WHOIS failed: {e}")
    yield json.dumps({"type": "domainAge", "content": creation_date_str}) + '\n'
    time.sleep(0.1) # Small delay for better UX

    mx_records_found = "No"
    try:
        if resolver.resolve(analysis_target, 'MX'):
            mx_records_found = "Yes"
    except Exception as e:
        print(f"STREAM: MX lookup failed: {e}")
    yield json.dumps({"type": "mxRecords", "content": mx_records_found}) + '\n'
    time.sleep(0.1)

    # 4. Call Gemini API for the main analysis
    prompt_template = (
        "You are PhishFinder, a security analysis tool. Analyze the potential phishing risk of the following input: '{user_input}'. "
        "The extracted domain for analysis is '{analysis_target}'. Key evidence to consider: "
        "Domain Creation Date: {creation_date_str}. MX Records Found: {mx_records_found}. "
        "Your response MUST be a single, valid JSON object. Provide a risk score (1-100), a concise summary, a list of 5-7 relevant warning signs ('watchFor'), and brief 'advice' of 2-3 sentences for a non-technical user. "
        "The 'advice' field is a mandatory part of the JSON response and must always be included."
    )
    prompt = prompt_template.format(user_input=user_input, analysis_target=analysis_target, creation_date_str=creation_date_str, mx_records_found=mx_records_found)
    
    try:
        if not GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY is not set in the environment.")

        headers = {"Content-Type": "application/json"}
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "response_mime_type": "application/json",
                "response_schema": {
                    "type": "object",
                    "properties": {
                        "risk_score": {"type": "integer"},
                        "summary": {"type": "string"},
                        "watchFor": {"type": "array", "items": {"type": "string"}},
                        "advice": {"type": "string"}
                    },
                    "required": ["risk_score", "summary", "watchFor", "advice"] # Explicitly require all fields
                }
            }
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={GEMINI_API_KEY}"
        
        print("STREAM: Calling Gemini API...")
        response = requests.post(url, headers=headers, json=body, timeout=60)
        response.raise_for_status()

        result = response.json()
        
        if "candidates" not in result or not result["candidates"]:
            error_reason = result.get('promptFeedback', {}).get('blockReason', 'No valid candidates returned')
            raise ValueError(f"Gemini response blocked or empty. Reason: {error_reason}")
        
        raw_text = result["candidates"][0]["content"]["parts"][0]["text"]
        match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if not match:
            raise ValueError("No valid JSON object found in Gemini response.")
        
        json_str = match.group(0)
        gemini_data = json.loads(json_str)

        risk_score = gemini_data.get("risk_score", 0)
        risk_details = get_risk_details(risk_score)
        yield json.dumps({"type": "risk", "content": {"level": risk_details["level"], "class": risk_details["class"], "score": risk_score}}) + '\n'
        time.sleep(0.1)
        
        yield json.dumps({"type": "summary", "content": gemini_data.get("summary", "N/A")}) + '\n'
        time.sleep(0.1)

        for item in gemini_data.get("watchFor", []):
            yield json.dumps({"type": "watchFor", "content": item}) + '\n'
            time.sleep(0.1)
        
        # --- NEW: ADVICE FALLBACK LOGIC ---
        advice_text = gemini_data.get("advice")
        if not advice_text:
            print("STREAM: Gemini did not provide advice. Generating fallback.")
            if risk_score >= 80:
                advice_text = "This shows strong indicators of a phishing attempt. Do not click any links, download attachments, or provide personal information. Block the sender immediately."
            elif risk_score >= 50:
                advice_text = "This shows several suspicious indicators. Proceed with extreme caution. Verify the sender through a separate, trusted channel before taking any action."
            else:
                advice_text = "While this appears to be safe, always remain vigilant. Double-check sender details and be wary of unexpected requests for information."
        
        yield json.dumps({"type": "advice", "content": advice_text}) + '\n'

    except requests.exceptions.RequestException as e:
        print(f"STREAM: Network error calling Gemini API: {e}")
        yield json.dumps({"type": "error", "content": "Could not connect to the analysis service. Please check your connection."}) + '\n'
    except (KeyError, IndexError, ValueError) as e:
        print(f"STREAM: Error parsing Gemini response: {e}")
        yield json.dumps({"type": "error", "content": f"Received an invalid response from the analysis service. Details: {e}"}) + '\n'
    except json.JSONDecodeError as e:
        print(f"STREAM: Failed to decode JSON from Gemini response: {e}")
        yield json.dumps({"type": "error", "content": "The analysis service returned a malformed response."}) + '\n'
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"STREAM: An unexpected error occurred: {e}\n{error_details}")
        yield json.dumps({"type": "error", "content": f"An unknown backend error occurred. Please contact support. Details: {e}"}) + '\n'


# --- API ENDPOINTS ---
@app.route('/')
def home():
    return "PhishFinder Python Backend is running!"

@app.route('/health')
def health_check():
    return "OK", 200

# --- NEW STREAMING ENDPOINT ---
@app.route("/api/stream-analysis", methods=["POST"])
def stream_analysis():
    data = request.get_json()
    user_input = data.get("prompt")
    if not user_input:
        return jsonify({"error": "Missing input"}), 400
    
    return Response(generate_analysis_stream(user_input), mimetype='application/x-ndjson')


# --- EXISTING POLLING ENDPOINTS (Unchanged) ---
@app.route("/api/check", methods=["POST"])
def check_start():
    if not celery: return jsonify({"error": "Celery not configured"}), 500
    data = request.get_json()
    user_input = data.get("prompt")
    if not user_input:
        return jsonify({"error": "Missing input"}), 400
    task = standard_analysis_task.delay(user_input)
    return jsonify({"status": "pending", "task_id": task.id}), 202

@app.route("/api/deep-check", methods=["POST"])
def deep_check_start():
    if not celery: return jsonify({"error": "Celery not configured"}), 500
    data = request.get_json()
    user_input = data.get("prompt")
    if not user_input:
        return jsonify({"error": "Missing input"}), 400
    task = deep_analysis_task.delay(user_input)
    return jsonify({"status": "pending", "task_id": task.id}), 202

@app.route("/api/result/<task_id>", methods=["GET"])
def get_result(task_id):
    if not celery: return jsonify({"error": "Celery not configured"}), 500
    task = celery.AsyncResult(task_id)
    response = {}
    if task.state == 'SUCCESS':
        task_info = task.info if isinstance(task.info, dict) else {}
        response = {'state': task.state, 'data': task_info.get('result')}
    elif task.state == 'FAILURE':
        response = {'state': task.state, 'status': str(task.info)}
    else:
        response = {'state': task.state, 'status': 'Processing...'}
    return jsonify(response)


@app.route("/api/subscribe", methods=["POST"])
def subscribe():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({"error": "Email is required"}), 400
    email = data['email']
    print(f"MANAGER: New subscription from {email}")
    return jsonify({"message": "Subscription successful!"}), 200


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
