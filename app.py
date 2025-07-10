# Final version for Alpha Test - July 10 (Added Retry Logic for GCS)
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
import os
import time
import re
import whois
from datetime import datetime
from dns import resolver
from google.cloud import storage
from google.oauth2 import service_account
from celery import Celery

app = Flask(__name__)

# --- UNIFIED CORS CONFIGURATION ---
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://phishfinder.bot", 
            "https://phishfinderbot.wpenginepowered.com",
            "chrome-extension://jamobibjpfcllagcdmefmnplcmobldbb" # Using the ID from previous context
        ]
    }
})

# --- CELERY CONFIGURATION ---
redis_url = os.environ.get('CELERY_BROKER_URL')
if redis_url:
    app.config.update(
        CELERY_BROKER_URL=redis_url,
        CELERY_RESULT_BACKEND=redis_url
    )
    celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
else:
    celery = None
    print("⚠️ Celery is not configured. Polling endpoints will be disabled.")


# --- CORE & GCS CONFIGURATION ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME")
GCS_CREDENTIALS_PATH = '/etc/secrets/gcs_credentials.json'

storage_client = None
if os.path.exists(GCS_CREDENTIALS_PATH):
    try:
        credentials = service_account.Credentials.from_service_account_file(GCS_CREDENTIALS_PATH)
        storage_client = storage.Client(credentials=credentials)
        print("✅ Successfully initialized Google Cloud Storage client.")
    except Exception as e:
        print(f"❌ Failed to initialize Google Cloud Storage client: {e}")
else:
    print("⚠️ GCS credentials file not found. Data collection will be disabled.")

# --- ALLOW-LIST ---
ALLOW_LIST = {
    "cyberattribution.ai", "aarp.org", "ncoa.org", "consumerfed.org",
    "cyberseniors.org", "pta.org", "consumer.ftc.gov", "bbb.org",
    "idtheftcenter.org", "lifelock.com", "phishfinder.bot", 
    "attributionengine.bot", "attributionagent.com", "attributionagent.ai", 
    "deerpfakedefender.ai"
}

# --- HELPER FUNCTIONS ---
def get_risk_details(score):
    if score >= 80: return {"level": "High", "class": "high"}
    elif score >= 50: return {"level": "Medium", "class": "medium"}
    else: return {"level": "Low", "class": "low"}

def save_to_gcs(data_to_save):
    if not storage_client or not GCS_BUCKET_NAME:
        print("-> GCS client not available. Skipping save.")
        return
    try:
        bucket = storage_client.bucket(GCS_BUCKET_NAME)
        timestamp = datetime.utcnow().strftime('%Y-%m-%d-%H%M%S-%f')
        full_results_blob = bucket.blob(f"phishfinder_results/{timestamp}.json")
        full_results_blob.upload_from_string(json.dumps(data_to_save, indent=2), content_type='application/json')
        print(f"✅ Successfully saved full analysis to GCS bucket.")
        risk_score = data_to_save.get("risk", {}).get("score", 0)
        if risk_score >= 80:
            indicator = data_to_save.get("rawInput", "")
            if indicator:
                threat_blob = bucket.blob(f"high_confidence_threats/{timestamp}.txt")
                threat_blob.upload_from_string(indicator, content_type='text/plain')
                print(f"✅ Saved high-confidence threat indicator: {indicator}")
    except Exception as e:
        print(f"❌ Failed to save data to GCS: {e}")

def perform_full_analysis(user_input):
    """Core analysis logic shared by all endpoints."""
    analysis_target = ""
    if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
        _, domain_from_email = user_input.split('@', 1)
        analysis_target = domain_from_email.lower()
    elif "Received: from" in user_input and "Subject:" in user_input:
        match = re.search(r'From:.*?<[^@]+@([^>]+)>', user_input)
        analysis_target = match.group(1).lower() if match else "raw_email_content"
    else:
        match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
        analysis_target = match.group(1).lower() if match else user_input.lower()

    if analysis_target in ALLOW_LIST:
        return {
            "risk": {"level": "Low", "class": "low", "score": 0},
            "summary": f"The domain '{analysis_target}' is a known, trusted entity.",
            "watchFor": ["This domain is on our internal allow-list of trusted sites."],
            "advice": "This site is considered safe.", "domainAge": "N/A", "mxRecords": "N/A",
            "generated": {"securityAlert": "N/A", "socialPost": "N/A"}, "rawInput": user_input
        }

    creation_date_str = "Not available"
    if analysis_target != "raw_email_content":
        try:
            domain_info = whois.whois(analysis_target)
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            if creation_date: creation_date_str = creation_date.strftime("%Y-%m-%d")
        except Exception as e: print(f"⚠️ WHOIS lookup failed: {e}")
    mx_records_found = "No"
    if analysis_target != "raw_email_content":
        try:
            if resolver.resolve(analysis_target, 'MX'): mx_records_found = "Yes"
        except Exception as e: print(f"⚠️ DNS MX lookup failed: {e}")

    prompt_template = (
        "You are PhishFinder. Analyze the potential phishing risk of the input: '{user_input}'. "
        "The extracted domain for analysis is '{analysis_target}'. Key evidence: "
        "Domain Creation Date: {creation_date_str}. MX Records Found: {mx_records_found}. "
        "Provide a risk score (1-100), summary, 'watchFor' list, 'advice', 'security_alert', and 'social_post'. "
        "Format the entire response as a single JSON object."
    )
    prompt = prompt_template.format(user_input=user_input, analysis_target=analysis_target, creation_date_str=creation_date_str, mx_records_found=mx_records_found)
    
    if not GEMINI_API_KEY: raise ValueError("GEMINI_API_KEY not set.")

    headers = {"Content-Type": "application/json"}
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "response_mime_type": "application/json",
            "response_schema": {
                "type": "object",
                "properties": {
                    "risk_score": {"type": "integer"}, "summary": {"type": "string"},
                    "watchFor": {"type": "array", "items": {"type": "string"}},
                    "advice": {"type": "string"}, "security_alert": {"type": "string"},
                    "social_post": {"type": "string"}
                },
                "required": ["risk_score", "summary", "watchFor", "advice", "security_alert", "social_post"]
            }
        }
    }
    url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
    
    # --- NEW: Retry Logic ---
    response = None
    for attempt in range(2): # Try up to 2 times
        try:
            response = requests.post(url, headers=headers, json=body, timeout=60)
            if response.status_code != 503: # If not a service unavailable error, break the loop
                response.raise_for_status()
                break
            print(f"⚠️ Received 503 from Gemini, retrying in 1 second... (Attempt {attempt + 1})")
            time.sleep(1)
        except requests.exceptions.RequestException as e:
            print(f"🔥 Network error calling Gemini: {e}")
            if attempt == 1: raise # Re-raise the exception on the last attempt
    
    if not response or not response.ok:
        raise Exception(f"Failed to get a successful response from Gemini after retries. Last status: {response.status_code if response else 'N/A'}")

    result = response.json()

    if "candidates" in result and result["candidates"]:
        gemini_data = json.loads(result["candidates"][0]["content"]["parts"][0]["text"])
        risk_score = gemini_data.get("risk_score", 0)
        risk_details = get_risk_details(risk_score)
        return {
            "risk": {"level": risk_details["level"], "class": risk_details["class"], "score": risk_score},
            "summary": gemini_data.get("summary", "No summary provided."),
            "watchFor": gemini_data.get("watchFor", []),
            "advice": gemini_data.get("advice", "No advice provided."),
            "domainAge": creation_date_str, "mxRecords": mx_records_found,
            "generated": {"securityAlert": gemini_data.get("security_alert", ""), "socialPost": gemini_data.get("social_post", "")},
            "rawInput": user_input
        }
    else:
        raise ValueError("No valid candidates in Gemini response.")

# --- API ENDPOINTS ---
@app.route("/api/check", methods=["POST"])
def check():
    try:
        data = request.get_json()
        user_input = data.get("prompt", "").strip()
        if not user_input: return jsonify({"error": "Missing input"}), 400
        
        final_response_data = perform_full_analysis(user_input)
        save_to_gcs(final_response_data)
        return jsonify(final_response_data)
        
    except Exception as e:
        print(f"🔥 Unexpected error in /api/check: {str(e)}")
        return jsonify({"error": f"Internal server error: {e}"}), 500

if celery:
    @celery.task
    def analysis_task(user_input):
        print(f"WORKER: Starting background analysis for '{user_input}'...")
        try:
            result = perform_full_analysis(user_input)
            save_to_gcs(result)
            return {"status": "Complete", "result": result}
        except Exception as e:
            print(f"WORKER: Analysis failed for '{user_input}': {e}")
            return {"status": "Failed", "error": str(e)}

@app.route("/api/start-check", methods=["POST"])
def start_check():
    if not celery: return jsonify({"error": "Celery not configured"}), 500
    data = request.get_json()
    user_input = data.get("prompt")
    if not user_input: return jsonify({"error": "Missing input"}), 400
    
    task = analysis_task.delay(user_input)
    return jsonify({"status": "pending", "task_id": task.id}), 202

@app.route("/api/result/<task_id>", methods=["GET"])
def get_result(task_id):
    if not celery: return jsonify({"error": "Celery not configured"}), 500
    task = celery.AsyncResult(task_id)
    if task.state == 'SUCCESS':
        return jsonify({'state': task.state, 'data': task.info.get('result')})
    elif task.state == 'FAILURE':
        return jsonify({'state': task.state, 'status': str(task.info)})
    else:
        return jsonify({'state': task.state, 'status': 'Processing...'})

# Other endpoints like /api/subscribe can remain as they are.

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)
