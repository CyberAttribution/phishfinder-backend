# Final version for Alpha Test - July 9 (Unified Backend with Polling & GCS)
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
# IMPORTANT: Replace <YOUR_EXTENSION_ID> with your actual extension's ID.
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://phishfinder.bot", 
            "https://phishfinderbot.wpenginepowered.com",
            "chrome-extension://<YOUR_EXTENSION_ID>" 
        ]
    }
})

# --- CELERY CONFIGURATION (for Chrome Extension) ---
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


# --- CORE CONFIGURATION ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
MAILERLITE_API_KEY = os.environ.get("MAILERLITE_API_KEY")
MAILERLITE_GROUP_ID = os.environ.get("MAILERLITE_GROUP_ID")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent"
if MAILERLITE_GROUP_ID:
    MAILERLITE_API_URL = f"https://api.mailerlite.com/api/v2/groups/{MAILERLITE_GROUP_ID}/subscribers"
else:
    MAILERLITE_API_URL = None

# --- GOOGLE CLOUD STORAGE CONFIGURATION ---
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
        
        # Save the full analysis result
        full_results_blob = bucket.blob(f"phishfinder_results/{timestamp}.json")
        full_results_blob.upload_from_string(json.dumps(data_to_save, indent=2), content_type='application/json')
        print(f"✅ Successfully saved full analysis to GCS bucket.")

        # --- NEW: Save high-confidence threats to a separate folder ---
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
    # Enhanced input detection for URL, email, or raw email content
    if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
        _, domain_from_email = user_input.split('@', 1)
        analysis_target = domain_from_email.lower()
    elif "Received: from" in user_input and "Subject:" in user_input:
        match = re.search(r'From:.*?<[^@]+@([^>]+)>', user_input)
        analysis_target = match.group(1).lower() if match else "raw_email_content"
    else: # Assume domain/URL
        match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
        analysis_target = match.group(1).lower() if match else user_input.lower()

    prompt_template = (
        "You are PhishFinder. Analyze the potential phishing risk of the following input: '{user_input}'. "
        "The extracted domain for analysis is '{analysis_target}'. Key evidence to consider: "
        "Domain Creation Date: {creation_date_str}. MX Records Found: {mx_records_found}. "
        "Provide a risk score (1-100), a concise summary, a list of warning signs ('watchFor'), and brief 'advice' for a non-technical user. "
        "Also generate a 'security_alert' for IT staff and a 'social_post' for public awareness. "
        "Format the entire response as a single JSON object."
    )
    
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
    response = requests.post(url, headers=headers, json=body)
    response.raise_for_status()
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
        return jsonify({"error": "Internal server error"}), 500

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

@app.route("/api/subscribe", methods=["POST"])
def subscribe():
    try:
        data = request.get_json()
        email = data.get("email")
        if not email: return jsonify({"success": False, "message": "Email is required"}), 400
        if not MAILERLITE_API_URL: return jsonify({"success": False, "message": "MailerLite not configured"}), 500
        headers = {"Content-Type": "application/json", "X-MailerLite-ApiKey": MAILERLITE_API_KEY}
        subscribe_body = {"email": email}
        response = requests.post(MAILERLITE_API_URL, headers=headers, json=subscribe_body)
        if response.ok:
            return jsonify({"success": True, "message": "Subscribed successfully"}), 200
        else:
            return jsonify({"success": False, "message": "API error"}), 500
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)
