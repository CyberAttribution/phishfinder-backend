# PhishFinder Backend - Phoenix Version - July 10, 2025
from flask import Flask, request, jsonify, Response
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

app = Flask(__name__)

# --- UNIFIED CORS CONFIGURATION ---
# Allows access from the website and the Chrome Extension.
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

# --- CORE CONFIGURATION ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME")
GCS_CREDENTIALS_PATH = '/etc/secrets/gcs_credentials.json'

# --- GOOGLE CLOUD STORAGE INITIALIZATION ---
storage_client = None
if os.path.exists(GCS_CREDENTIALS_PATH):
    try:
        credentials = service_account.Credentials.from_service_account_file(GCS_CREDENTIALS_PATH)
        storage_client = storage.Client(credentials=credentials)
        print("✅ Successfully initialized Google Cloud Storage client.")
    except Exception as e:
        print(f"❌ Failed to initialize GCS client: {e}")
else:
    print("⚠️ GCS credentials file not found. Data collection will be disabled.")

# --- ALLOW-LIST & HELPER FUNCTIONS ---
ALLOW_LIST = {
    "cyberattribution.ai", "aarp.org", "ncoa.org", "consumerfed.org",
    "cyberseniors.org", "pta.org", "consumer.ftc.gov", "bbb.org",
    "idtheftcenter.org", "lifelock.com", "phishfinder.bot", 
    "attributionengine.bot", "attributionagent.com", "attributionagent.ai", 
    "deerpfakedefender.ai"
}

def get_risk_details(score):
    if score >= 80: return {"level": "High", "class": "high"}
    elif score >= 50: return {"level": "Medium", "class": "medium"}
    else: return {"level": "Low", "class": "low"}

def save_to_gcs(data_to_save):
    if not storage_client or not GCS_BUCKET_NAME: return
    try:
        bucket = storage_client.bucket(GCS_BUCKET_NAME)
        timestamp = datetime.utcnow().strftime('%Y-%m-%d-%H%M%S-%f')
        full_results_blob = bucket.blob(f"phishfinder_results/{timestamp}.json")
        full_results_blob.upload_from_string(json.dumps(data_to_save, indent=2), content_type='application/json')
        print(f"✅ Saved full analysis to GCS.")
        if data_to_save.get("risk", {}).get("score", 0) >= 80:
            indicator = data_to_save.get("rawInput", "")
            if indicator:
                threat_blob = bucket.blob(f"high_confidence_threats/{timestamp}.txt")
                threat_blob.upload_from_string(indicator, content_type='text/plain')
                print(f"✅ Saved high-confidence threat.")
    except Exception as e:
        print(f"❌ Failed to save data to GCS: {e}")

# --- CORE ANALYSIS STREAMING GENERATOR ---
def generate_analysis_stream(user_input, model_type='flash'):
    full_response_for_saving = {"rawInput": user_input, "modelUsed": model_type}
    
    try:
        analysis_target = ""
        if "Received: from" in user_input and "Subject:" in user_input:
            match = re.search(r'From:.*?<[^@]+@([^>]+)>', user_input)
            analysis_target = match.group(1).lower() if match else "raw_email_content"
            prompt_context = "The user has submitted raw email source code. Analyze it for phishing, paying close attention to the headers (Received, SPF, DKIM, DMARC) and the body content."
        elif re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
            _, domain_from_email = user_input.split('@', 1)
            analysis_target = domain_from_email.lower()
            prompt_context = "The user has submitted an email address. Analyze the domain for signs of impersonation or risk."
        else:
            match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
            analysis_target = match.group(1).lower() if match else user_input.lower()
            prompt_context = "The user has submitted a URL or domain. Analyze it for phishing risk."

        if analysis_target in ALLOW_LIST:
            # ... (Allow list logic remains the same)
            return

        # --- Perform initial checks and stream results immediately ---
        creation_date_str = "N/A"
        if analysis_target != "raw_email_content":
            try:
                domain_info = whois.whois(analysis_target)
                creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                if creation_date: creation_date_str = creation_date.strftime("%Y-%m-%d")
            except Exception as e: print(f"⚠️ WHOIS lookup failed: {e}")
        yield json.dumps({"type": "domainAge", "content": creation_date_str}) + '\n'
        
        mx_records_found = "N/A"
        if analysis_target != "raw_email_content":
            try:
                if resolver.resolve(analysis_target, 'MX'): mx_records_found = "Yes"
                else: mx_records_found = "No"
            except Exception as e: mx_records_found = "No"
        yield json.dumps({"type": "mxRecords", "content": mx_records_found}) + '\n'

        # --- Call Gemini API for the main analysis ---
        model_name = "gemini-1.5-pro-latest" if model_type == 'pro' else "gemini-1.5-flash-latest"
        print(f"STREAM: Using model: {model_name}")

        prompt = (
            f"You are PhishFinder, an expert cybersecurity analyst. {prompt_context} "
            f"Analyze the following input: '{user_input}'. The extracted domain is '{analysis_target}'. "
            f"Key evidence: Domain Created: {creation_date_str}, MX Records Found: {mx_records_found}. "
            f"Respond in a single, valid JSON object with: risk_score (1-100), summary (string), watchFor (array of strings), "
            f"advice (string), security_alert (string), and social_post (string)."
        )
        
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
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={GEMINI_API_KEY}"
        
        response = None
        for attempt in range(2): # Retry logic
            try:
                response = requests.post(url, headers=headers, json=body, timeout=60)
                if response.status_code != 503:
                    response.raise_for_status()
                    break
                print(f"⚠️ Received 503 from Gemini, retrying... (Attempt {attempt + 1})")
                time.sleep(1)
            except requests.exceptions.RequestException as e:
                if attempt == 1: raise e

        if not response or not response.ok:
            raise Exception(f"Failed to get a successful response from Gemini. Status: {response.status_code if response else 'N/A'}")

        result = response.json()

        if "candidates" in result and result["candidates"]:
            gemini_data = json.loads(result["candidates"][0]["content"]["parts"][0]["text"])
            risk_score = gemini_data.get("risk_score", 0)
            risk_details = get_risk_details(risk_score)
            
            final_result = {
                "risk": {"level": risk_details["level"], "class": risk_details["class"], "score": risk_score},
                "summary": gemini_data.get("summary", "No summary provided."),
                "watchFor": gemini_data.get("watchFor", []),
                "advice": gemini_data.get("advice", "No advice provided."),
                "domainAge": creation_date_str, "mxRecords": mx_records_found,
                "generated": {"securityAlert": gemini_data.get("security_alert", ""), "socialPost": gemini_data.get("social_post", "")},
                "rawInput": user_input
            }

            yield json.dumps({"type": "final", "content": final_result}) + '\n'
            save_to_gcs(final_result)
        else:
            raise ValueError("No valid candidates in Gemini response.")

    except Exception as e:
        print(f"🔥 STREAM: Unexpected error: {str(e)}")
        error_payload = json.dumps({"type": "error", "content": f"An unexpected backend error occurred: {str(e)}"}) + '\n'
        yield error_payload
        save_to_gcs({"rawInput": user_input, "error": str(e)})

# --- API ENDPOINTS ---
@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    user_input = data.get("prompt")
    model_type = data.get("model", "flash")
    if not user_input:
        return jsonify({"error": "Missing input"}), 400
    
    return Response(generate_analysis_stream(user_input, model_type), mimetype='application/x-ndjson')

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
