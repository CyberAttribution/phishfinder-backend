# Final version for Alpha Test - July 9 (Dual Model Streaming Backend)
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
CORS(app, resources={r"/api/*": {"origins": "*"}}) # Using wildcard for easier testing

# --- CORE CONFIGURATION ---
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
        print(f"❌ Failed to initialize GCS client: {e}")
else:
    print("⚠️ GCS credentials file not found. Data collection is disabled.")

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

def generate_analysis_stream(user_input, model_type='flash'):
    """
    Core generator function that performs analysis and yields JSON data chunks.
    Accepts a 'model_type' to choose between 'flash' and 'pro'.
    """
    full_response_for_saving = {"rawInput": user_input, "modelUsed": model_type}
    
    try:
        # 1. Extract domain
        analysis_target = ""
        if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
            _, domain_from_email = user_input.split('@', 1)
            analysis_target = domain_from_email.lower()
        else:
            match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
            analysis_target = match.group(1).lower() if match else user_input.lower()

        # 2. Allow list check
        if analysis_target in ALLOW_LIST:
            final_result = {
                "risk": {"level": "Low", "class": "low", "score": 0},
                "summary": f"The domain '{analysis_target}' is a known, trusted entity.",
                "watchFor": ["This domain is on our internal allow-list of trusted sites."],
                "advice": "This site is considered safe.", "domainAge": "N/A", "mxRecords": "N/A",
                "rawInput": user_input
            }
            yield json.dumps({"type": "final", "content": final_result}) + '\n'
            return

        # 3. Perform initial checks and stream results immediately
        creation_date_str = "Not available"
        try:
            domain_info = whois.whois(analysis_target)
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            if creation_date: creation_date_str = creation_date.strftime("%Y-%m-%d")
        except Exception as e: print(f"⚠️ WHOIS lookup failed: {e}")
        yield json.dumps({"type": "domainAge", "content": creation_date_str}) + '\n'
        
        mx_records_found = "No"
        try:
            if resolver.resolve(analysis_target, 'MX'): mx_records_found = "Yes"
        except Exception as e: print(f"⚠️ DNS MX lookup failed: {e}")
        yield json.dumps({"type": "mxRecords", "content": mx_records_found}) + '\n'

        # 4. Call Gemini API for the main analysis
        model_name = "gemini-1.5-pro-latest" if model_type == 'pro' else "gemini-1.5-flash-latest"
        print(f"STREAM: Using model: {model_name}")

        prompt_template = (
            "You are PhishFinder. Analyze the potential phishing risk of the input: '{user_input}'. "
            "Domain is '{analysis_target}'. Evidence: Created on {creation_date_str}, MX Records: {mx_records_found}. "
            "Respond in JSON with: risk_score (1-100), summary (string), watchFor (array of strings), advice (string)."
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
                        "advice": {"type": "string"}
                    },
                    "required": ["risk_score", "summary", "watchFor", "advice"]
                }
            }
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={GEMINI_API_KEY}"
        response = requests.post(url, headers=headers, json=body)
        response.raise_for_status()
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
    """Unified streaming endpoint for all clients."""
    data = request.get_json()
    user_input = data.get("prompt")
    model_type = data.get("model", "flash") # Default to 'flash' if not specified
    if not user_input:
        return jsonify({"error": "Missing input"}), 400
    
    return Response(generate_analysis_stream(user_input, model_type), mimetype='application/x-ndjson')

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
