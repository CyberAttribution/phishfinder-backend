# Version with Actionable Content Generation REMOVED

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

app = Flask(__name__)
CORS(app)

# --- CONFIGURATION (Your existing code) ---
# ... (Full configuration remains here)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
# ... etc ...

# --- ALLOW-LIST (Your existing code) ---
ALLOW_LIST = {
    "cyberattribution.ai", "aarp.org", "ncoa.org", # ... etc
}

# --- Helper function (Your existing code) ---
def get_risk_details(score):
    if score >= 80: return {"level": "High", "class": "high"}
    elif score >= 50: return {"level": "Medium", "class": "medium"}
    else: return {"level": "Low", "class": "low"}

# --- CHECK ENDPOINT ---
@app.route("/api/check", methods=["POST"])
def check():
    function_start_time = time.time()
    print(f"[{function_start_time:.0f}] --- Check request received ---")

    try:
        data = request.get_json()
        if not data: return jsonify({"error": "Invalid JSON"}), 400
        
        user_input = data.get("prompt", "").strip()
        if not user_input: return jsonify({"error": "Missing input in request"}), 400

        # ... (Input detection logic is correct) ...
        if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
            username, domain_from_email = user_input.split('@', 1)
            analysis_target = domain_from_email.lower()
        else:
            match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
            if match: analysis_target = match.group(1).lower()
            else: analysis_target = user_input.lower()
            
        if analysis_target in ALLOW_LIST:
            # ... (Allow list logic is correct) ...
            return jsonify({ "risk": {"level": "Low", "class": "low", "score": 0}, "summary": f"The domain '{analysis_target}' is a known, trusted entity.", "watchFor": ["This domain is on our internal allow-list of trusted sites."],"advice": "This site is considered safe.", "domainAge": "N/A", "mxRecords": "N/A", "generated": {"securityAlert": "N/A", "socialPost": "N/A"}, "rawInput": user_input})

        # --- THIS IS A SIMPLIFIED PROMPT FOR TESTING ---
        prompt = (
            f"You are PhishFinder. Analyze the potential phishing risk of the following input: '{user_input}'. "
            "Provide a risk score (1-100), a concise summary, a list of warning signs ('watchFor'), and brief 'advice' for a non-technical user. "
            "Format the entire response as a single JSON object."
        )
        
        if not GEMINI_API_KEY:
            return jsonify({"error": "API key not configured"}), 500

        headers = {"Content-Type": "application/json"}
        # --- THIS IS A SIMPLIFIED BODY FOR TESTING ---
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "response_mime_type": "application/json",
            }
        }
        url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
        
        response = requests.post(url, headers=headers, json=body)

        if not response.ok:
            return jsonify({"error": "Gemini request failed"}), response.status_code

        result = response.json()

        if "candidates" in result and result["candidates"]:
            gemini_output_json_str = result["candidates"][0]["content"]["parts"][0]["text"]
            gemini_data = json.loads(gemini_output_json_str)
            
            risk_score = gemini_data.get("risk_score", 0)
            risk_details = get_risk_details(risk_score)
            
            final_response_data = {
                "risk": { "level": risk_details["level"], "class": risk_details["class"], "score": risk_score },
                "summary": gemini_data.get("summary", "No summary provided."),
                "watchFor": gemini_data.get("watchFor", []),
                "advice": gemini_data.get("advice", "No advice provided."),
                "domainAge": "N/A", # No data to provide
                "mxRecords": "N/A", # No data to provide
                "generated": {"securityAlert": "", "socialPost": ""}, # Return empty strings
                "rawInput": user_input
            }
            
            return jsonify(final_response_data)
        else:
            return jsonify({"error": "No valid response from Gemini"}), 500

    except Exception as e:
        print(f"🔥 Unexpected server error in /api/check: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# --- SUBSCRIBE ENDPOINT (Unchanged) ---
# ... (Full subscribe logic) ...

if __name__ == "__main__":
    # ... (Unchanged) ...
