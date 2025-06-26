# Final version for Alpha Test - June 25 (Expanded CORS)
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
# --- CONFIGURATION: More robust CORS for all subdomains and primary domain ---
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://phishfinder.bot", 
            "https://phishfinderbot.wpenginepowered.com"
        ]
    }
})

# --- CONFIGURATION ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
MAILERLITE_API_KEY = os.environ.get("MAILERLITE_API_KEY")
MAILERLITE_GROUP_ID = os.environ.get("MAILERLITE_GROUP_ID")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent"
if MAILERLITE_GROUP_ID:
    MAILERLITE_API_URL = f"https://api.mailerlite.com/api/v2/groups/{MAILERLITE_GROUP_ID}/subscribers"
else:
    MAILERLITE_API_URL = None

# --- ALLOW-LIST ---
ALLOW_LIST = {
    "cyberattribution.ai", "aarp.org", "ncoa.org", "consumerfed.org",
    "cyberseniors.org", "pta.org", "consumer.ftc.gov", "bbb.org",
    "idtheftcenter.org", "lifelock.com", "phishfinder.bot", 
    "attributionengine.bot", "attributionagent.com", "attributionagent.ai", 
    "deerpfakedefender.ai"
}

# --- Helper function to map score to risk level/class ---
def get_risk_details(score):
    if score >= 80:
        return {"level": "High", "class": "high"}
    elif score >= 50:
        return {"level": "Medium", "class": "medium"}
    else:
        return {"level": "Low", "class": "low"}

# --- CHECK ENDPOINT ---
@app.route("/api/check", methods=["POST"])
def check():
    function_start_time = time.time()
    print(f"[{function_start_time:.0f}] --- Check request received ---")

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400
        
        user_input = data.get("prompt", "").strip()
        if not user_input:
            print("⚠️ Missing 'prompt' in request.")
            return jsonify({"error": "Missing input in request"}), 400

        analysis_target = ""
        # Input Detection Logic
        if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
            print(f"✅ Input detected as an EMAIL: {user_input}")
            username, domain_from_email = user_input.split('@', 1)
            analysis_target = domain_from_email.lower()
        else:
            print(f"✅ Input detected as a DOMAIN/URL: {user_input}")
            # A simple way to extract domain from a URL
            match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
            if match:
                analysis_target = match.group(1).lower()
            else:
                analysis_target = user_input.lower()

        prompt_template = (
            "You are PhishFinder. Analyze the potential phishing risk of the following input: '{user_input}'. "
            "The extracted domain for analysis is '{analysis_target}'. Key evidence to consider: "
            "Domain Creation Date: {creation_date_str}. MX Records Found: {mx_records_found}. "
            "Provide a risk score (1-100), a concise summary, a list of warning signs ('watchFor'), and brief 'advice' for a non-technical user. "
            "Also generate a 'security_alert' for IT staff and a 'social_post' for public awareness. "
            "Format the entire response as a single JSON object."
        )

        if analysis_target in ALLOW_LIST:
            print(f"✅ Domain '{analysis_target}' found in the Allow-List.")
            return jsonify({
                "risk": {"level": "Low", "class": "low", "score": 0},
                "summary": f"The domain '{analysis_target}' is a known, trusted entity.",
                "watchFor": ["This domain is on our internal allow-list of trusted sites."],
                "advice": "This site is considered safe.",
                "domainAge": "N/A",
                "mxRecords": "N/A",
                "generated": {"securityAlert": "N/A", "socialPost": "N/A"},
                "rawInput": user_input
            })
        
        creation_date_str = "Not available"
        try:
            domain_info = whois.whois(analysis_target)
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            if creation_date:
                creation_date_str = creation_date.strftime("%Y-%m-%d")
            print(f"ℹ️ WHOIS Creation Date for {analysis_target}: {creation_date_str}")
        except Exception as e:
            print(f"⚠️ WHOIS lookup failed for {analysis_target}: {e}")

        mx_records_found = "No"
        try:
            records = resolver.resolve(analysis_target, 'MX')
            if records:
                mx_records_found = "Yes"
            print(f"ℹ️ DNS MX Records Found for {analysis_target}: {mx_records_found}")
        except Exception as e:
            print(f"⚠️ DNS MX lookup failed for {analysis_target}: {e}")

        prompt = prompt_template.format(user_input=user_input, analysis_target=analysis_target, creation_date_str=creation_date_str, mx_records_found=mx_records_found)
        
        if not GEMINI_API_KEY:
            print("❌ GEMINI_API_KEY is not set.")
            return jsonify({"error": "API key not configured"}), 500

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
                        "advice": {"type": "string"},
                        "security_alert": {"type": "string"},
                        "social_post": {"type": "string"}
                    },
                    "required": ["risk_score", "summary", "watchFor", "advice", "security_alert", "social_post"]
                }
            }
        }
        url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
        
        response = requests.post(url, headers=headers, json=body)

        if not response.ok:
            print(f"❌ Gemini error: {response.status_code} {response.text}")
            return jsonify({"error": "Gemini request failed"}), response.status_code

        result = response.json()

        if "candidates" in result and result["candidates"]:
            gemini_output_json_str = result["candidates"][0]["content"]["parts"][0]["text"]
            gemini_data = json.loads(gemini_output_json_str)
            
            risk_score = gemini_data.get("risk_score", 0)
            risk_details = get_risk_details(risk_score)
            
            final_response_data = {
                "risk": {
                    "level": risk_details["level"],
                    "class": risk_details["class"],
                    "score": risk_score
                },
                "summary": gemini_data.get("summary", "No summary provided."),
                "watchFor": gemini_data.get("watchFor", []),
                "advice": gemini_data.get("advice", "No advice provided."),
                "domainAge": creation_date_str,
                "mxRecords": mx_records_found,
                "generated": {
                    "securityAlert": gemini_data.get("security_alert", ""),
                    "socialPost": gemini_data.get("social_post", "")
                },
                "rawInput": user_input
            }
            
            return jsonify(final_response_data)
        else:
            print("⚠️ Gemini response had no valid candidates.")
            return jsonify({"error": "No valid response from Gemini"}), 500

    except Exception as e:
        print(f"🔥 Unexpected server error in /api/check: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# --- SUBSCRIBE ENDPOINT ---
@app.route("/api/subscribe", methods=["POST"])
def subscribe():
    # This endpoint remains largely the same
    try:
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"success": False, "message": "Email is required"}), 400
        if not MAILERLITE_API_URL:
            return jsonify({"success": False, "message": "MailerLite not configured"}), 500
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
