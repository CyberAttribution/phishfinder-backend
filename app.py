# Final version for Alpha Test - June 22
from flask import Flask, request, jsonify
from flask_cors import CORS  # <--- ADDED CORS FIX
import requests
import json
import os
import time
import re
import whois
from datetime import datetime

app = Flask(__name__)
CORS(app)  # <--- ADDED CORS FIX

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
    "cyberattribution.ai",
    "aarp.org",             # AARP
    "ncoa.org",             # National Council on Aging
    "consumerfed.org",      # Consumer Federation of America
    "cyberseniors.org",     # Cyber-Seniors
    "pta.org",              # National PTA
    "consumer.ftc.gov",     # Part of the ecosystem for gov't reporting
    "bbb.org",              # Better Business Bureau
    "idtheftcenter.org",    # Identity Theft Resource Center
    "lifelock.com"          # Gen Digital (LifeLock / Norton)
}

# --- CHECK ENDPOINT ---
@app.route("/check", methods=["POST"])
def check():
    function_start_time = time.time()
    print(f"[{function_start_time:.0f}] --- Check request received ---")

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400
        
        user_input = data.get("domain", "").strip()
        input_text = data.get("text", "") 
        
        if not user_input:
            print("⚠️ Missing 'domain' or 'email' in request.")
            return jsonify({"error": "Missing input in request"}), 400

        analysis_target = ""
        # Input Detection Logic
        if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
            print(f"✅ Input detected as an EMAIL: {user_input}")
            username, domain_from_email = user_input.split('@', 1)
            analysis_target = domain_from_email.lower()
            prompt_template = (
                "As a cybersecurity expert, analyze the EMAIL ADDRESS '{user_input}' for phishing indicators. The username is '{username}' and the domain is '{analysis_target}'. The domain's creation date is {creation_date_str}. "
                "When evaluating risk, consider that new businesses and startups legitimately have recently created domains; this is a potential indicator but not definitive proof of maliciousness. "
                "Assess if the username ('{username}') creates false authority (e.g., 'support', 'billing') and if the domain ('{analysis_target}') appears to be impersonating a *different*, well-known brand. "
                "Also, based on your analysis, generate two pieces of content: a concise 'security_alert' for an internal IT team, and a brief 'social_post' (max 280 chars) for warning others on social media. "
                "Provide a risk score (1-100) and a summary in a JSON object with keys: 'risk_score', 'summary', 'indicators', 'journalist_tips', 'security_alert', 'social_post'."
            )
        else:
            print(f"✅ Input detected as a DOMAIN/URL: {user_input}")
            analysis_target = user_input.lower()
            prompt_template = (
                "As a cybersecurity expert, analyze the DOMAIN '{analysis_target}' for phishing risk. The domain's creation date is {creation_date_str}. Focus on domain age, brand impersonation, and other standard indicators. "
                "Also, based on your analysis, generate two pieces of content: a concise 'security_alert' for an internal IT team, and a brief 'social_post' (max 280 chars) for warning others on social media. "
                "Provide a risk score (1-100) and a summary in a JSON object with keys: 'risk_score', 'summary', 'indicators', 'journalist_tips', 'security_alert', 'social_post'."
            )
        
        # Check against the Allow-List
        if analysis_target in ALLOW_LIST:
            print(f"✅ Domain '{analysis_target}' found in the Allow-List. Bypassing AI analysis.")
            return jsonify({
                "risk_score": 0,
                "summary": f"The domain '{analysis_target}' is a known, trusted entity.",
                "indicators": ["This domain is on our internal allow-list."],
                "journalist_tips": ["No risk detected from this trusted domain."],
                "creation_date": "N/A"
            })
        
        creation_date_str = "Not available"
        try:
            domain_info = whois.whois(analysis_target)
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            
            if creation_date:
                creation_date_str = creation_date.strftime("%Y-%m-%d")
            print(f"ℹ️ WHOIS Creation Date for {analysis_target}: {creation_date_str}")
        except Exception as e:
            print(f"⚠️ WHOIS lookup failed for {analysis_target}: {e}")

        prompt = prompt_template.format(user_input=user_input, username=locals().get('username', ''), analysis_target=analysis_target, creation_date_str=creation_date_str)
        
        if not GEMINI_API_KEY:
            print("❌ GEMINI_API_KEY is not set.")
            return jsonify({"error": "Gemini API key not configured on server"}), 500

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
                        "indicators": {"type": "array", "items": {"type": "string"}},
                        "journalist_tips": {"type": "array", "items": {"type": "string"}},
                        "security_alert": {"type": "string"},
                        "social_post": {"type": "string"}
                    },
                    "required": ["risk_score", "summary", "indicators", "security_alert", "social_post"]
                }
            }
        }

        url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
        
        gemini_call_start_time = time.time()
        print(f"[{gemini_call_start_time:.0f}] 🌐 Sending request to Gemini API...")
        response = requests.post(url, headers=headers, json=body)
        gemini_call_end_time = time.time()
        duration = gemini_call_end_time - gemini_call_start_time
        print(f"[{gemini_call_end_time:.0f}] 🧠 Received response from Gemini. The API call took: {duration:.2f} seconds.")

        if not response.ok:
            print(f"❌ Gemini error: {response.status_code} {response.text}")
            return jsonify({"error": "Gemini request failed"}), response.status_code

        result = response.json()

        if "candidates" in result and result["candidates"]:
            gemini_output_json_str = result["candidates"][0]["content"]["parts"][0]["text"]
            final_response_data = json.loads(gemini_output_json_str)
            final_response_data['creation_date'] = creation_date_str
            
            total_duration = time.time() - function_start_time
            print(f"[{time.time():.0f}] ✅ Successfully processed request. Total time: {total_duration:.2f} seconds.")
            return jsonify(final_response_data)
        else:
            print("⚠️ Gemini response had no valid candidates.")
            return jsonify({"error": "No valid response from Gemini"}), 500

    except Exception as e:
        print(f"🔥 Unexpected server error in /check: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# --- SUBSCRIBE ENDPOINT ---
@app.route("/subscribe", methods=["POST"])
def subscribe():
    try:
        data = request.get_json()
        email = data.get("email")

        if not email:
            print("⚠️ Missing email in subscribe request.")
            return jsonify({"success": False, "message": "Email is required"}), 400
        
        if not MAILERLITE_API_KEY or not MAILERLITE_GROUP_ID or not MAILERLITE_API_URL:
            print("❌ MailerLite API key or Group ID is not set.")
            return jsonify({"success": False, "message": "MailerLite not configured"}), 500

        headers = {
            "Content-Type": "application/json",
            "X-MailerLite-ApiKey": MAILERLITE_API_KEY
        }
        
        subscribe_body = {"email": email}

        mailerlite_response = requests.post(MAILERLITE_API_URL, headers=headers, json=subscribe_body)
        
        if mailerlite_response.ok:
            print(f"✅ Subscribed {email} to MailerLite.")
            return jsonify({"success": True, "message": "Subscribed successfully"}), 200
        else:
            print(f"❌ MailerLite error: {mailerlite_response.status_code} {mailerlite_response.text}")
            return jsonify({"success": False, "message": "API error"}), 500

    except Exception as e:
        print(f"🔥 Unexpected server error in /subscribe: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)
