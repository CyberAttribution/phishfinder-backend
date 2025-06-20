from flask import Flask, request, jsonify
import requests
import json
import os
import time

app = Flask(__name__)

# --- CONFIGURATION ---
# Load API keys from environment variables
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
MAILERLITE_API_KEY = os.environ.get("MAILERLITE_API_KEY")
MAILERLITE_GROUP_ID = os.environ.get("MAILERLITE_GROUP_ID")

# Define API URLs
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent"
# Ensure the Group ID is available before constructing the MailerLite URL
if MAILERLITE_GROUP_ID:
    MAILERLITE_API_URL = f"https://api.mailerlite.com/api/v2/groups/{MAILERLITE_GROUP_ID}/subscribers"
else:
    MAILERLITE_API_URL = None

# --- CHECK ENDPOINT ---
@app.route("/check", methods=["POST"])
def check():
    function_start_time = time.time()
    print(f"[{function_start_time:.0f}] --- Check request received ---")

    try:
        data = request.get_json()
        if not data or "domain" not in data:
            print("⚠️ Missing 'domain' in request.")
            return jsonify({"error": "Missing 'domain' in request"}), 400

        domain = data["domain"]
        input_text = data.get("text", "")

        prompt = (
            f"As an expert in cybersecurity and threat intelligence, analyze the following domain for potential phishing or malicious intent. Provide a numerical risk score from 1-100 (100 being highest risk). Explain the reasoning behind the score, highlighting specific indicators for a cybersecurity journalist. Focus on elements like domain age, unusual characters, brand impersonation attempts, and typical phishing patterns.\n\n"
            f"Domain: {domain}\n\nContext: {input_text}\n\n"
            f"Provide your response as a JSON object with the following keys: 'risk_score' (integer 1-100), 'summary' (string), 'indicators' (array of strings), 'journalist_tips' (array of strings)."
        )

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
                        "journalist_tips": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["risk_score", "summary", "indicators"]
                }
            }
        }

        url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
        
        gemini_call_start_time = time.time()
        print(f"[{gemini_call_start_time:.0f}] 🌐 Sending request to Gemini API...")

        response = requests.post(url, headers=headers, json=body)

        gemini_call_end_time = time.time()
        duration = gemini_call_end_time - gemini_call_start_time
        # This is the line that was corrected
        print(f"[{gemini_call_end_time:.0f}] 🧠 Received response from Gemini. The API call took: {duration:.2f} seconds.")

        if not response.ok:
            print(f"❌ Gemini error: {response.status_code} {response.text}")
            return jsonify({"error": "Gemini request failed"}), response.status_code

        result = response.json()

        if "candidates" in result and result["candidates"]:
            gemini_output_json_str = result["candidates"][0]["content"]["parts"][0]["text"]
            total_duration = time.time() - function_start_time
            print(f"[{time.time():.0f}] ✅ Successfully processed request. Total time: {total_duration:.2f} seconds.")
            return jsonify(json.loads(gemini_output_json_str))
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

# This part is for running the app with Gunicorn, which Render does automatically.
# The if __name__ == "__main__": block is not needed for Render's default Gunicorn setup.