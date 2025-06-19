from flask import Flask, request, jsonify
import requests
import json
import os

app = Flask(__name__)

# Set GEMINI_API_KEY as an environment variable in Render and for local development
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
# Using gemini-2.5-pro as requested - this is the most recent Pro model
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent"

# Define the MailerLite API endpoint and key from environment variables
MAILERLITE_API_KEY = os.environ.get("MAILERLITE_API_KEY")
MAILERLITE_API_URL = "https://api.mailerlite.com/api/v2/subscribers" # Or your specific MailerLite endpoint

@app.route("/check", methods=["POST"])
def check():
    try:
        data = request.get_json()
        print("📩 Incoming request data:", data)

        if not data or "domain" not in data:
            print("⚠️ Missing 'domain' in request:", data)
            return jsonify({"error": "Missing 'domain' in request"}), 400

        domain = data["domain"]
        input_text = data.get("text", "")

        prompt = (
            f"As an expert in cybersecurity and threat intelligence, analyze the following domain for potential phishing or malicious intent. Provide a numerical risk score from 1-100 (100 being highest risk). Explain the reasoning behind the score, highlighting specific indicators for a cybersecurity journalist. Focus on elements like domain age, unusual characters, brand impersonation attempts, and typical phishing patterns.\n\n"
            f"Domain: {domain}\n\nContext: {input_text}\n\n"
            f"Provide your response as a JSON object with the following keys: 'risk_score' (integer 1-100), 'summary' (string), 'indicators' (array of strings), 'journalist_tips' (array of strings)."
        )

        # Ensure GEMINI_API_KEY is available
        if not GEMINI_API_KEY:
            print("❌ GEMINI_API_KEY is not set.")
            return jsonify({"error": "Gemini API key not configured on server"}), 500

        headers = {
            "Content-Type": "application/json"
        }

        body = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            # Request JSON output directly from Gemini 2.5 Pro
            "generationConfig": {
                "response_mime_type": "application/json",
                "response_schema": {
                    "type": "object",
                    "properties": {
                        "risk_score": {"type": "integer", "minimum": 1, "maximum": 100},
                        "summary": {"type": "string"},
                        "indicators": {"type": "array", "items": {"type": "string"}},
                        "journalist_tips": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["risk_score", "summary", "indicators", "journalist_tips"]
                }
            }
        }

        url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
        print("🌐 Sending to Gemini:", url)
        # print("📤 Request body:", json.dumps(body, indent=2)) # Commented out to avoid printing large body

        response = requests.post(url, headers=headers, json=body)

        if not response.ok:
            print("❌ Gemini error:", response.status_code, response.text)
            return jsonify({"error": "Gemini request failed", "status": response.status_code, "detail": response.text}), 500

        result = response.json()
        print("🧠 Gemini raw response:", result)

        if "candidates" in result and result["candidates"]:
            # Direct access to JSON output if response_mime_type is set
            gemini_output_json = result["candidates"][0]["content"]["parts"][0]["text"]
            return jsonify(json.loads(gemini_output_json))

        else:
            print("⚠️ Gemini response had no valid candidates.")
            return jsonify({"error": "No valid response from Gemini"}), 500

    except Exception as e:
        print("🔥 Unexpected server error:", str(e))
        return jsonify({"error": "Internal server error", "exception": str(e)}), 500

@app.route("/subscribe", methods=["POST"])
def subscribe():
    try:
        data = request.get_json()
        email = data.get("email")
        opt_in = data.get("opt_in")
        
        print(f"📩 Incoming subscribe request: Email={email}, Opt_in={opt_in}")

        if not email:
            print("⚠️ Missing email in subscribe request.")
            return jsonify({"error": "Email is required"}), 400
        
        if not MAILERLITE_API_KEY:
            print("❌ MAILERLITE_API_KEY is not set.")
            return jsonify({"error": "MailerLite API key not configured on server"}), 500

        headers = {
            "Content-Type": "application/json",
            "X-MailerLite-ApiKey": MAILERLITE_API_KEY
        }
        
        subscribe_body = {
            "email": email,
            "status": "active" if opt_in else "unsubscribed"
        }

        print(f"📤 Sending to MailerLite: {subscribe_body}")
        mailerlite_response = requests.post(MAILERLITE_API_URL, headers=headers, json=subscribe_body)
        print(f"🧠 MailerLite raw response: {mailerlite_response.status_code}, {mailerlite_response.text}")

        if mailerlite_response.ok:
            return jsonify({"message": "Subscription status updated successfully"}), 200
        else:
            print(f"❌ MailerLite error: {mailerlite_response.status_code}, {mailerlite_response.text}")
            return jsonify({
                "error": "Failed to subscribe/update in MailerLite",
                "status": mailerlite_response.status_code,
                "detail": mailerlite_response.text
            }), 500

    except Exception as e:
        print(f"🔥 Unexpected server error during MailerLite subscribe: {str(e)}")
        return jsonify({"error": "Internal server error", "exception": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)