from collections import defaultdict
import time
import os
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("📁 Running file:", os.path.abspath(__file__))

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=["chrome-extension://gijlcdmofkoadbfhceicofnakijifgpk"])

# IP rate limiter setup
rate_limits = defaultdict(list)

@app.before_request
def limit_remote_addr():
    ip = request.remote_addr
    now = time.time()
    window = 60  # seconds
    limit = 30   # max requests per IP per window

    # Remove old requests from window
    rate_limits[ip] = [t for t in rate_limits[ip] if now - t < window]
    rate_limits[ip].append(now)

    if len(rate_limits[ip]) > limit:
        return jsonify({"error": "Too many requests"}), 429

# Load Gemini API key from environment
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

@app.route("/")
def home():
    return "✅ Hello from Flask!"

@app.route("/check", methods=["POST"])
def check():
    print("🛠️ DEBUG: Entered /check route")

    try:
        data = request.get_json(force=True, silent=True)
        print("📥 DEBUG: Parsed JSON:", data)

        if not data or "domain" not in data:
            print("❗ Missing domain key in data")
            return jsonify({"error": "Missing 'domain' field in request"}), 400

        prompt_text = data["domain"]

        prompt = f"""
Evaluate whether this domain or email address could be used in a phishing attempt: {prompt_text}

Respond ONLY in valid JSON like this:
{{
  "risk": "Low",
  "summary": "Brief one-sentence summary",
  "watchFor": ["Red flag 1", "Red flag 2"],
  "advice": "One-sentence user guidance"
}}
"""

        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": GEMINI_API_KEY
        }

        body = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ]
        }

        response = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent",
            headers=headers,
            json=body
        )

        result = response.json()
        print("📄 Gemini raw response:", result)

        if "candidates" in result and result["candidates"]:
            gemini_text = result["candidates"][0]["content"]["parts"][0]["text"]
            print("🗃 Gemini response text:", gemini_text)

            try:
                parsed = json.loads(gemini_text)
                return jsonify(parsed)
            except Exception as e:
                print("❌ JSON parse error:", str(e))
                return jsonify({
                    "error": "Could not parse Gemini output",
                    "raw_output": gemini_text,
                    "exception": str(e)
                }), 500
        else:
            return jsonify({"error": "No valid response from Gemini"}), 500

    except Exception as e:
        print("❌ Gemini request failed:", str(e))
        return jsonify({
            "error": "Request to Gemini API failed",
            "message": str(e)
        }), 500


# Start the Flask app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
