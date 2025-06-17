from collections import defaultdict
import time

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os
import requests

load_dotenv()

print("📁 Running file:", os.path.abspath(__file__))

app = Flask(__name__)
CORS(app, origins=["chrome-extension://gijlcdmofkoadbfhceicofnakijifgpk"])
rate_limits = defaultdict(list)

@app.before_request
def limit_remote_addr():
    ip = request.remote_addr
    now = time.time()
    window = 60  # seconds
    limit = 30   # max requests per IP per window

    # Keep only recent requests
    rate_limits[ip] = [t for t in rate_limits[ip] if now - t < window]
    rate_limits[ip].append(now)

    if len(rate_limits[ip]) > limit:
        return jsonify({"error": "Too many requests"}), 429

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

@app.route("/")
def home():
    return "✅ Hello from Flask!"

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    print("🔥 /check endpoint was hit with:", data)
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' field in request"}), 400

    prompt_text = data["domain"]


    # Call Gemini API
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": GEMINI_API_KEY
    }

    prompt = f"""
Evaluate whether this domain or email address could be used in a phishing attempt: {prompt_text}

Respond in this format:

- Phishing Risk: [Low / Moderate / High]
- Summary: A clear 1–3 sentence overview
- What to Watch For: Bullet points of risk indicators
- Advice: A single sentence of guidance

Keep it professional and concise, as if for a browser security tool.
"""

    body = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }

    try:
        response = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent",
            headers=headers,
            json=body
        )
        result = response.json()
        print("📄 Gemini raw response:", result)

        if "candidates" in result:
            gemini_response = result["candidates"][0]["content"]["parts"][0]["text"]
            return jsonify({"response": gemini_response})
        else:
            return jsonify({"error": "No response or unclear result."}), 400

    except Exception as e:
        return jsonify({"error": "Request to Gemini API failed", "message": str(e)}), 500



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)


