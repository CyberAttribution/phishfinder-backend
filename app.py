from flask import Flask, request, jsonify
import requests
import json
import os
import time # <--- ADDED: Import the time library

app = Flask(__name__)

# --- CONFIGURATION ---
# Load API keys from environment variables
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
MAILERLITE_API_KEY = os.environ.get("MAILERLITE_API_KEY")
MAILERLITE_GROUP_ID = os.environ.get("MAILERLITE_GROUP_ID")

# Define API URLs
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent"
MAILERLITE_API_URL = f"https://api.mailerlite.com/api/v2/groups/{MAILERLITE_GROUP_ID}/subscribers"

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
        
        # --- ADDED: Timing for Gemini API call ---
        gemini_call_start_time = time.time()
        print(f"[{gemini_call_start_time:.0f}] 🌐 Sending request to Gemini API...")

        response = requests.post(url, headers=headers, json=body)

        gemini_call_end_time = time.time()
        duration = gemini_call_end_time - gemini_call_start_time
        print(f"[{gemini_call_end_time:.0f}] 🧠 Received response from Gemini. The API call took: {duration:.2