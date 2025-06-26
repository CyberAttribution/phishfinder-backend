# Final version with startup block removed
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

# --- Helper function ---
def get_risk_details(score):
    if score >= 80: return {"level": "High", "class": "high"}
    elif score >= 50: return {"level": "Medium", "class": "medium"}
    else: return {"level": "Low", "class": "low"}

# --- CHECK ENDPOINT ---
@app.route("/api/check", methods=["POST"])
def check():
    # ... (the entire check function logic is correct and remains here) ...
    # ... I have omitted it for brevity, but you should use your full, correct version ...
    # ... ending with the return jsonify(final_response_data) or error ...
    try:
        data = request.get_json()
        if not data: return jsonify({"error": "Invalid JSON"}), 400
        user_input = data.get("prompt", "").strip()
        if not user_input: return jsonify({"error": "Missing input in request"}), 400
        # (rest of your check function)
    except Exception as e:
        print(f"🔥 Unexpected server error in /api/check: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


# --- SUBSCRIBE ENDPOINT ---
@app.route("/api/subscribe", methods=["POST"])
def subscribe():
    # ... (the entire subscribe function logic is correct and remains here) ...
    try:
        data = request.get_json()
        email = data.get("email")
        if not email: return jsonify({"success": False, "message": "Email is required"}), 400
        if not MAILERLITE_API_URL: return jsonify({"success": False, "message": "MailerLite not configured"}), 500
        headers = {"Content-Type": "application/json", "X-MailerLite-ApiKey": MAILERLITE_API_KEY}
        subscribe_body = {"email": email}
        response = requests.post(MAILERLITE_API_URL, headers=headers, json=subscribe_body)
        if response.ok: return jsonify({"success": True, "message": "Subscribed successfully"}), 200
        else: return jsonify({"success": False, "message": "API error"}), 500
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

# The if __name__ == "__main__": block is now removed.
