from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app) # Enable CORS for the minimal app

@app.route("/check", methods=["POST"])
def check():
    print("✅ Minimal app's /check route was hit successfully!")
    return jsonify({
        "risk_score": 10,
        "summary": "This is a test response from the minimal 'hello world' app. If you see this, the core environment is working.",
        "indicators": ["Test successful."],
        "journalist_tips": ["Test successful."],
        "security_alert": "Test successful.",
        "social_post": "Test successful."
    })
