from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests

print("📁 Running file:", os.path.abspath(__file__))

app = Flask(__name__)
CORS(app)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

@app.route("/")
def home():
    return "✅ Hello from Flask!"

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    print("🔥 /check endpoint was hit with:", data)

    if not data or 'text' not in data:
        return jsonify({"error": "Missing 'text' field in request"}), 400

    prompt_text = data['text']

    # Call Gemini API
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": GEMINI_API_KEY
    }

    body = {
        "contents": [
            {
                "parts": [
                    {"text": f"Is the following text potentially a phishing attempt?\n\n{prompt_text}"}
                ]
            }
        ]
    }

    try:
        response = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
            headers=headers,
            json=body
        )
        result = response.json()
        print("📨 Gemini raw response:", result)

        if "candidates" in result:
            gemini_response = result["candidates"][0]["content"]["parts"][0]["text"]
            return jsonify({"response": gemini_response})
        else:
            return jsonify({"error": "Gemini API call failed", "details": result}), 400

    except Exception as e:
        return jsonify({"error": "Request to Gemini API failed", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
