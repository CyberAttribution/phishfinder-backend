from flask import Flask, request, jsonify
import requests
import json
import os

app = Flask(__name__)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")  # Set this in your .env or Render environment
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"

@app.route("/check", methods=["POST"])
def check():
    try:
        data = request.get_json()

    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in request"}), 400
        print("📩 Incoming request data:", data)

        domain = data["domain"]
        input_text = data.get("text", "")

        prompt = (
            f"Is the following domain suspicious or used in phishing? Provide a short explanation.\n\n"
            f"Domain: {domain}\n\nContext: {input_text}"
        )

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
            ]
        }

        url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
        print("🌐 Sending request to:", url)
        print("📤 Body:", json.dumps(body))

        response = requests.post(url, headers=headers, json=body)

        if not response.ok:
            print("❌ Gemini response error:", response.status_code, response.text)
            return jsonify({"error": "Request to Gemini failed", "status": response.status_code}), 500

        result = response.json()
        print("🧠 Gemini raw response:", result)

        if "candidates" in result and result["candidates"]:
            try:
                gemini_text = result["candidates"][0]["content"]["parts"][0]["text"]
                print("✅ Gemini extracted text:", gemini_text)
                parsed = json.loads(gemini_text)
                return jsonify(parsed)
            except Exception as e:
                print("❗️JSON parsing failed:", str(e))
                return jsonify({
                    "error": "Could not parse Gemini output",
                    "raw_output": gemini_text,
                    "exception": str(e)
                }), 500
        else:
            print("⚠️ No valid candidates in Gemini response.")
            return jsonify({"error": "No valid response from Gemini"}), 500

    except Exception as e:
        print("🔥 Unexpected server error:", str(e))
        return jsonify({"error": "Internal server error", "exception": str(e)}), 500
