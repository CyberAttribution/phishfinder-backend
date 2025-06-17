from flask import Flask, request, jsonify
import requests
import json
import os

app = Flask(__name__)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")  # Set this in your .env or Render environment
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"

        print("📩 Incoming request data:", data)

    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in request"}), 400
        print("📩 Incoming request data:", data)@app.route("/check", methods=["POST"])
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
        print("🌐 Sending to Gemini:", url)
        print("📤 Request body:", body)

        response = requests.post(url, headers=headers, json=body)

        if not response.ok:
            print("❌ Gemini error:", response.status_code, response.text)
            return jsonify({"error": "Gemini request failed", "status": response.status_code}), 500

        result = response.json()
        print("🧠 Gemini raw response:", result)

        if "candidates" in result and result["candidates"]:
            gemini_text = result["candidates"][0]["content"]["parts"][0]["text"]
            print("✅ Gemini extracted text:", gemini_text)

            try:
                parsed = json.loads(gemini_text)
                return jsonify(parsed)
            except Exception as e:
                print("❗ JSON parse error:", str(e))
                return jsonify({
                    "error": "Could not parse Gemini output",
                    "raw_output": gemini_text,
                    "exception": str(e)
                }), 500
        else:
            print("⚠️ Gemini response had no valid candidates.")
            return jsonify({"error": "No valid response from Gemini"}), 500

    except Exception as e:
        print("🔥 Unexpected server error:", str(e))
        return jsonify({"error": "Internal server error", "exception": str(e)}), 500
