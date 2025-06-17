from flask import Flask, request, jsonify
import requests
import json
import os

app = Flask(__name__)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")  # Set this in your .env or Render environment
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()

    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' in request"}), 400

    domain = data["domain"]
    input_text = data.get("text", "")

    prompt = f"Is the following domain suspicious or used in phishing? Provide a short explanation.\n\nDomain: {domain}\n\nContext: {input_text}"

    headers = {
        "Content-Type": "application/json"
    }

    body = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ]
    }

    response = requests.post(
        f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
        headers=headers,
        json=body
    )

    if not response.ok:
        return jsonify({"error": "Request to Gemini failed", "status": response.status_code}), 500

    result = response.json()
    print("🧠 Gemini raw response:", result)

    if "candidates" in result and result["candidates"]:
        gemini_text = result["candidates"][0]["content"]["parts"][0]["text"]
        print("🧠 Gemini response text:", gemini_text)

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


# Start the Flask app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
