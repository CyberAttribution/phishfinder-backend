from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/check", methods=["POST"])
def check():
    print("✅ Minimal app's /check route was hit successfully!")
    return jsonify({
        "summary": "This is a test response from the minimal 'hello world' app. The environment is working."
    })
