<<<<<<< Updated upstream
# Final version for Alpha Test - June 26 (Specific CORS for Extension)
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
=======
# --- Imports ---
from dotenv import load_dotenv
load_dotenv() # Load environment variables first

>>>>>>> Stashed changes
import os
import time
import re
import json
import whois
from datetime import datetime
from dns import resolver
<<<<<<< Updated upstream
import logging # <-- ADDED

# --- START: ROBUST STARTUP LOGGING AND ERROR HANDLING ---
# Configure logging to output to the console, which will be captured by Render.
# This is the most important step for debugging silent crashes.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# --- END: ROBUST STARTUP LOGGING AND ERROR HANDLING ---
=======
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from celery import Celery
# Note: Playwright and asyncio are only used by the worker, but we keep imports here for clarity
# In a larger project, tasks would be in their own file.
>>>>>>> Stashed changes

# --- Flask & Celery Initialization ---
app = Flask(__name__)
<<<<<<< Updated upstream
logging.info("Flask app object created.")

# --- THIS IS THE FINAL, CORRECT CORS CONFIGURATION ---
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://phishfinder.bot", 
            "https://phishfinderbot.wpenginepowered.com",
            "chrome-extension://jamobibjpfcllagcdmefmnplcmobldbb" # <-- YOUR EXTENSION ID
        ]
    }
})
logging.info("CORS configured.")

# --- CONFIGURATION ---
# We wrap the entire startup configuration in a try...except block.
# If the app crashes here, the exception will be logged.
try:
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
    MAILERLITE_API_KEY = os.environ.get("MAILERLITE_API_KEY")
    MAILERLITE_GROUP_ID = os.environ.get("MAILERLITE_GROUP_ID")
    logging.info("Attempting to load environment variables.")
    
    # Check if keys are loaded and log a warning if they are not
    if not GEMINI_API_KEY:
        logging.warning("GEMINI_API_KEY environment variable is NOT SET.")
    if not MAILERLITE_API_KEY:
        logging.warning("MAILERLITE_API_KEY environment variable is NOT SET.")
    if not MAILERLITE_GROUP_ID:
        logging.warning("MAILERLITE_GROUP_ID environment variable is NOT SET.")

    GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent"
    
    if MAILERLITE_GROUP_ID:
        MAILERLITE_API_URL = f"https://api.mailerlite.com/api/v2/groups/{MAILERLITE_GROUP_ID}/subscribers"
        logging.info("MailerLite API URL configured successfully.")
    else:
        MAILERLITE_API_URL = None
        logging.warning("MailerLite API URL is not configured because MAILERLITE_GROUP_ID is missing.")

except Exception as e:
    # This is the crucial part. It will catch any exception during startup.
    logging.critical(f"FATAL ERROR DURING STARTUP CONFIGURATION: {e}", exc_info=True)
    # The `exc_info=True` part will print the full error traceback.
    
logging.info("Initial configuration block completed.")

# --- ALLOW-LIST ---
=======
CORS(app, resources={r"/api/*": {"origins": "*"}}) # Using a wildcard for local testing is fine

app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# --- App Configuration & Helpers ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
# (Your other configuration and allow-list can be placed here)
>>>>>>> Stashed changes
ALLOW_LIST = {
    "cyberattribution.ai", "aarp.org", "ncoa.org", "consumerfed.org",
    "cyberseniors.org", "pta.org", "consumer.ftc.gov", "bbb.org",
    "idtheftcenter.org", "lifelock.com", "phishfinder.bot",
    "attributionengine.bot", "attributionagent.com", "attributionagent.ai",
    "deerpfakedefender.ai"
}
<<<<<<< Updated upstream
logging.info("Allow-list loaded.")

# --- Helper function to map score to risk level/class ---
=======
>>>>>>> Stashed changes
def get_risk_details(score):
    if score >= 80:
        return {"level": "High", "class": "high"}
    elif score >= 50:
        return {"level": "Medium", "class": "medium"}
    else:
        return {"level": "Low", "class": "low"}

<<<<<<< Updated upstream
logging.info("Helper function defined. Registering API routes.")

# --- CHECK ENDPOINT ---
@app.route("/api/check", methods=["POST"])
def check():
    # Using app.logger which is tied to the Flask app instance
    app.logger.info(f"--- Check request received from {request.remote_addr} ---")

    try:
        data = request.get_json()
        if not data:
            app.logger.warning("Request received with invalid JSON.")
            return jsonify({"error": "Invalid JSON"}), 400
        
        user_input = data.get("prompt", "").strip()
        if not user_input:
            app.logger.warning("⚠️ Missing 'prompt' in request.")
            return jsonify({"error": "Missing input in request"}), 400

        analysis_target = ""
        # Input Detection Logic
        if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
            app.logger.info(f"✅ Input detected as an EMAIL: {user_input}")
            username, domain_from_email = user_input.split('@', 1)
            analysis_target = domain_from_email.lower()
        else:
            app.logger.info(f"✅ Input detected as a DOMAIN/URL: {user_input}")
            match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
            if match:
                analysis_target = match.group(1).lower()
            else:
                analysis_target = user_input.lower()

        prompt_template = (
            "You are PhishFinder. Analyze the potential phishing risk of the following input: '{user_input}'. "
            "The extracted domain for analysis is '{analysis_target}'. Key evidence to consider: "
            "Domain Creation Date: {creation_date_str}. MX Records Found: {mx_records_found}. "
            "Provide a risk score (1-100), a concise summary, a list of warning signs ('watchFor'), and brief 'advice' for a non-technical user. "
            "Also generate a 'security_alert' for IT staff and a 'social_post' for public awareness. "
            "Format the entire response as a single JSON object."
        )

        if analysis_target in ALLOW_LIST:
            app.logger.info(f"✅ Domain '{analysis_target}' found in the Allow-List.")
            return jsonify({
                "risk": {"level": "Low", "class": "low", "score": 0},
                "summary": f"The domain '{analysis_target}' is a known, trusted entity.",
                "watchFor": ["This domain is on our internal allow-list of trusted sites."],
                "advice": "This site is considered safe.",
                "domainAge": "N/A",
                "mxRecords": "N/A",
                "generated": {"securityAlert": "N/A", "socialPost": "N/A"},
                "rawInput": user_input
            })
        
        creation_date_str = "Not available"
        try:
            domain_info = whois.whois(analysis_target)
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            if creation_date:
                creation_date_str = creation_date.strftime("%Y-%m-%d")
            app.logger.info(f"ℹ️ WHOIS Creation Date for {analysis_target}: {creation_date_str}")
        except Exception as e:
            app.logger.warning(f"⚠️ WHOIS lookup failed for {analysis_target}: {e}")

        mx_records_found = "No"
        try:
            records = resolver.resolve(analysis_target, 'MX')
            if records:
                mx_records_found = "Yes"
            app.logger.info(f"ℹ️ DNS MX Records Found for {analysis_target}: {mx_records_found}")
        except Exception as e:
            app.logger.warning(f"⚠️ DNS MX lookup failed for {analysis_target}: {e}")

        prompt = prompt_template.format(user_input=user_input, analysis_target=analysis_target, creation_date_str=creation_date_str, mx_records_found=mx_records_found)
        
        if not GEMINI_API_KEY:
            app.logger.error("❌ GEMINI_API_KEY is not set. Cannot proceed with Gemini request.")
            return jsonify({"error": "API key not configured"}), 500

        headers = {"Content-Type": "application/json"}
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "response_mime_type": "application/json",
                "response_schema": {
                    "type": "object",
                    "properties": {
                        "risk_score": {"type": "integer"}, "summary": {"type": "string"},
                        "watchFor": {"type": "array", "items": {"type": "string"}},
                        "advice": {"type": "string"}, "security_alert": {"type": "string"},
                        "social_post": {"type": "string"}
                    },
                    "required": ["risk_score", "summary", "watchFor", "advice", "security_alert", "social_post"]
                }
            }
        }
        url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
        
        response = requests.post(url, headers=headers, json=body)

        if not response.ok:
            app.logger.error(f"❌ Gemini error: {response.status_code} {response.text}")
            return jsonify({"error": "Gemini request failed"}), response.status_code

        result = response.json()

        if "candidates" in result and result["candidates"]:
            gemini_output_json_str = result["candidates"][0]["content"]["parts"][0]["text"]
            gemini_data = json.loads(gemini_output_json_str)
            
            risk_score = gemini_data.get("risk_score", 0)
            risk_details = get_risk_details(risk_score)
            
            final_response_data = {
                "risk": {
                    "level": risk_details["level"], "class": risk_details["class"],
                    "score": risk_score
                },
                "summary": gemini_data.get("summary", "No summary provided."),
                "watchFor": gemini_data.get("watchFor", []),
                "advice": gemini_data.get("advice", "No advice provided."),
                "domainAge": creation_date_str,
                "mxRecords": mx_records_found,
                "generated": {
                    "securityAlert": gemini_data.get("security_alert", ""),
                    "socialPost": gemini_data.get("social_post", "")
                },
                "rawInput": user_input
            }
            
            return jsonify(final_response_data)
        else:
            app.logger.warning("⚠️ Gemini response had no valid candidates.")
            return jsonify({"error": "No valid response from Gemini"}), 500

    except Exception as e:
        app.logger.error(f"🔥 Unexpected server error in /api/check: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

# --- SUBSCRIBE ENDPOINT ---
@app.route("/api/subscribe", methods=["POST"])
def subscribe():
    app.logger.info(f"--- Subscribe request received from {request.remote_addr} ---")
    try:
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"success": False, "message": "Email is required"}), 400
        if not MAILERLITE_API_URL:
            app.logger.error("❌ MailerLite not configured. Cannot subscribe user.")
            return jsonify({"success": False, "message": "MailerLite not configured"}), 500
        headers = {"Content-Type": "application/json", "X-MailerLite-ApiKey": MAILERLITE_API_KEY}
        subscribe_body = {"email": email}
        response = requests.post(MAILERLITE_API_URL, headers=headers, json=subscribe_body)
        if response.ok:
            return jsonify({"success": True, "message": "Subscribed successfully"}), 200
        else:
            app.logger.error(f"❌ MailerLite API error: {response.status_code} {response.text}")
            return jsonify({"success": False, "message": "API error"}), 500
    except Exception as e:
        app.logger.error(f"🔥 Unexpected server error in /api/subscribe: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

logging.info("Application startup sequence complete. Waiting for requests.")

# Note: The 'if __name__ == "__main__":' block is intentionally omitted
# because a production WSGI server like Gunicorn is used for deployment.
=======

# --- Celery Background Task ---
@celery.task
def long_running_analysis_task(user_input):
    """
    This background task contains all the original logic from your /api/check endpoint.
    """
    print(f"WORKER: Starting full analysis for '{user_input}'...")
    # --- Start of analysis logic ---
    analysis_target = ""
    if re.match(r"[^@]+@[^@]+\.[^@]+", user_input):
        _, domain_from_email = user_input.split('@', 1)
        analysis_target = domain_from_email.lower()
    else:
        match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', user_input)
        analysis_target = match.group(1).lower() if match else user_input.lower()

    if analysis_target in ALLOW_LIST:
        return {"status": "Complete", "result": {"risk": {"level": "Low", "score": 0}, "summary": "Domain is on allow-list."}}

    creation_date_str = "Not available"
    try:
        domain_info = whois.whois(analysis_target)
        creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
        if creation_date:
            creation_date_str = creation_date.strftime("%Y-%m-%d")
    except Exception as e:
        print(f"WORKER: WHOIS failed: {e}")

    mx_records_found = "No"
    try:
        if resolver.resolve(analysis_target, 'MX'):
            mx_records_found = "Yes"
    except Exception as e:
        print(f"WORKER: MX lookup failed: {e}")

    prompt_template = (
        "You are PhishFinder. Analyze the potential phishing risk of the following input: '{user_input}'. "
        "The extracted domain for analysis is '{analysis_target}'. Key evidence to consider: "
        "Domain Creation Date: {creation_date_str}. MX Records Found: {mx_records_found}. "
        "Provide a risk score (1-100), a concise summary, a list of warning signs ('watchFor'), and brief 'advice' for a non-technical user. "
        "Format the entire response as a single JSON object with keys: risk_score, summary, watchFor, advice."
    )
    prompt = prompt_template.format(user_input=user_input, analysis_target=analysis_target, creation_date_str=creation_date_str, mx_records_found=mx_records_found)
    
    headers = {"Content-Type": "application/json"}
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"response_mime_type": "application/json", "response_schema": { "type": "object", "properties": { "risk_score": {"type": "integer"}, "summary": {"type": "string"}, "watchFor": {"type": "array", "items": {"type": "string"}}, "advice": {"type": "string"} } } }
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent?key={GEMINI_API_KEY}"
    
    print("WORKER: Calling Gemini API...")
    response = requests.post(url, headers=headers, json=body)

    if not response.ok:
        return {"status": "Error", "result": f"Gemini API Error: {response.status_code}"}

    gemini_data = json.loads(response.json()["candidates"][0]["content"]["parts"][0]["text"])
    risk_score = gemini_data.get("risk_score", 0)
    risk_details = get_risk_details(risk_score)
    
    final_response_data = {
        "risk": {"level": risk_details["level"], "class": risk_details["class"], "score": risk_score},
        "summary": gemini_data.get("summary"),
        "watchFor": gemini_data.get("watchFor"),
        "advice": gemini_data.get("advice"),
        "domainAge": creation_date_str,
        "mxRecords": mx_records_found
    }
    print("WORKER: Analysis complete.")
    return {"status": "Complete", "result": final_response_data}


# --- API Endpoints ---
@app.route('/')
def home():
    return "PhishFinder Python Backend is running!"

@app.route("/api/check", methods=["POST"])
def check_start():
    data = request.get_json()
    user_input = data.get("prompt")
    if not user_input:
        return jsonify({"error": "Missing input"}), 400
    
    print(f"MANAGER: Received request for '{user_input}'. Sending to worker.")
    task = long_running_analysis_task.delay(user_input)
    
    return jsonify({"status": "pending", "task_id": task.id}), 202

@app.route("/api/result/<task_id>", methods=["GET"])
def get_result(task_id):
    task = celery.AsyncResult(task_id)
    if task.state == 'PENDING':
        response = {'state': task.state, 'status': 'Pending...'}
    elif task.state != 'FAILURE':
        response = {'state': task.state, 'data': task.info}
    else: # Task failed
        response = {'state': task.state, 'status': str(task.info)}
    return jsonify(response)


# (Your /api/subscribe endpoint would go here if needed)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    # Note: debug=False is better for production/staging environments
    app.run(host="0.0.0.0", port=port, debug=False)
>>>>>>> Stashed changes
