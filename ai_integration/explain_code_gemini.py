# ai_integration/explain_code_gemini.py

import google.generativeai as genai
import os
import sys

print(f"DEBUG: Python executable: {sys.executable}", file=sys.stderr)
print(f"DEBUG: sys.path: {sys.path}", file=sys.stderr)

# --- Configuration ---
# This retrieves your API key from the environment variable we set earlier
API_KEY = os.getenv("GOOGLE_API_KEY")
if not API_KEY:
    print("Error: GOOGLE_API_KEY environment variable not set. Please set it securely.", file=sys.stderr)
    sys.exit(1)

genai.configure(api_key=API_KEY)

# We'll use the 'gemini-pro' model, which is good for text and code tasks.
MODEL_NAME = 'gemini-1.5-pro-latest'
model = genai.GenerativeModel(MODEL_NAME)

# --- Core Functionality ---
def get_gemini_explanation(code_input: str) -> str:
    """
    Sends code to Gemini for explanation and returns the response.
    """
    if not code_input.strip():
        return "Error: No code provided to Gemini for explanation."

    # This is the instruction we give Gemini
    prompt_template = f"""
    You are an expert software engineer assistant. Explain the following code snippet in detail,
    focusing on its purpose, functionality, and any best practices or potential improvements.
    Provide your explanation in clear, concise markdown format.

    Code Snippet:
    ```
    {code_input}
    ```
    """
    try:
        response = model.generate_content(prompt_template)
        return response.text
    except Exception as e:
        # If there's an error talking to Gemini
        return f"Error communicating with Gemini: {e}"

# --- How the script runs when called ---
if __name__ == "__main__":
    # --- MODIFIED: Get code from command-line argument ---
    if len(sys.argv) > 1:
        code_from_editor = sys.argv[1]
    else:
        print("Error: No code provided as a command-line argument.", file=sys.stderr)
        sys.exit(1)

    explanation = get_gemini_explanation(code_from_editor)
    print(explanation) # Print Gemini's response so Cursor/VS Code can see it