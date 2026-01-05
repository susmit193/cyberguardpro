# gemini_integration.py
import os
from dotenv import load_dotenv, find_dotenv
import google.generativeai as genai

# -----------------------------------------------------
# Load environment variables securely from .env
# -----------------------------------------------------
dotenv_path = find_dotenv()
if dotenv_path:
    load_dotenv(dotenv_path)
else:
    load_dotenv()  # fallback to cwd if .env not found

# Cache selected model name for reuse
_SELECTED_MODEL_NAME = None


# -----------------------------------------------------
# Helper: Automatically pick a supported Gemini model
# -----------------------------------------------------
def _select_model_name(preferred_keywords=('1.5-flash', '2.5-flash', '2.5-pro', 'flash', 'pro', 'gemini')):
    """
    Select a supported model that implements generateContent.
    Returns the model name string or None if not found.
    """
    global _SELECTED_MODEL_NAME
    if _SELECTED_MODEL_NAME:
        return _SELECTED_MODEL_NAME

    try:
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        models_gen = genai.list_models()
    except Exception:
        return None

    # iterate models and pick the first matching preferred keyword
    for m in models_gen:
        name = getattr(m, 'name', None) or (m.get('name') if hasattr(m, 'get') else None)
        methods = getattr(m, 'supported_generation_methods', None) or (
            m.get('supported_generation_methods') if hasattr(m, 'get') else None
        )
        if not name or not methods:
            continue
        if 'generateContent' not in methods:
            continue
        lname = name.lower()
        for kw in preferred_keywords:
            if kw in lname:
                _SELECTED_MODEL_NAME = name
                return _SELECTED_MODEL_NAME

    # fallback: any model supporting generateContent
    try:
        models_gen = genai.list_models()
        for m in models_gen:
            name = getattr(m, 'name', None) or (m.get('name') if hasattr(m, 'get') else None)
            methods = getattr(m, 'supported_generation_methods', None) or (
                m.get('supported_generation_methods') if hasattr(m, 'get') else None
            )
            if name and methods and 'generateContent' in methods:
                _SELECTED_MODEL_NAME = name
                return _SELECTED_MODEL_NAME
    except Exception:
        return None

    return None


# -----------------------------------------------------
# Main function: Generate Gemini response
# -----------------------------------------------------
def try_gemini_api(prompt: str) -> str:
    """
    Generate a Gemini response for a given prompt.
    Returns the generated text or None on error.
    """
    try:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            print("❌ Gemini API key not found. Please set GEMINI_API_KEY in your .env file.")
            return None

        # Configure Gemini SDK
        genai.configure(api_key=api_key)

        # Prefer the light, free-tier-friendly model
        preferred_model = "gemini-2.0-flash"
        try:
            model = genai.GenerativeModel(preferred_model)
        except Exception as e:
            print(f"⚠️ Could not use {preferred_model}, trying fallback model: {e}")
            model_name = _select_model_name() or preferred_model
            model = genai.GenerativeModel(model_name)

        # Generate a concise, cybersecurity-focused response.
        # Instruct the model to refuse non-cybersecurity questions explicitly.
        system_instruction = (
            "You are a specialist cybersecurity assistant. ONLY answer cybersecurity-related "
            "questions (phishing, malware, breaches, passwords, 2FA, vulnerabilities, SSL/TLS, DNS, etc.). "
            "If the user asks about non-cyber topics, reply exactly: 'I can only assist with cybersecurity-related questions.' "
            "Provide concise, practical, and safe guidance."
        )
        response = model.generate_content(f"{system_instruction}\n\nUser: {prompt}\nAssistant:")

        # Safely extract text
        if hasattr(response, "text"):
            return response.text.strip()
        elif isinstance(response, dict):
            return response.get("text", "").strip()
        else:
            return str(response)

    except Exception as e:
        msg = str(e)
        # More descriptive error for quota/billing issues
        if '429' in msg or 'quota' in msg.lower() or 'Quota exceeded' in msg:
            print(
                f"🚫 Gemini API error (quota/billing): {msg}\n"
                "Please check your Google Cloud project billing and Gemini API quotas.\n"
                "Docs: https://ai.google.dev/gemini-api/docs/rate-limits"
            )
        else:
            print(f"Gemini API error: {msg}")
        return None
