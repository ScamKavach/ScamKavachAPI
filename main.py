import os
import json
import base64
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from google.genai import types

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Fetch the comma-separated keys and create a list
keys_env = os.environ.get("GEMINI_API_KEY", "")
API_KEYS = [k.strip() for k in keys_env.split(",") if k.strip()]

class ScanRequest(BaseModel):
    mode: str
    payload: str

@app.post("/scan")
async def scan_threat(request: ScanRequest):
    if not API_KEYS:
        return {"error": "No API Keys configured on server."}

    prompt = """
    You are 'ScamKavach', a highly advanced cybersecurity threat intelligence AI. 
    Analyze the provided message or image for scams, phishing, social engineering, or fraud.
    Return ONLY a valid JSON object with the following exact structure (no markdown, no backticks, no extra text):
    {
        "score": integer (0-100, 100 being critical risk),
        "classification": "Short Title (e.g. Financial Impersonation, Fake Job Offer, Safe Communication)",
        "risk_level": "CRITICAL RISK" | "ELEVATED RISK" | "LOW RISK",
        "entities": [ {"title": "Entity Type (e.g. Suspicious URL, UPI ID, Phone Number)", "value": "The extracted value"} ] (max 2),
        "heuristics": [ {"title": "Signal Name", "desc": "Why it is suspicious or safe"} ] (max 2),
        "mitigation": [ "Actionable step 1", "Actionable step 2" ] (max 3)
    }
    """
    
    last_error = ""
    
    # Loop through the available API keys
    for key in API_KEYS:
        try:
            # Initialize client with the current key in the loop
            client = genai.Client(api_key=key)
            
            if request.mode == 'text':
                response = client.models.generate_content(
                    model='gemini-3.6-flash',
                    contents=[prompt, request.payload]
                )
            else:
                header, encoded = request.payload.split(",", 1)
                mime_type = header.split(":")[1].split(";")[0]
                image_bytes = base64.b64decode(encoded)
                image_part = types.Part.from_bytes(data=image_bytes, mime_type=mime_type)
                
                response = client.models.generate_content(
                    model='gemini-3.6-flash',
                    contents=[prompt, image_part]
                )
            
            raw_text = response.text.replace('```json', '').replace('```', '').strip()
            return json.loads(raw_text)
            
        except Exception as e:
            error_msg = str(e)
            last_error = error_msg
            
            # If it's a rate limit (429) or temporary overload (503), try the next key
            if "429" in error_msg or "503" in error_msg:
                print(f"Key failed with {error_msg[:20]}... Switching to next key.")
                continue
            else:
                # If it's a different error (like bad formatting), break and return it
                return {"error": error_msg}

    # If all keys are exhausted and return 429s
    return {"error": f"All API keys exhausted. Last error: {last_error}"}
