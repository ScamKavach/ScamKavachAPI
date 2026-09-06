import os
import json
import base64
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from google.genai import types

app = FastAPI()

# Cross-Origin Bridge
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Securely initialize the new GenAI client
api_key = os.environ.get("GEMINI_API_KEY")
if api_key:
    client = genai.Client(api_key=api_key)

class ScanRequest(BaseModel):
    mode: str
    payload: str

@app.post("/scan")
async def scan_threat(request: ScanRequest):
    if not api_key:
        return {"error": "API Key not configured on server."}

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
    
    try:
        if request.mode == 'text':
            # Text Analysis Pipeline
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=[prompt, request.payload]
            )
        else:
            # Multimodal Vision Pipeline (OCR & Image parsing)
            header, encoded = request.payload.split(",", 1)
            mime_type = header.split(":")[1].split(";")[0]
            
            image_bytes = base64.b64decode(encoded)
            image_part = types.Part.from_bytes(data=image_bytes, mime_type=mime_type)
            
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=[prompt, image_part]
            )
        
        # Clean the response to guarantee flawless UI rendering
        raw_text = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(raw_text)
        
    except Exception as e:
        return {"error": str(e)}
