import os
import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import google.generativeai as genai

app = FastAPI()

# This is the bridge. It allows your Cloudflare Pages frontend to talk to this backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# We will securely inject the API key later in Render
api_key = os.environ.get("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-3.1-flash')

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
            response = model.generate_content([prompt, request.payload])
        else:
            # Parse the base64 image coming from the frontend
            header, encoded = request.payload.split(",", 1)
            mime_type = header.split(":")[1].split(";")[0]
            image_part = {
                "mime_type": mime_type,
                "data": encoded
            }
            response = model.generate_content([prompt, image_part])
        
        # Strip out any markdown formatting the LLM might try to add
        raw_text = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(raw_text)
        
    except Exception as e:
        return {"error": str(e)}
