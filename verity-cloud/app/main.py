from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import httpx
import asyncio
from typing import Optional, List, Dict
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Verity Cloud Enterprise Backend")

# Allow Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ThreatIntelRequest(BaseModel):
    url: str

class TelemetryReport(BaseModel):
    url: str
    feature_vector: Optional[List[float]] = None
    rule_score: Optional[int] = None
    ml_score: Optional[int] = None
    final_risk: Optional[int] = None
    action_taken: str # e.g. "PROCEED_ANYWAY"

# Simple in-memory cache for demo (Use Redis/SQLite in prod)
threat_cache: Dict[str, dict] = {}

# Remote threat intel lookup toggle (Opt-in only, OFF by default)
ENABLE_REMOTE_THREAT_INTEL = False

# Mock SafeBrowsing API Key (In production, load from env)
SAFE_BROWSING_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"

@app.post("/threat-intel/check")
async def check_threat_intel(req: ThreatIntelRequest):
    if not ENABLE_REMOTE_THREAT_INTEL:
        return {"malware": False, "source": None}

    url = req.url
    
    if url in threat_cache:
        return threat_cache[url]
        
    result = {"malware": False, "source": None}

    # Concurrently check SafeBrowsing and URLhaus
    async with httpx.AsyncClient() as client:
        # 1. URLhaus Check
        urlhaus_task = client.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=3.0
        )
        
        # 2. SafeBrowsing Check
        sb_body = {
            "client": {"clientId": "verity-cloud", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        sb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
        sb_task = None
        if SAFE_BROWSING_API_KEY != "YOUR_GOOGLE_SAFE_BROWSING_API_KEY":
            sb_task = client.post(sb_url, json=sb_body, timeout=3.0)

        tasks = [urlhaus_task]
        if sb_task:
            tasks.append(sb_task)

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        uh_res = responses[0]
        sb_res = responses[1] if len(responses) > 1 else None

        if not isinstance(uh_res, Exception) and uh_res.status_code == 200:
            data = uh_res.json()
            if data.get('query_status') == 'ok' and data.get('url_status') == 'online':
                result = {"malware": True, "source": "URLhaus"}
                threat_cache[url] = result
                return result

        if sb_res and not isinstance(sb_res, Exception) and sb_res.status_code == 200:
            data = sb_res.json()
            if data.get('matches') and len(data['matches']) > 0:
                result = {"malware": True, "source": "SafeBrowsing"}
                threat_cache[url] = result
                return result

    threat_cache[url] = result
    return result

@app.post("/telemetry/report")
async def report_telemetry(report: TelemetryReport):
    # In production, this would insert into a database for the Federated Learning loop
    print(f"[Verity Cloud] False Positive Reported for: {report.url}")
    print(f"Features: {report.feature_vector}")
    print(f"ML Score: {report.ml_score} | Rule Score: {report.rule_score}")
    
    return {"status": "success", "message": "Telemetry received for retraining"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
