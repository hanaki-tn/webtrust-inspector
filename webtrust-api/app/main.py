from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import psycopg
from pydantic import BaseModel
import whois
from urllib.parse import urlparse
import json
import requests
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class UrlRequest(BaseModel):
    url: str

app = FastAPI()

# Disable CORS. Do not remove this for full-stack development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

def json_serial(obj):
    """JSONシリアライズできないオブジェクトを文字列に変換"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def check_url_safety(url):
    """
    Google Safe Browsing APIを使用してURLの安全性を確認する
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not api_key:
        return {
            "threat": False,
            "error": "APIキーが設定されていません"
        }
    
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "webtrust-api",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(api_url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        if "matches" in data and len(data["matches"]) > 0:
            threat_types = [match.get("threatType") for match in data["matches"]]
            return {
                "threat": True,
                "threat_types": threat_types
            }
        else:
            return {
                "threat": False
            }
    except Exception as e:
        return {
            "threat": False,
            "error": f"APIリクエストエラー: {str(e)}"
        }

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

@app.post("/analyze")
async def analyze(request: UrlRequest):
    """
    URLを分析するエンドポイント
    """
    try:
        parsed_url = urlparse(request.url)
        domain = parsed_url.netloc
        
        if not domain:
            domain = parsed_url.path
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        whois_info = whois.whois(domain)
        whois_data = json.loads(json.dumps(whois_info, default=json_serial))
        
        safety_check = check_url_safety(request.url)
        
        return {
            "status": "ok",
            "message": "This is a sample analysis.",
            "domain": domain,
            "whois": whois_data,
            "threat": safety_check.get("threat", False),
            "threat_types": safety_check.get("threat_types", []),
            "safety_error": safety_check.get("error")
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"エラーが発生しました: {str(e)}",
            "domain": request.url
        }
