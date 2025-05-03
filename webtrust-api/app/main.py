from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import psycopg
from pydantic import BaseModel
import whois
from urllib.parse import urlparse
import json
from datetime import datetime

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
        
        return {
            "status": "ok",
            "message": "This is a sample analysis.",
            "domain": domain,
            "whois": whois_data
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"エラーが発生しました: {str(e)}",
            "domain": request.url
        }
