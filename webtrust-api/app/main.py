from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import psycopg
from pydantic import BaseModel
import whois
from urllib.parse import urlparse
import json
import requests
import os
import ssl
import socket
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

def get_ssl_certificate(url):
    """
    URLからSSL/TLS証明書情報を取得する
    """
    parsed_url = urlparse(url)
    
    if parsed_url.scheme != 'https':
        return None
    
    hostname = parsed_url.netloc
    port = 443  # HTTPSのデフォルトポート
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                result = {
                    "common_name": None,
                    "issuer": {},
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "subject_alt_names": []
                }
                
                for item in cert.get("subject", []):
                    for key, value in item:
                        if key == "commonName":
                            result["common_name"] = value
                
                for item in cert.get("issuer", []):
                    for key, value in item:
                        if key == "commonName":
                            result["issuer"]["common_name"] = value
                        elif key == "organizationName":
                            result["issuer"]["organization"] = value
                        elif key == "countryName":
                            result["issuer"]["country"] = value
                
                for ext in cert.get("subjectAltName", []):
                    if ext[0] == "DNS":
                        result["subject_alt_names"].append(ext[1])
                
                return result
    except Exception as e:
        return {
            "error": f"証明書取得エラー: {str(e)}"
        }

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
        
        certificate_info = get_ssl_certificate(request.url)
        
        response = {
            "status": "ok",
            "message": "This is a sample analysis.",
            "domain": domain,
            "whois": whois_data,
            "threat": safety_check.get("threat", False),
            "threat_types": safety_check.get("threat_types", []),
            "safety_error": safety_check.get("error")
        }
        
        if certificate_info:
            response["certificate"] = certificate_info
        
        return response
    except Exception as e:
        return {
            "status": "error",
            "message": f"エラーが発生しました: {str(e)}",
            "domain": request.url
        }
