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
from openai import OpenAI

load_dotenv()

class UrlRequest(BaseModel):
    url: str

app = FastAPI()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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
        
def check_phishing(url):
    """
    PhishTank APIを使用してURLがフィッシングサイトかどうかを確認する
    注意: Sprint 5の要件に従い、この機能は無効化されています
    """
    return {
        "phishing": False,
        "phish_detail_url": "",
        "error": None
    }

def analyze_with_gpt(data):
    """
    GPT-4oを使用してURLのリスク評価を行う
    """
    try:
        if not os.getenv("OPENAI_API_KEY"):
            return {
                "ai_error": True,
                "error_message": "OpenAI APIキーが設定されていません"
            }
        
        prompt = f"""

以下のウェブサイト情報を分析し、セキュリティリスクを評価してください。

- URL: {data.get('domain', 'N/A')}
- WHOIS情報:
  - 登録者: {data.get('whois', {}).get('registrar', 'N/A')}
  - 作成日: {data.get('whois', {}).get('creation_date', 'N/A')}
  - 有効期限: {data.get('whois', {}).get('expiration_date', 'N/A')}

- SSL/TLS証明書: {"あり" if data.get('certificate') else "なし"}
"""

        if data.get('certificate'):
            prompt += f"""
  - 発行者: {data.get('certificate', {}).get('issuer', {}).get('common_name', 'N/A')}
  - 有効期間: {data.get('certificate', {}).get('valid_from', 'N/A')} から {data.get('certificate', {}).get('valid_to', 'N/A')}
"""

        prompt += f"""
- 脅威検出: {"あり" if data.get('threat', False) else "なし"}
"""

        if data.get('threat', False):
            prompt += f"""
  - 脅威タイプ: {', '.join(data.get('threat_types', []))}
"""

        prompt += """
以下の形式で回答してください：

1. リスクスコア: 0から100の整数で、数値が高いほどリスクが高いことを示す
2. 要約: サイトのリスク評価の簡潔な要約（日本語、100文字以内）
3. 判定: 以下のいずれかを選択
   - 安全: リスクスコアが0-30
   - 注意: リスクスコアが31-70
   - 危険: リスクスコアが71-100

回答は以下のJSON形式で返してください：
```json
{
  "risk_score": <整数値>,
  "summary": "<要約文>",
  "judgment": "<安全/注意/危険>"
}
```
"""

        response = client.chat.completions.create(
            model="gpt-4o",  # gpt-4oが利用できない場合はgpt-4を使用
            messages=[
                {"role": "system", "content": "あなたはウェブサイトのセキュリティリスクを評価する専門家です。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,  # 一貫性のある回答を得るために低い温度を設定
        )
        
        response_text = response.choices[0].message.content
        
        json_start = response_text.find('{')
        json_end = response_text.rfind('}') + 1
        
        if json_start >= 0 and json_end > json_start:
            json_str = response_text[json_start:json_end]
            try:
                result = json.loads(json_str)
                return {
                    "ai_risk_score": result.get("risk_score", 0),
                    "ai_summary": result.get("summary", "評価できませんでした"),
                    "ai_judgment": result.get("judgment", "安全"),
                    "ai_error": False
                }
            except json.JSONDecodeError:
                return {
                    "ai_error": True,
                    "error_message": "AIレスポンスの解析に失敗しました"
                }
        else:
            return {
                "ai_error": True,
                "error_message": "AIレスポンスからJSONを抽出できませんでした"
            }
    
    except Exception as e:
        return {
            "ai_error": True,
            "error_message": f"AIリスク評価エラー: {str(e)}"
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
        phishing_check = check_phishing(request.url)
        certificate_info = get_ssl_certificate(request.url)
        
        response = {
            "status": "ok",
            "message": "This is a sample analysis.",
            "domain": domain,
            "whois": whois_data,
            "threat": safety_check.get("threat", False),
            "threat_types": safety_check.get("threat_types", []),
            "safety_error": safety_check.get("error"),
            "phishing": phishing_check.get("phishing", False),
            "phish_detail_url": phishing_check.get("phish_detail_url", ""),
            "phishing_error": phishing_check.get("error")
        }
        
        if certificate_info:
            response["certificate"] = certificate_info
        
        # GPT-4oを使用したAIリスク評価を追加
        ai_assessment = analyze_with_gpt(response)
        response.update(ai_assessment)
        
        return response
    except Exception as e:
        return {
            "status": "error",
            "message": f"エラーが発生しました: {str(e)}",
            "domain": request.url
        }
