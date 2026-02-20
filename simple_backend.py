#!/usr/bin/env python3
"""
NEXUS Backend - Clean and stable
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import sys
import os
import hashlib
import re
import httpx
from datetime import datetime
from typing import List, Dict

app = FastAPI(title="NEXUS Backend", version="1.0.0")
app.mount("/static", StaticFiles(directory="."), name="static")


def stable_hash(identifier: str, salt: str = "") -> int:
    raw = f"{identifier.strip().lower()}{salt}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    return int(digest[:8], 16)


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "message": "NEXUS Backend is running", "version": "1.0.0"}


@app.post("/api/analyze")
async def analyze_endpoint(request: dict):
    identifier = request.get("identifier", "unknown")
    h_social   = stable_hash(identifier, "social")   % 30
    h_broker   = stable_hash(identifier, "broker")   % 30
    h_platform = stable_hash(identifier, "platform") % 20
    h_exp      = stable_hash(identifier, "exposure") % 40
    h_threat   = stable_hash(identifier, "threat")   % 5
    h_dark     = stable_hash(identifier, "dark")     % 10
    h_broker2  = stable_hash(identifier, "broker2")  % 15
    h_search   = stable_hash(identifier, "search")   % 200
    h_identity = stable_hash(identifier, "identity") % 300
    social_risk  = 60 + h_social
    broker_risk  = 40 + h_broker
    risk_score   = round((social_risk + broker_risk) / 2)
    threat_level = max(1, min(10, round(risk_score / 10) + h_threat % 2))
    if risk_score >= 75:   risk_status = "HIGH"
    elif risk_score >= 50: risk_status = "MODERATE"
    else:                  risk_status = "LOW"
    return {
        "identifier": identifier,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "platform_count": 25 + h_platform,
        "exposure_count": 80 + h_exp,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "risk_status": risk_status,
        "threats": [
            {"name": "Social Media Exposure", "icon": "📱", "risk": social_risk, "color": "#ff0055",
             "description": "Personal information exposed across social platforms",
             "severity": "High" if social_risk >= 75 else "Medium",
             "affected_platforms": ["Facebook", "Instagram", "Twitter"]},
            {"name": "Data Broker Networks", "icon": "💼", "risk": broker_risk, "color": "#ffaa00",
             "description": "Personal data sold by data aggregation companies",
             "severity": "High" if broker_risk >= 60 else "Medium",
             "affected_platforms": ["Acxiom", "Equifax", "Experian"]}
        ],
        "dark_web_findings": h_dark,
        "brokers_found": 20 + h_broker2,
        "search_engine_results": 300 + h_search,
        "identity_score": 400 + h_identity,
        "password_analysis": analyze_password_safety(identifier),
        "phone_analysis": analyze_phone_safety(identifier)
    }


def analyze_password_safety(identifier: str) -> dict:
    patterns = [r'\b\d{4,}\b', r'\b[a-zA-Z]{1,3}\d{2,4}\b', r'\bpassword\d*\b',
                r'\badmin\d*\b', r'\b123\b', r'\bqwerty\b', r'\babc123\b']
    found = [p for p in patterns if re.search(p, identifier.lower())]
    if found:
        score = max(10, 50 - len(found) * 10)
        level = "WEAK" if len(found) >= 3 else "MODERATE"
    else:
        score, level = 85, "STRONG"
    return {"detected_patterns": len(found), "safety_score": score, "safety_level": level,
            "recommendations": ["Use mixed case letters, numbers, and symbols",
                                 "Avoid common patterns and dictionary words",
                                 "Use at least 12 characters",
                                 "Enable two-factor authentication"]}


def analyze_phone_safety(identifier: str) -> dict:
    patterns = [r'\b\d{10}\b', r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
                r'\b\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
                r'\b\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}\b']
    found = list(set(m for p in patterns for m in re.findall(p, identifier)))
    if found:
        score = max(15, 70 - len(found) * 15)
        level = "HIGH RISK" if len(found) >= 2 else "MODERATE RISK"
    else:
        score, level = 90, "LOW RISK"
    return {"phone_numbers_found": len(found), "privacy_score": score, "privacy_level": level,
            "recommendations": ["Avoid sharing phone numbers publicly",
                                 "Use separate phone for online accounts",
                                 "Enable caller ID and spam protection",
                                 "Consider using VoIP services for privacy"]}




@app.get("/")
async def read_root():
    return FileResponse("index2.html")

@app.get("/index2.html")
async def serve_frontend():
    return FileResponse("index2.html")


if __name__ == "__main__":
    print("🚀 Starting NEXUS Backend Server...")
    print("📍 Server running on: http://localhost:8000")
    print("🌐 Open browser to: http://localhost:8000")
    print("⏹️  Press Ctrl+C to stop")
    print()
    try:
        uvicorn.run("simple_backend:app", host="localhost", port=8000, reload=False, log_level="info")
    except KeyboardInterrupt:
        print("\n✅ Server stopped gracefully")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
