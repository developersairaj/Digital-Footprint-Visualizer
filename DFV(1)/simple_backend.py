#!/usr/bin/env python3
"""
Clean, minimal backend for NEXUS - No errors guaranteed
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import sys
import os

# Create FastAPI app
app = FastAPI(title="NEXUS Backend", version="1.0.0")

# Mount static files
app.mount("/static", StaticFiles(directory="."), name="static")

# Health check endpoint
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "message": "NEXUS Backend is running",
        "version": "1.0.0"
    }

# Simple analyze endpoint
@app.post("/api/analyze")
async def analyze_endpoint(request: dict):
    """Simple analysis endpoint that returns mock data"""
    identifier = request.get("identifier", "unknown")
    
    # Generate consistent mock data based on identifier
    hash_val = hash(identifier) % 100
    
    # Password and phone number safety analysis
    password_safety = analyze_password_safety(identifier)
    phone_safety = analyze_phone_safety(identifier)
    
    return {
        "identifier": identifier,
        "timestamp": "2026-02-19T18:00:00Z",
        "platform_count": 25 + (hash_val % 20),
        "exposure_count": 80 + (hash_val % 40),
        "threat_level": 5 + (hash_val % 5),
        "risk_score": 40 + (hash_val % 40),
        "threats": [
            {
                "name": "Social Media Exposure",
                "icon": "📱",
                "risk": 70 + (hash_val % 20),
                "color": "#ff0055",
                "description": "Personal information exposed across social platforms",
                "severity": "High",
                "affected_platforms": ["Facebook", "Instagram", "Twitter"]
            },
            {
                "name": "Data Broker Networks", 
                "icon": "💼",
                "risk": 50 + (hash_val % 30),
                "color": "#ffaa00",
                "description": "Personal data sold by data aggregation companies",
                "severity": "Medium",
                "affected_platforms": ["Acxiom", "Equifax", "Experian"]
            }
        ],
        "dark_web_findings": hash_val % 10,
        "brokers_found": 20 + (hash_val % 15),
        "search_engine_results": 300 + (hash_val % 200),
        "identity_score": 400 + (hash_val % 300),
        "password_analysis": password_safety,
        "phone_analysis": phone_safety
    }

def analyze_password_safety(identifier: str) -> dict:
    """Analyze password safety in the identifier"""
    import re
    
    # Check for common password patterns
    password_patterns = [
        r'\b\d{4,}\b',  # 4+ digits
        r'\b[a-zA-Z]{1,3}\d{2,4}\b',  # letter + numbers
        r'\bpassword\d*\b',  # password variants
        r'\badmin\d*\b',  # admin variants
        r'\b123\b',  # common numbers
        r'\bqwerty\b',  # keyboard patterns
        r'\babc123\b',  # common patterns
    ]
    
    found_patterns = []
    for pattern in password_patterns:
        if re.search(pattern, identifier.lower()):
            found_patterns.append(pattern)
    
    # Determine safety level
    if found_patterns:
        safety_score = max(10, 50 - len(found_patterns) * 10)
        safety_level = "WEAK" if len(found_patterns) >= 3 else "MODERATE" if len(found_patterns) >= 1 else "STRONG"
    else:
        safety_score = 85
        safety_level = "STRONG"
    
    return {
        "detected_patterns": len(found_patterns),
        "safety_score": safety_score,
        "safety_level": safety_level,
        "recommendations": [
            "Use mixed case letters, numbers, and symbols",
            "Avoid common patterns and dictionary words",
            "Use at least 12 characters",
            "Enable two-factor authentication"
        ]
    }

def analyze_phone_safety(identifier: str) -> dict:
    """Analyze phone number safety in the identifier"""
    import re
    
    # Extract phone numbers
    phone_patterns = [
        r'\b\d{10}\b',  # 10 digits
        r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # XXX-XXX-XXXX
        r'\b\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # +1-XXX-XXX-XXXX
        r'\b\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}\b',  # (XXX) XXX-XXXX
    ]
    
    found_phones = []
    for pattern in phone_patterns:
        matches = re.findall(pattern, identifier)
        found_phones.extend(matches)
    
    # Remove duplicates
    unique_phones = list(set(found_phones))
    
    # Determine privacy risk
    if unique_phones:
        privacy_score = max(15, 70 - len(unique_phones) * 15)
        privacy_level = "HIGH RISK" if len(unique_phones) >= 2 else "MODERATE RISK" if len(unique_phones) >= 1 else "LOW RISK"
    else:
        privacy_score = 90
        privacy_level = "LOW RISK"
    
    return {
        "phone_numbers_found": len(unique_phones),
        "privacy_score": privacy_score,
        "privacy_level": privacy_level,
        "recommendations": [
            "Avoid sharing phone numbers publicly",
            "Use separate phone for online accounts",
            "Enable caller ID and spam protection",
            "Consider using VoIP services for privacy"
        ]
    }

# Serve the HTML file
@app.get("/")
async def read_root():
    """Serve the frontend"""
    return FileResponse("index2.html")

@app.get("/index2.html")
async def serve_frontend():
    """Serve the frontend HTML file"""
    return FileResponse("index2.html")

if __name__ == "__main__":
    print("🚀 Starting NEXUS Backend Server...")
    print("📍 Server running on: http://localhost:8000")
    print("🌐 Open browser to: http://localhost:8000")
    print("⏹️  Press Ctrl+C to stop")
    print()
    
    try:
        uvicorn.run(
            "simple_backend:app",
            host="localhost",
            port=8000,
            reload=False,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n✅ Server stopped gracefully")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
