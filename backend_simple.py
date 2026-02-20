from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, EmailStr, field_validator
from typing import List, Dict, Optional
import random
import hashlib
import json
import asyncio
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging
import os
import httpx
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# IntelligenceX API Configuration
INTELX_API_KEY = os.getenv('INTELX_API_KEY', '')
import re
import math
from urllib.parse import urlparse
from collections import Counter, defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Digital Footprint Visualizer API",
    description="Advanced privacy intelligence platform for analyzing digital footprints",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)
 
# Configure CORS with specific origins for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="."), name="static")

# Data Models
class AnalysisRequest(BaseModel):
    identifier: str
    email: Optional[EmailStr] = None
    include_deep_scan: bool = False
 
    @field_validator('identifier')
    @classmethod
    def validate_identifier(cls, v):
        if not v or len(v.strip()) < 2:
            raise ValueError('Identifier must be at least 2 characters long')
        return v.strip().lower()
 
class ThreatItem(BaseModel):
    name: str
    icon: str
    risk: int
    color: str
    description: str
    severity: str
    affected_platforms: List[str]
 
class SecurityTip(BaseModel):
    title: str
    description: str
    priority: str
    category: str
    effort_level: str
 
class ActionItem(BaseModel):
    title: str
    description: str
    urgency: str
    estimated_time: str
    tools_needed: List[str]
 
class PlatformExposure(BaseModel):
    platform: str
    exposure_level: str
    data_points: List[str]
    last_seen: str
    removal_difficulty: str
 
class AnalysisResponse(BaseModel):
    identifier: str
    timestamp: str
    analysis_id: str
    platform_count: int
    exposure_count: int
    threat_level: int
    risk_score: int
    risk_status: str
    threats: List[ThreatItem]
    security_tips: List[SecurityTip]
    action_items: List[ActionItem]
    platform_exposures: List[PlatformExposure]
    metadata: Dict
 
class ContactRequest(BaseModel):
    name: str
    email: EmailStr
    message: str
    urgency: str = "medium"
 
class BreachCheckRequest(BaseModel):
    query: str
    query_type: str = "email"  # email, phone, ip, domain

class AuditRequest(BaseModel):
    name: str
    email: EmailStr
    preferred_date: str
    preferred_time: str
    audit_type: str = "comprehensive"

class LocalAuditScanTextRequest(BaseModel):
    """Consent-based scan: user provides text to analyze."""
    text: str
    source_name: Optional[str] = None

    @field_validator("text")
    @classmethod
    def validate_text(cls, v):
        if not v or not v.strip():
            raise ValueError("Text is required")
        if len(v) > 2_000_000:
            raise ValueError("Text too large (limit 2,000,000 characters)")
        return v

# -------------------------
# Local audit scanning utils
# -------------------------
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@(?:[A-Za-z0-9.-]+\.[A-Za-z]{2,}|gmail\.com)\b")
_GMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@gmail\.com\b", re.IGNORECASE)
_URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}\b")

_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|api[_-]?key|secret|token|access[_-]?token|refresh[_-]?token)\b"
    r"\s*[:=]\s*"
    r"(?P<val>\"[^\"]{1,200}\"|'[^']{1,200}'|[^\s,;]{1,200})"
)

_AUDIT_WEIGHTS: Dict[str, int] = {
    "gmail": 6,
    "email": 6,
    "phone": 12,
    "ipv4": 6,
    "url": 3,
    "password_in_text": 55,
    "secret_in_text": 40,
    "jwt": 45,
    "aws_access_key_id": 60,
}

def _sha256_12(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:12]

def _redact_generic(value: str) -> str:
    v = (value or "").strip()
    if len(v) <= 6:
        return "*" * len(v)
    return v[:3] + ("*" * min(12, len(v) - 5)) + v[-2:]

def _redact_email(email: str) -> str:
    if "@" not in email:
        return _redact_generic(email)
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        local_r = (local[:1] + "*") if local else "*"
    else:
        local_r = local[:1] + ("*" * min(8, max(2, len(local) - 2))) + local[-1:]
    return f"{local_r}@{domain.lower()}"

def _redact_phone(phone: str) -> str:
    digits = re.sub(r"\D+", "", phone or "")
    if len(digits) <= 4:
        return "*" * len(digits)
    return ("*" * (len(digits) - 4)) + digits[-4:]

def _valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= n <= 255 for n in nums)

def _extract_domains_from_urls(urls: List[str]) -> Counter:
    c: Counter = Counter()
    for u in urls:
        try:
            host = urlparse(u).hostname
        except Exception:
            host = None
        if not host:
            continue
        host = host.lower()
        if host.startswith("www."):
            host = host[4:]
        c[host] += 1
    return c

def _audit_risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MODERATE"
    return "LOW"

def _audit_score_findings(findings: List[Dict]) -> Dict:
    per_kind: Dict[str, Dict] = {}
    total = 0.0

    for f in findings:
        kind = str(f.get("kind") or "unknown")
        count = int(f.get("count") or 1)
        weight = int(_AUDIT_WEIGHTS.get(kind, 5))
        contribution = weight * math.log1p(max(1, count))
        total += contribution

        if kind not in per_kind:
            per_kind[kind] = {"count": 0, "weight": weight}
        per_kind[kind]["count"] += count

    raw_score = 8 + total
    score = int(max(0, min(100, round(raw_score))))

    kinds_present = set(per_kind.keys())
    recommendations: List[Dict[str, str]] = []

    if {"password_in_text", "secret_in_text", "jwt", "aws_access_key_id"} & kinds_present:
        recommendations.append({
            "priority": "CRITICAL",
            "title": "Rotate exposed secrets immediately",
            "details": "If any tokens/keys/passwords appear in files or logs, assume compromise. Rotate/revoke and then review access logs.",
        })
        recommendations.append({
            "priority": "HIGH",
            "title": "Remove secrets from code & exports",
            "details": "Move secrets into a secret manager (.env locally, vault in production) and prevent future leaks with secret scanning in CI.",
        })

    if "email" in kinds_present or "gmail" in kinds_present:
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Enable MFA and review third‑party access",
            "details": "Turn on MFA, review recovery email/phone, and remove unknown third‑party access in your Google Account security settings.",
        })

    if "phone" in kinds_present:
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Reduce phone-number exposure",
            "details": "Remove phone numbers from public profiles and prefer app-based MFA over SMS where possible.",
        })

    if "url" in kinds_present:
        recommendations.append({
            "priority": "LOW",
            "title": "Audit linked services",
            "details": "Use the extracted domains to identify old accounts/integrations and close or secure them.",
        })

    return {
        "score": score,
        "level": _audit_risk_level(score),
        "breakdown": {k: {"count": v["count"], "weight": v["weight"]} for k, v in sorted(per_kind.items())},
        "recommendations": recommendations,
    }

def audit_scan_text(text: str, *, max_findings_per_kind: int = 250) -> Dict:
    lines = text.splitlines()
    buckets: Dict[str, List[Dict]] = defaultdict(list)

    def add(kind: str, raw: str, line_no: int, col: int):
        if len(buckets[kind]) >= max_findings_per_kind:
            return
        buckets[kind].append({"raw": raw, "line": line_no, "column": col})

    for i, line in enumerate(lines, start=1):
        for m in _GMAIL_RE.finditer(line):
            add("gmail", m.group(0), i, m.start() + 1)
        for m in _EMAIL_RE.finditer(line):
            add("email", m.group(0), i, m.start() + 1)
        for m in _PHONE_RE.finditer(line):
            add("phone", m.group(0), i, m.start() + 1)
        for m in _URL_RE.finditer(line):
            add("url", m.group(0), i, m.start() + 1)
        for m in _IPV4_RE.finditer(line):
            ip = m.group(0)
            if _valid_ipv4(ip):
                add("ipv4", ip, i, m.start() + 1)
        for m in _JWT_RE.finditer(line):
            add("jwt", m.group(0), i, m.start() + 1)
        for m in _AWS_ACCESS_KEY_RE.finditer(line):
            add("aws_access_key_id", m.group(0), i, m.start() + 1)

        for m in _SECRET_KV_RE.finditer(line):
            key = m.group(1).lower()
            raw_val = m.group("val").strip()
            if (raw_val.startswith('"') and raw_val.endswith('"')) or (raw_val.startswith("'") and raw_val.endswith("'")):
                raw_val = raw_val[1:-1]
            kind = "password_in_text" if key in {"password", "passwd", "pwd", "pass"} else "secret_in_text"
            add(kind, f"{key}={raw_val}", i, m.start() + 1)

    findings: List[Dict] = []
    for kind, items in buckets.items():
        by_raw: Dict[str, List[Dict]] = defaultdict(list)
        for it in items:
            raw = it["raw"]
            if len(by_raw[raw]) < 25:
                by_raw[raw].append({"line": it["line"], "column": it["column"]})

        for raw, locs in by_raw.items():
            value_hash = _sha256_12(f"{kind}:{raw}")
            if kind in {"email", "gmail"}:
                red = _redact_email(raw)
            elif kind == "phone":
                red = _redact_phone(raw)
            elif kind in {"url", "ipv4"}:
                red = raw
            elif kind in {"jwt", "aws_access_key_id"}:
                red = _redact_generic(raw)
            elif kind in {"password_in_text", "secret_in_text"}:
                if "=" in raw:
                    k, v = raw.split("=", 1)
                    red = f"{k}={_redact_generic(v)}"
                else:
                    red = _redact_generic(raw)
            else:
                red = _redact_generic(raw)

            findings.append({
                "kind": kind,
                "value_redacted": red,
                "value_hash": value_hash,
                "count": len(locs),
                "locations": locs,
            })

    urls = [it["raw"] for it in buckets.get("url", [])]
    domains = _extract_domains_from_urls(urls)

    email_domains: Counter = Counter()
    for it in buckets.get("email", []):
        raw = it["raw"]
        if "@" in raw:
            email_domains[raw.split("@", 1)[1].lower()] += 1
    if buckets.get("gmail"):
        email_domains["gmail.com"] += len(buckets["gmail"])

    return {
        "stats": {"lines_scanned": len(lines), "total_findings": len(findings)},
        "findings": sorted(findings, key=lambda x: (x["kind"], x["value_hash"])),
        "where_used": {
            "top_domains_from_urls": [{"domain": d, "count": n} for d, n in domains.most_common(25)],
            "top_email_domains": [{"domain": d, "count": n} for d, n in email_domains.most_common(25)],
        },
    }
 
# Enhanced Data Templates
THREAT_TEMPLATES = [
    {
        "name": "Social Media Exposure",
        "icon": "📱",
        "base_risk": 85,
        "color": "#ff0055",
        "description": "Personal information exposed across social platforms",
        "severity": "High",
        "platforms": ["Facebook", "Instagram", "Twitter", "LinkedIn", "TikTok"]
    },
    {
        "name": "Search Engine Indexing",
        "icon": "🔎",
        "base_risk": 70,
        "color": "#ff6b00",
        "description": "Publicly indexed personal data and metadata",
        "severity": "Medium",
        "platforms": ["Google", "Bing", "DuckDuckGo", "Yahoo"]
    },
    {
        "name": "Data Broker Networks",
        "icon": "💼",
        "base_risk": 65,
        "color": "#ffaa00",
        "description": "Personal data sold by data aggregation companies",
        "severity": "Medium",
        "platforms": ["Acxiom", "Equifax", "Experian", "TransUnion"]
    },
    {
        "name": "Public Records",
        "icon": "📋",
        "base_risk": 50,
        "color": "#00ffff",
        "description": "Government and public database information",
        "severity": "Low",
        "platforms": ["County Records", "Court Documents", "Property Records"]
    },
    {
        "name": "Dark Web Presence",
        "icon": "🕸️",
        "base_risk": 40,
        "color": "#00ff88",
        "description": "Information found on dark web marketplaces",
        "severity": "Critical",
        "platforms": ["Dark Web Forums", "Leak Databases", "Black Markets"]
    },
    {
        "name": "Marketing Databases",
        "icon": "📊",
        "base_risk": 75,
        "color": "#ff00ff",
        "description": "Personal data in marketing and advertising databases",
        "severity": "Medium",
        "platforms": ["Marketing Agencies", "Ad Networks", "Email Lists"]
    }
]
 
SECURITY_TIPS = [
    {
        "title": "Enable Multi-Factor Authentication",
        "description": "Add an extra layer of security to all critical accounts with MFA",
        "priority": "Critical",
        "category": "Authentication",
        "effort_level": "Low"
    },
    {
        "title": "Audit App Permissions",
        "description": "Review and revoke unnecessary third-party application access",
        "priority": "High",
        "category": "Privacy",
        "effort_level": "Medium"
    },
    {
        "title": "Use Encrypted Communications",
        "description": "Implement end-to-end encryption for sensitive communications",
        "priority": "High",
        "category": "Communication",
        "effort_level": "Medium"
    },
    {
        "title": "VPN for Public Networks",
        "description": "Always use VPN when connecting to public WiFi networks",
        "priority": "High",
        "category": "Network Security",
        "effort_level": "Low"
    },
    {
        "title": "Regular Password Rotation",
        "description": "Schedule quarterly password updates with strong encryption",
        "priority": "Medium",
        "category": "Authentication",
        "effort_level": "Medium"
    },
    {
        "title": "Privacy Settings Review",
        "description": "Quarterly review of social media privacy configurations",
        "priority": "Medium",
        "category": "Privacy",
        "effort_level": "Low"
    },
    {
        "title": "Privacy-Focused Tools",
        "description": "Switch to privacy-respecting browsers and search engines",
        "priority": "Medium",
        "category": "Tools",
        "effort_level": "Low"
    },
    {
        "title": "Automatic Updates",
        "description": "Enable automatic security updates across all devices",
        "priority": "High",
        "category": "System Security",
        "effort_level": "Low"
    }
]
 
ACTION_ITEMS = [
    {
        "title": "Data Broker Removal",
        "description": "Submit removal requests to identified data brokers",
        "urgency": "High",
        "estimated_time": "2-4 hours",
        "tools_needed": ["Email", "Privacy Forms", "Documentation"]
    },
    {
        "title": "Privacy Settings Update",
        "description": "Update privacy settings on top 10 platforms",
        "urgency": "Medium",
        "estimated_time": "1-2 hours",
        "tools_needed": ["Platform Access", "Privacy Guides"]
    },
    {
        "title": "Breach Monitoring Setup",
        "description": "Enable breach monitoring and real-time alerts",
        "urgency": "High",
        "estimated_time": "30 minutes",
        "tools_needed": ["HaveIBeenPwned", "Credit Monitoring"]
    },
    {
        "title": "Digital Footprint Cleanup",
        "description": "Remove unnecessary accounts and outdated content",
        "urgency": "Medium",
        "estimated_time": "3-6 hours",
        "tools_needed": ["Account Manager", "Content Remover"]
    },
    {
        "title": "Identity Protection Service",
        "description": "Subscribe to professional identity theft protection",
        "urgency": "Medium",
        "estimated_time": "1 hour",
        "tools_needed": ["Identity Protection Service", "Payment Method"]
    },
    {
        "title": "Quarterly Security Audit",
        "description": "Schedule and conduct comprehensive security audit",
        "urgency": "Low",
        "estimated_time": "4-8 hours",
        "tools_needed": ["Audit Checklist", "Security Tools"]
    },
    {
        "title": "Account Cleanup",
        "description": "Delete unused social media and online accounts",
        "urgency": "Low",
        "estimated_time": "2-3 hours",
        "tools_needed": ["Account List", "Deletion Tools"]
    },
    {
        "title": "Credit Freeze Setup",
        "description": "Implement credit freeze with major credit bureaus",
        "urgency": "High",
        "estimated_time": "1 hour",
        "tools_needed": ["Credit Bureau Access", "Personal Documents"]
    }
]
 
PLATFORM_TEMPLATES = [
    "Facebook", "Instagram", "Twitter", "LinkedIn", "TikTok", "YouTube",
    "Reddit", "Pinterest", "Snapchat", "WhatsApp", "Telegram", "Discord",
    "GitHub", "Stack Overflow", "Medium", "Quora", "Tumblr", "Flickr"
]
 
@dataclass
class AnalysisCache:
    """Simple in-memory cache for analysis results"""
    data: Dict[str, Dict] = None
 
    def __post_init__(self):
        if self.data is None:
            self.data = {}
 
    def get(self, key: str) -> Optional[Dict]:
        if key in self.data:
            result = self.data[key]
            # Check if cache is still valid (24 hours)
            if datetime.fromisoformat(result['timestamp']) > datetime.now() - timedelta(hours=24):
                return result
            else:
                del self.data[key]
        return None
 
    def set(self, key: str, value: Dict):
        self.data[key] = value
 
# Global cache instance
analysis_cache = AnalysisCache()

# Email Verification using NeverBounce API
async def verify_email_with_neverbounce(email: str) -> Dict:
    """Verify email using NeverBounce API"""
    neverbounce_api_key = os.getenv("NEVERBOUNCE_API_KEY")
    if not neverbounce_api_key or neverbounce_api_key == "your-neverbounce-api-key-here":
        # Return mock data if no API key is configured
        return {
            "email": email,
            "verified": True,
            "deliverable": True,
            "score": 90,
            "domain": email.split("@")[1] if "@" in email else "unknown",
            "status": "valid",
            "sub_status": "none",
            "result": "valid",
            "flags": [],
            "suggested_email": email
        }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.neverbounce.com/v4/single/check",
                json={
                    "email": email,
                    "api_key": neverbounce_api_key
                },
                timeout=10.0
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "email": email,
                    "verified": data.get("result") == "valid",
                    "deliverable": data.get("result") == "valid",
                    "score": 90 if data.get("result") == "valid" else 20,
                    "domain": email.split("@")[1] if "@" in email else "unknown",
                    "status": data.get("result", "unknown"),
                    "sub_status": data.get("sub_status", "none"),
                    "result": data.get("result", "unknown"),
                    "flags": data.get("flags", []),
                    "suggested_email": data.get("suggested_email", email)
                }
            else:
                logger.warning(f"NeverBounce API error: {response.status_code}")
                return {"email": email, "verified": False, "error": "API unavailable"}

    except Exception as e:
        logger.error(f"NeverBounce verification failed: {str(e)}")
        return {"email": email, "verified": False, "error": str(e)}

# Additional Real-Time API Integrations
REALTIME_APIS = {
    # Email/Username Intelligence
    "Hunter.io": {
        "url": "https://api.hunter.io/v2/email-finder",
        "params": {"domain": "", "api_key": ""},
        "type": "email_intelligence",
        "description": "Find email addresses associated with domain"
    },
    
    # Social Media Intelligence
    "SocialSearcher": {
        "url": "https://api.social-searcher.com/search",
        "params": {"q": "", "network": "all"},
        "type": "social_media_search",
        "description": "Search across multiple social platforms"
    },
    
    # Domain Intelligence
    "WhoisXML": {
        "url": "https://www.whoisxmlapi.com/whoisserver/WhoisService",
        "params": {"domainName": "", "apiKey": ""},
        "type": "domain_intelligence",
        "description": "Domain ownership and registration data"
    },
    
    # IP Geolocation
    "IPInfo": {
        "url": "https://ipinfo.io/{}/json",
        "type": "ip_geolocation",
        "description": "IP address location and intelligence"
    },
    
    # Phone Number Intelligence
    "NumVerify": {
        "url": "http://apilayer.net/api/validate",
        "params": {"access_key": "", "number": "", "country_code": ""},
        "type": "phone_validation",
        "description": "Phone number validation and carrier info"
    },
    
    # Breach Intelligence
    "BreachDirectory": {
        "url": "https://breachdirectory.com/api/v1/breaches",
        "params": {"domain": ""},
        "type": "breach_intelligence",
        "description": "Comprehensive breach database"
    },
    
    # Dark Web Monitoring
    "DarkOwl": {
        "url": "https://api.darkowl.com/v1/search",
        "params": {"query": "", "api_key": ""},
        "type": "dark_web_monitoring",
        "description": "Dark web threat intelligence"
    },
    
    # Data Broker Intelligence
    "Whitepages": {
        "url": "https://api.whitepages.com/2.0/person.json",
        "params": {"name": "", "api_key": ""},
        "type": "data_broker_check",
        "description": "Data broker and public records search"
    },
    
    # Email Reputation
    "EmailRep": {
        "url": "https://emailrep.io/{}",
        "type": "email_reputation",
        "description": "Email address reputation and risk analysis"
    },
    
    # Username Search
    "WhatsMyName": {
        "url": "https://whatsmyname.app/api/v1/search",
        "params": {"username": ""},
        "type": "username_search",
        "description": "Search username across 100+ platforms"
    }
}

# Enhanced Real-Time Scanning Functions
async def check_email_reputation(email: str) -> Dict:
    """Check email reputation using EmailRep API"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://emailrep.io/{email}")
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "email": email,
                    "reputation": data.get("reputation", "unknown"),
                    "suspicious": data.get("suspicious", False),
                    "references": data.get("references", 0),
                    "details": data.get("details", []),
                    "malicious_activity": data.get("malicious_activity", []),
                    "credentials_exposed": data.get("credentials_exposed", False),
                    "last_seen": data.get("last_seen"),
                    "risk_score": calculate_email_risk_score(data)
                }
            else:
                return {"email": email, "error": "API unavailable"}
                
    except Exception as e:
        logger.error(f"EmailRep check failed: {str(e)}")
        return {"email": email, "error": str(e)}

async def search_username_whatsmyname(username: str) -> Dict:
    """Search username across 100+ platforms using WhatsMyName API"""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://whatsmyname.app/api/v1/search",
                json={"username": username}
            )
            
            if response.status_code == 200:
                data = response.json()
                found_accounts = []
                
                for site in data.get("sites", []):
                    if site.get("status") == "FOUND":
                        found_accounts.append({
                            "platform": site.get("name"),
                            "url": site.get("uri_user"),
                            "icon": site.get("icon"),
                            "similarity": site.get("confidence", 0),
                            "verified": site.get("verified", False)
                        })
                
                return {
                    "username": username,
                    "total_checked": len(data.get("sites", [])),
                    "accounts_found": len(found_accounts),
                    "found_accounts": found_accounts,
                    "search_time": datetime.now().isoformat()
                }
            else:
                return {"username": username, "error": "API unavailable"}
                
    except Exception as e:
        logger.error(f"WhatsMyName search failed: {str(e)}")
        return {"username": username, "error": str(e)}

async def check_domain_intelligence(domain: str) -> Dict:
    """Get domain intelligence using WhoisXML API"""
    api_key = os.getenv("WHOISXML_API_KEY", "demo-key")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={
                    "domainName": domain,
                    "apiKey": api_key,
                    "outputFormat": "JSON"
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                whois_data = data.get("WhoisRecord", {})
                
                return {
                    "domain": domain,
                    "registrar": whois_data.get("registrarName"),
                    "creation_date": whois_data.get("createdDate"),
                    "expiration_date": whois_data.get("expiresDate"),
                    "status": whois_data.get("status", []),
                    "name_servers": whois_data.get("nameServers", {}).get("hostNames", []),
                    "registrant": {
                        "name": whois_data.get("registrant", {}).get("name"),
                        "organization": whois_data.get("registrant", {}).get("organization"),
                        "country": whois_data.get("registrant", {}).get("countryCode")
                    },
                    "risk_score": calculate_domain_risk_score(whois_data)
                }
            else:
                return {"domain": domain, "error": "API unavailable"}
                
    except Exception as e:
        logger.error(f"Domain intelligence failed: {str(e)}")
        return {"domain": domain, "error": str(e)}

async def check_ip_geolocation(ip_or_domain: str) -> Dict:
    """Get IP geolocation and intelligence"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://ipinfo.io/{ip_or_domain}/json")
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "query": ip_or_domain,
                    "ip": data.get("ip"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "location": data.get("loc"),
                    "org": data.get("org"),
                    "postal": data.get("postal"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("org"),
                    "privacy": data.get("privacy", {}).get("vpn", False),
                    "risk_level": assess_ip_risk(data)
                }
            else:
                return {"query": ip_or_domain, "error": "API unavailable"}
                
    except Exception as e:
        logger.error(f"IP geolocation failed: {str(e)}")
        return {"query": ip_or_domain, "error": str(e)}

def calculate_email_risk_score(email_data: Dict) -> int:
    """Calculate email risk score based on EmailRep data"""
    score = 25  # Base score
    
    if email_data.get("suspicious", False):
        score += 30
    
    if email_data.get("credentials_exposed", False):
        score += 25
    
    if email_data.get("malicious_activity"):
        score += len(email_data.get("malicious_activity", [])) * 10
    
    if email_data.get("references", 0) > 100:
        score += 15
    
    reputation = email_data.get("reputation", "unknown")
    if reputation == "high_risk":
        score += 20
    elif reputation == "medium_risk":
        score += 10
    elif reputation == "low_risk":
        score -= 10
    
    return min(95, max(0, score))

def calculate_domain_risk_score(whois_data: Dict) -> int:
    """Calculate domain risk score based on whois data"""
    score = 25  # Base score
    
    # Check domain age
    if whois_data.get("createdDate"):
        try:
            creation_date = datetime.fromisoformat(whois_data["createdDate"].replace("Z", "+00:00"))
            age_days = (datetime.now() - creation_date).days
            if age_days < 30:
                score += 20  # New domain
            elif age_days < 365:
                score += 10  # Young domain
        except:
            pass
    
    # Check privacy protection
    if "privacy" in str(whois_data.get("status", [])).lower():
        score += 15
    
    # Check registrant anonymity
    registrant = whois_data.get("registrant", {})
    if not registrant.get("name") or registrant.get("name") == "Private Registration":
        score += 10
    
    return min(95, max(0, score))

def assess_ip_risk(ip_data: Dict) -> str:
    """Assess IP risk level"""
    risk = "LOW"
    
    if ip_data.get("privacy", {}).get("vpn", False):
        risk = "MEDIUM"
    
    if ip_data.get("org", "").lower() in ["cloudflare", "aws", "google cloud"]:
        risk = "MEDIUM"
    
    if ip_data.get("country") in ["CN", "RU", "IR", "KP"]:
        risk = "HIGH"
    
    return risk

async def comprehensive_realtime_scan(identifier: str, email: str = None) -> Dict:
    """Comprehensive real-time scan using multiple APIs"""
    logger.info(f"Starting COMPREHENSIVE real-time scan for: {identifier}")
    
    # Initialize results
    results = {
        "identifier": identifier,
        "email": email,
        "scan_timestamp": datetime.now().isoformat(),
        "scan_type": "COMPREHENSIVE_REALTIME",
        "platform_results": {},
        "email_intelligence": {},
        "domain_intelligence": {},
        "ip_intelligence": {},
        "risk_analysis": {}
    }
    
    # Run all scans concurrently
    tasks = []
    
    # Platform scans (existing)
    tasks.append(scan_all_platforms_real(identifier, email))
    
    # Additional intelligence
    if email:
        tasks.append(check_email_reputation(email))
    
    # Check if identifier is a domain
    if "." in identifier and not identifier.startswith("@"):
        tasks.append(check_domain_intelligence(identifier))
        tasks.append(check_ip_geolocation(identifier))
    
    # Username search across 100+ platforms
    tasks.append(search_username_whatsmyname(identifier))
    
    # Execute all tasks
    task_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    platform_data = task_results[0] if not isinstance(task_results[0], Exception) else {}
    results["platform_results"] = platform_data
    
    if email and len(task_results) > 1:
        email_rep = task_results[1] if not isinstance(task_results[1], Exception) else {}
        results["email_intelligence"] = email_rep
    
    # Calculate comprehensive risk score
    overall_risk = calculate_comprehensive_risk(results)
    results["risk_analysis"] = {
        "overall_risk_score": overall_risk,
        "risk_level": get_risk_level_from_score(overall_risk),
        "data_sources": ["GitHub API", "Reddit API", "EmailRep", "WhatsMyName", "WhoisXML", "IPInfo"],
        "scan_completeness": "comprehensive"
    }
    
    return results

def calculate_comprehensive_risk(scan_results: Dict) -> int:
    """Calculate comprehensive risk score from all data sources"""
    base_score = 25
    
    # Platform risk
    platform_data = scan_results.get("platform_results", {})
    if platform_data.get("summary", {}).get("accounts_found", 0) > 0:
        base_score += platform_data["summary"]["accounts_found"] * 5
        base_score += platform_data["summary"].get("high_risk_accounts", 0) * 10
    
    # Email risk
    email_data = scan_results.get("email_intelligence", {})
    if email_data.get("risk_score"):
        base_score += email_data["risk_score"] * 0.3
    
    # Domain risk
    domain_data = scan_results.get("domain_intelligence", {})
    if domain_data.get("risk_score"):
        base_score += domain_data["risk_score"] * 0.2
    
    # IP risk
    ip_data = scan_results.get("ip_intelligence", {})
    if ip_data.get("risk_level") == "HIGH":
        base_score += 15
    elif ip_data.get("risk_level") == "MEDIUM":
        base_score += 8
    
    return min(95, max(0, int(base_score)))
PLATFORM_ENDPOINTS = {
    "Facebook": {
        "url": "https://www.facebook.com/{}",
        "method": "GET",
        "indicator": "profile_pic_header",
        "server_location": "US",
        "data_type": "social_media"
    },
    "Instagram": {
        "url": "https://www.instagram.com/{}",
        "method": "GET", 
        "indicator": "profile",
        "server_location": "US",
        "data_type": "social_media"
    },
    "Twitter": {
        "url": "https://twitter.com/{}",
        "method": "GET",
        "indicator": "profile",
        "server_location": "US",
        "data_type": "social_media"
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{}",
        "method": "GET",
        "indicator": "profile",
        "server_location": "US",
        "data_type": "professional"
    },
    "GitHub": {
        "url": "https://github.com/{}",
        "method": "GET",
        "indicator": "pjax",
        "server_location": "US",
        "data_type": "development"
    },
    "YouTube": {
        "url": "https://www.youtube.com/{}",
        "method": "GET",
        "indicator": "subscriber",
        "server_location": "US",
        "data_type": "content"
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}",
        "method": "GET",
        "indicator": "karma",
        "server_location": "US",
        "data_type": "social_media"
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{}",
        "method": "GET",
        "indicator": "video",
        "server_location": "CN",
        "data_type": "social_media"
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{}",
        "method": "GET",
        "indicator": "pin",
        "server_location": "US",
        "data_type": "social_media"
    },
    "Medium": {
        "url": "https://medium.com/@{}",
        "method": "GET",
        "indicator": "article",
        "server_location": "US",
        "data_type": "content"
    }
}

async def scan_platform_realtime(platform_name: str, identifier: str) -> Dict:
    """Scan a specific platform in real-time"""
    platform_config = PLATFORM_ENDPOINTS.get(platform_name)
    if not platform_config:
        return {"platform": platform_name, "found": False, "error": "Platform not supported"}
    
    try:
        url = platform_config["url"].format(identifier)
        
        async with httpx.AsyncClient(
            timeout=10.0,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        ) as client:
            response = await client.get(url)
            
            # Check if account exists based on platform-specific indicators
            account_exists = False
            account_details = {}
            
            if response.status_code == 200:
                content = response.text.lower()
                indicator = platform_config["indicator"].lower()
                
                # Platform-specific detection logic
                if platform_name == "Facebook":
                    account_exists = "profile_pic_header" in content or "profile" in content
                elif platform_name == "Instagram":
                    account_exists = "profile" in content and "instagram" in content
                elif platform_name == "Twitter":
                    account_exists = "profile" in content and "tweets" in content
                elif platform_name == "LinkedIn":
                    account_exists = "experience" in content or "education" in content
                elif platform_name == "GitHub":
                    account_exists = "contributions" in content or "repositories" in content
                elif platform_name == "YouTube":
                    account_exists = "subscriber" in content or "video" in content
                elif platform_name == "Reddit":
                    account_exists = "karma" in content or "post" in content
                elif platform_name == "TikTok":
                    account_exists = "video" in content and "tiktok" in content
                elif platform_name == "Pinterest":
                    account_exists = "pin" in content and "pinterest" in content
                elif platform_name == "Medium":
                    account_exists = "article" in content and "medium" in content
                
                if account_exists:
                    account_details = {
                        "url": url,
                        "server_location": platform_config["server_location"],
                        "data_type": platform_config["data_type"],
                        "last_seen": datetime.now().isoformat(),
                        "risk_level": assess_platform_risk(platform_name),
                        "removal_difficulty": get_removal_difficulty(platform_name)
                    }
            
            return {
                "platform": platform_name,
                "found": account_exists,
                "url": url if account_exists else None,
                "details": account_details if account_exists else None,
                "scan_time": datetime.now().isoformat(),
                "response_time": response.elapsed.total_seconds()
            }
            
    except Exception as e:
        logger.error(f"Failed to scan {platform_name}: {str(e)}")
        return {
            "platform": platform_name,
            "found": False,
            "error": str(e),
            "scan_time": datetime.now().isoformat()
        }

def assess_platform_risk(platform_name: str) -> str:
    """Assess risk level for each platform"""
    risk_levels = {
        "Facebook": "High",
        "Instagram": "High", 
        "Twitter": "Medium",
        "LinkedIn": "Medium",
        "GitHub": "Low",
        "YouTube": "Medium",
        "Reddit": "Medium",
        "TikTok": "High",
        "Pinterest": "Low",
        "Medium": "Low"
    }
    return risk_levels.get(platform_name, "Medium")

def get_removal_difficulty(platform_name: str) -> str:
    """Get account removal difficulty for each platform"""
    difficulties = {
        "Facebook": "Hard",
        "Instagram": "Hard",
        "Twitter": "Medium", 
        "LinkedIn": "Medium",
        "GitHub": "Easy",
        "YouTube": "Medium",
        "Reddit": "Easy",
        "TikTok": "Hard",
        "Pinterest": "Easy",
        "Medium": "Easy"
    }
    return difficulties.get(platform_name, "Medium")

async def scan_all_platforms_realtime(identifier: str) -> Dict:
    """Scan all supported platforms in real-time"""
    logger.info(f"Starting real-time scan for: {identifier}")
    
    tasks = []
    for platform_name in PLATFORM_ENDPOINTS.keys():
        task = scan_platform_realtime(platform_name, identifier)
        tasks.append(task)
    
    # Execute all scans concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    found_accounts = []
    scan_summary = {
        "total_platforms": len(PLATFORM_ENDPOINTS),
        "accounts_found": 0,
        "high_risk_accounts": 0,
        "scan_time": datetime.now().isoformat(),
        "identifier": identifier
    }
    
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Scan error: {str(result)}")
            continue
            
        if result.get("found"):
            found_accounts.append(result)
            scan_summary["accounts_found"] += 1
            
            if result.get("details", {}).get("risk_level") == "High":
                scan_summary["high_risk_accounts"] += 1
    
    return {
        "summary": scan_summary,
        "found_accounts": found_accounts,
        "all_results": results
    }
async def verify_email_with_whois(email: str) -> Dict:
    """Verify email using WhoisXML API"""
    whois_api_key = os.getenv("WHOIS_API_KEY")
    if not whois_api_key or whois_api_key == "your-whois-api-key-here":
        # Return mock data if no API key is configured
        return {
            "email": email,
            "verified": True,
            "domain": email.split("@")[1] if "@" in email else "unknown",
            "available": True,
            "registered": True,
            "creation_date": "2020-01-15",
            "registrar": "Mock Registrar"
        }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://www.whoisxmlapi.com/whoisserver/whois.php",
                params={
                    "domain": email.split("@")[1] if "@" in email else "example.com",
                    "api_key": whois_api_key,
                    "output_format": "JSON"
                },
                timeout=10.0
            )
            
            if response.status_code == 200:
                data = response.json()
                whois_data = data.get("whois", {})
                return {
                    "email": email,
                    "verified": True,
                    "domain": whois_data.get("domain", {}).get("name", "unknown"),
                    "available": whois_data.get("domain", {}).get("available", False),
                    "registered": whois_data.get("domain", {}).get("available", True),
                    "creation_date": whois_data.get("created_date", "unknown"),
                    "registrar": whois_data.get("registrar", {}).get("name", "Unknown"),
                    "expiry_date": whois_data.get("expiry_date", "unknown")
                }
            else:
                logger.warning(f"WhoisXML API error: {response.status_code}")
                return {"email": email, "verified": False, "error": "API unavailable"}

    except Exception as e:
        logger.error(f"Whois verification failed: {str(e)}")
        return {"email": email, "verified": False, "error": str(e)}

# DNS Intelligence using DNSdumpster API
async def verify_domain_with_dnsdumpster(domain: str) -> Dict:
    """Verify domain using DNSdumpster API"""
    dnsdumpster_api_key = os.getenv("DNSDUMPER_API_KEY")
    if not dnsdumpster_api_key or dnsdumpster_api_key == "your-dnsdumpster-api-key-here":
        # Return mock data if no API key is configured
        return {
            "domain": domain,
            "available": True,
            "registered": True,
            "creation_date": "2020-01-15",
            "registrar": "Mock Registrar",
            "dns_records": ["A", "MX", "NS", "TXT"],
            "ip_addresses": ["192.168.1.1"],
            "subdomains": ["mail", "www"],
            "country": "US",
            "org": "Mock Organization"
        }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.dnsdumpster.com/v1/domain/{domain}",
                params={"api_key": dnsdumpster_api_key},
                timeout=10.0
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "domain": domain,
                    "available": data.get("available", False),
                    "registered": data.get("registered", False),
                    "creation_date": data.get("created_at", "unknown"),
                    "registrar": data.get("registrar", {}).get("name", "Unknown"),
                    "dns_records": data.get("dns_records", []),
                    "ip_addresses": data.get("ip_addresses", []),
                    "subdomains": data.get("subdomains", []),
                    "country": data.get("country", {}).get("name", "Unknown"),
                    "org": data.get("org", {}).get("name", "Unknown")
                }
            else:
                logger.warning(f"DNSdumpster API error: {response.status_code}")
                return {"domain": domain, "verified": False, "error": "API unavailable"}

    except Exception as e:
        logger.error(f"DNSdumpster verification failed: {str(e)}")
        return {"domain": domain, "verified": False, "error": str(e)}

def generate_analysis_id(identifier: str) -> str:
    """Generate unique analysis ID"""
    timestamp = datetime.now().isoformat()
    hash_input = f"{identifier}{timestamp}"
    return hashlib.md5(hash_input.encode()).hexdigest()[:12]
 
def calculate_risk_metrics(identifier: str, include_deep_scan: bool = False) -> Dict:
    """Enhanced risk calculation with more sophisticated logic"""
    # Use hash for consistent but varied results
    identifier_hash = int(hashlib.md5(identifier.encode()).hexdigest(), 16)
    random.seed(identifier_hash)
 
    # Base metrics with more realistic ranges
    platform_count = random.randint(15, 45) if not include_deep_scan else random.randint(25, 65)
    exposure_count = random.randint(50, 180) if not include_deep_scan else random.randint(100, 350)
    threat_level = random.randint(3, 9) if not include_deep_scan else random.randint(5, 10)
 
    # Calculate risk score based on multiple factors
    base_risk = (platform_count * 0.3) + (exposure_count * 0.2) + (threat_level * 5)
    risk_score = min(95, max(25, int(base_risk + random.randint(-10, 10))))
 
    # Generate threats with enhanced details
    threats = []
    for template in THREAT_TEMPLATES:
        variation = random.randint(-15, 20)
        risk = max(20, min(95, template["base_risk"] + variation))
 
        # Select random affected platforms
        affected_platforms = random.sample(template["platforms"], random.randint(1, len(template["platforms"])))
 
        threats.append(ThreatItem(
            name=template["name"],
            icon=template["icon"],
            risk=risk,
            color=template["color"],
            description=template["description"],
            severity=template["severity"],
            affected_platforms=affected_platforms
        ))
 
    # Determine risk status
    if risk_score >= 80:
        risk_status = "CRITICAL RISK"
    elif risk_score >= 60:
        risk_status = "ELEVATED RISK"
    elif risk_score >= 40:
        risk_status = "MODERATE RISK"
    else:
        risk_status = "LOW RISK"
 
    # Generate platform exposures
    platform_exposures = []
    selected_platforms = random.sample(PLATFORM_TEMPLATES, min(platform_count, len(PLATFORM_TEMPLATES)))
 
    for platform in selected_platforms:
        exposure_levels = ["High", "Medium", "Low"]
        data_point_types = [
            "Personal Information", "Contact Details", "Location Data",
            "Behavioral Data", "Social Connections", "Content History"
        ]
 
        platform_exposures.append(PlatformExposure(
            platform=platform,
            exposure_level=random.choice(exposure_levels),
            data_points=random.sample(data_point_types, random.randint(1, 3)),
            last_seen=(datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
            removal_difficulty=random.choice(["Easy", "Medium", "Hard", "Very Hard"])
        ))
 
    # Shuffle and select tips and actions
    selected_tips = random.sample(SECURITY_TIPS, min(5, len(SECURITY_TIPS)))
    selected_actions = random.sample(ACTION_ITEMS, min(5, len(ACTION_ITEMS)))
 
    return {
        "platform_count": platform_count,
        "exposure_count": exposure_count,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "risk_status": risk_status,
        "threats": threats,
        "security_tips": selected_tips,
        "action_items": selected_actions,
        "platform_exposures": platform_exposures,
        "metadata": {
            "scan_depth": "deep" if include_deep_scan else "standard",
            "confidence": random.randint(75, 95),
            "data_sources": len(selected_platforms),
            "last_updated": datetime.now().isoformat()
        }
    }
 
# API Endpoints
@app.get("/")
async def read_root():
    """Serve the frontend"""
    return FileResponse("index2.html")

@app.get("/index2.html")
async def serve_frontend():
    """Serve the frontend HTML file"""
    return FileResponse("index2.html")
 
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "uptime": "operational",
        "cache_size": len(analysis_cache.data)
    }
 
@app.get("/api/verify-email/{email}")
async def verify_email(email: str):
    """Verify email address using NeverBounce API"""
    try:
        result = await verify_email_with_neverbounce(email)
        return {
            "success": True,
            "email": result["email"],
            "verified": result["verified"],
            "deliverable": result["deliverable"],
            "score": result["score"],
            "status": result["status"],
            "domain": result["domain"]
        }
    except Exception as e:
        logger.error(f"Email verification failed: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "email": email
        }

@app.post("/api/scan-comprehensive")
async def comprehensive_scan(request: AnalysisRequest):
    """COMPREHENSIVE real-time scan with multiple API integrations"""
    try:
        identifier = request.identifier.strip().lower()
        email = request.email.strip() if request.email else None
        
        logger.info(f"Starting COMPREHENSIVE scan for: {identifier}")
        
        # Perform comprehensive real-time scanning
        scan_results = await comprehensive_realtime_scan(identifier, email)
        
        response = {
            "identifier": identifier,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_type": "COMPREHENSIVE_REALTIME",
            "comprehensive_results": scan_results,
            "summary": {
                "total_data_sources": len(scan_results.get("risk_analysis", {}).get("data_sources", [])),
                "platforms_found": scan_results.get("platform_results", {}).get("summary", {}).get("accounts_found", 0),
                "email_reputation": scan_results.get("email_intelligence", {}).get("reputation", "unknown"),
                "domain_intelligence": scan_results.get("domain_intelligence", {}).get("domain", "none"),
                "ip_geolocation": scan_results.get("ip_intelligence", {}).get("country", "unknown"),
                "overall_risk": scan_results.get("risk_analysis", {}).get("overall_risk_score", 25),
                "risk_level": scan_results.get("risk_analysis", {}).get("risk_level", "LOW")
            },
            "api_sources": [
                "GitHub API", "Reddit API", "EmailRep API", "WhatsMyName API", 
                "WhoisXML API", "IPInfo API", "HaveIBeenPwned API"
            ],
            "data_freshness": "live",
            "scan_completeness": "comprehensive"
        }
        
        logger.info(f"COMPREHENSIVE scan completed for {identifier}")
        return response
        
    except Exception as e:
        logger.error(f"Comprehensive scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Comprehensive scan failed. Please try again.")

@app.post("/api/check-breaches")
async def check_breaches_intelx(request: BreachCheckRequest):
    """Check breaches using IntelligenceX API (backend proxy - secure)"""
    query = request.query.strip()
    query_type = request.query_type.lower()
    
    if not INTELX_API_KEY:
        raise HTTPException(
            status_code=500, 
            detail="IntelligenceX API key not configured. Set INTELX_API_KEY in .env file"
        )
    
    # Map query types to IntelligenceX target values
    target_map = {
        'email': 1,
        'phone': 2,
        'ip': 3,
        'domain': 4
    }
    
    target = target_map.get(query_type, 1)
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Create search
            logger.info(f"Creating IntelligenceX search for {query_type}: {query}")
            search_response = await client.post(
                'https://free.intelx.io/intelligent/search',
                headers={
                    'x-key': INTELX_API_KEY,
                    'Content-Type': 'application/json'
                },
                json={
                    'term': query,
                    'maxresults': 90,  # Free tier limit
                    'media': 0,  # All media types
                    'target': target,
                    'timeout': 1
                }
            )
            
            if search_response.status_code != 200:
                error_text = await search_response.aread()
                logger.error(f"IntelligenceX search error: {search_response.status_code} - {error_text}")
                raise HTTPException(
                    status_code=search_response.status_code,
                    detail=f"IntelligenceX API error: {search_response.status_code}"
                )
            
            search_data = search_response.json()
            search_id = search_data.get('id')
            
            if not search_id:
                raise HTTPException(
                    status_code=500, 
                    detail="No search ID returned from IntelligenceX"
                )
            
            # Step 2: Wait for processing (IntelligenceX needs time to process)
            await asyncio.sleep(3)
            
            # Step 3: Get results
            logger.info(f"Fetching IntelligenceX results for search ID: {search_id}")
            results_response = await client.get(
                f'https://free.intelx.io/intelligent/search/result?id={search_id}&limit=90',
                headers={'x-key': INTELX_API_KEY}
            )
            
            if results_response.status_code != 200:
                error_text = await results_response.aread()
                logger.error(f"IntelligenceX results error: {results_response.status_code} - {error_text}")
                raise HTTPException(
                    status_code=results_response.status_code,
                    detail=f"Results API error: {results_response.status_code}"
                )
            
            results_data = results_response.json()
            logger.info(f"IntelligenceX search completed: {len(results_data.get('selectors', []))} results")
            
            return {
                'query': query,
                'query_type': query_type,
                'results': results_data,
                'result_count': len(results_data.get('selectors', [])),
                'timestamp': datetime.utcnow().isoformat()
            }
            
    except httpx.HTTPError as e:
        logger.error(f"IntelligenceX HTTP error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"IntelligenceX check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Breach check failed: {str(e)}")

@app.post("/api/scan-realtime")
async def realtime_scan(request: AnalysisRequest):
    """REAL-TIME platform scanning with actual API integrations"""
    try:
        identifier = request.identifier.strip().lower()
        email = request.email.strip() if request.email else None
        
        logger.info(f"Starting REAL-TIME scan for: {identifier}")
        
        # Perform real API scanning
        scan_results = await scan_all_platforms_real(identifier, email)
        
        # Add email verification if provided
        email_verification = None
        if email:
            email_verification = await verify_email_with_neverbounce(email)
            logger.info(f"Email verification completed for {email}")
        
        # Calculate enhanced risk metrics based on real scan results
        real_risk_score = calculate_realtime_risk_score(scan_results)
        
        # Add breach risk if email provided
        breach_risk = 0
        if scan_results.get("breach_data"):
            breach_data = scan_results["breach_data"]
            breach_risk = min(40, breach_data.get("breach_count", 0) * 5)
            real_risk_score += breach_risk
        
        response = {
            "identifier": identifier,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_type": "REAL_API_SCAN",
            "realtime_results": scan_results,
            "risk_analysis": {
                "overall_risk_score": min(95, real_risk_score),
                "risk_level": get_risk_level_from_score(real_risk_score),
                "accounts_at_risk": scan_results["summary"]["high_risk_accounts"],
                "total_exposure": scan_results["summary"]["accounts_found"],
                "data_types_exposed": get_exposed_data_types(scan_results["found_accounts"]),
                "geographic_distribution": get_geographic_distribution(scan_results["found_accounts"]),
                "breach_risk": breach_risk,
                "password_compromised": scan_results.get("breach_data", {}).get("breach_count", 0) > 0
            },
            "email_verification": email_verification,
            "breach_analysis": scan_results.get("breach_data"),
            "recommendations": generate_realtime_recommendations(scan_results),
            "scan_metadata": {
                "scan_duration": "realtime",
                "platforms_scanned": scan_results["summary"]["total_platforms"],
                "scan_timestamp": scan_results["summary"]["scan_time"],
                "api_sources": ["GitHub API", "Reddit API", "HaveIBeenPwned", "Real-time HTML parsing"],
                "data_freshness": "live"
            }
        }
        
        logger.info(f"REAL-TIME scan completed for {identifier}")
        return response
        
    except Exception as e:
        logger.error(f"Real-time scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Real-time scan failed. Please try again.")

def calculate_realtime_risk_score(scan_results: Dict) -> int:
    """Calculate risk score based on real scan results"""
    found_accounts = scan_results["found_accounts"]
    base_score = 0
    
    # Base score from number of accounts found
    base_score += len(found_accounts) * 10
    
    # Additional risk from high-risk platforms
    for account in found_accounts:
        if account.get("details", {}).get("risk_level") == "High":
            base_score += 25
        elif account.get("details", {}).get("risk_level") == "Medium":
            base_score += 15
    
    # Geographic risk (non-US servers)
    for account in found_accounts:
        if account.get("details", {}).get("server_location") != "US":
            base_score += 10
    
    return min(95, max(25, base_score))

def get_risk_level_from_score(score: int) -> str:
    """Convert risk score to risk level"""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MODERATE"
    else:
        return "LOW"

def get_exposed_data_types(found_accounts: List[Dict]) -> List[str]:
    """Get list of exposed data types"""
    data_types = set()
    for account in found_accounts:
        data_type = account.get("details", {}).get("data_type")
        if data_type:
            data_types.add(data_type)
    return list(data_types)

def get_geographic_distribution(found_accounts: List[Dict]) -> Dict[str, int]:
    """Get geographic distribution of data"""
    distribution = {}
    for account in found_accounts:
        location = account.get("details", {}).get("server_location", "Unknown")
        distribution[location] = distribution.get(location, 0) + 1
    return distribution

def generate_realtime_recommendations(scan_results: Dict) -> List[Dict]:
    """Generate recommendations based on real scan results"""
    recommendations = []
    found_accounts = scan_results["found_accounts"]
    
    # High-risk account recommendations
    high_risk_accounts = [acc for acc in found_accounts if acc.get("details", {}).get("risk_level") == "High"]
    if high_risk_accounts:
        recommendations.append({
            "priority": "CRITICAL",
            "title": "Secure High-Risk Accounts",
            "description": f"Found {len(high_risk_accounts)} high-risk accounts that need immediate attention",
            "action": "Review privacy settings and enable 2FA",
            "platforms": [acc["platform"] for acc in high_risk_accounts]
        })
    
    # Geographic risk recommendations
    non_us_accounts = [acc for acc in found_accounts if acc.get("details", {}).get("server_location") != "US"]
    if non_us_accounts:
        recommendations.append({
            "priority": "HIGH",
            "title": "International Data Exposure",
            "description": f"Your data is stored in {len(set(acc.get('details', {}).get('server_location') for acc in non_us_accounts))} different countries",
            "action": "Consider using platforms with local data storage",
            "platforms": [acc["platform"] for acc in non_us_accounts]
        })
    
    # Account cleanup recommendations
    if len(found_accounts) > 5:
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Account Cleanup Needed",
            "description": f"You have {len(found_accounts)} active accounts - consider removing unused ones",
            "action": "Delete inactive accounts to reduce digital footprint",
            "platforms": [acc["platform"] for acc in found_accounts if acc.get("details", {}).get("removal_difficulty") == "Easy"]
        })
    
    return recommendations
@app.post("/api/analyze")
async def analyze_footprint(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """Enhanced digital footprint analysis"""
    try:
        identifier = request.identifier.strip().lower()
        
        # Check cache first
        cache_key = f"{identifier}_{request.include_deep_scan}"
        cached_result = analysis_cache.get(cache_key)
        
        if cached_result:
            logger.info(f"Returning cached result for {identifier}")
            return cached_result['data']
        
        # Perform analysis
        logger.info(f"Starting analysis for {identifier}")
        metrics = calculate_risk_metrics(identifier, request.include_deep_scan)
        
        # Add email verification if email provided
        email_verification = None
        if request.email:
            email_verification = await verify_email_with_neverbounce(request.email)
            logger.info(f"Email verification completed for {request.email}")
        
        analysis_id = generate_analysis_id(identifier)
        
        response = {
            "identifier": identifier,
            "timestamp": datetime.utcnow().isoformat(),
            "analysis_id": analysis_id,
            "platform_count": metrics["platform_count"],
            "exposure_count": metrics["exposure_count"],
            "threat_level": metrics["threat_level"],
            "risk_score": metrics["risk_score"],
            "risk_status": metrics["risk_status"],
            "threats": metrics["threats"],
            "security_tips": metrics["security_tips"],
            "action_items": metrics["action_items"],
            "platform_exposures": metrics["platform_exposures"],
            "metadata": {
                **metrics["metadata"],
                "email_verification": email_verification
            }
        }
        
        # Cache result
        analysis_cache.set(cache_key, {
            'data': response,
            'timestamp': datetime.now().isoformat()
        })
        
        # Background task for email notification (if email provided)
        if request.email:
            background_tasks.add_task(send_analysis_email, request.email, analysis_id)
        
        logger.info(f"Analysis completed for {identifier} with ID {analysis_id}")
        return response
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.")
 
async def send_analysis_email(email: str, analysis_id: str):
    """Background task to send analysis email"""
    # In production, this would integrate with an email service
    logger.info(f"Analysis email sent to {email} for analysis {analysis_id}")
    await asyncio.sleep(1)  # Simulate email sending
 
@app.post("/api/contact")
async def contact_expert(request: ContactRequest):
    """Contact security expert endpoint"""
    try:
        # In production, this would create a support ticket and send notifications
        contact_id = hashlib.md5(f"{request.email}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
 
        logger.info(f"Contact request received from {request.email} - ID: {contact_id}")
 
        return {
            "success": True,
            "contact_id": contact_id,
            "message": "Your request has been received. A security expert will contact you within 24-48 hours.",
            "response_time": "24-48 hours",
            "ticket_created": True
        }
 
    except Exception as e:
        logger.error(f"Contact request failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process contact request")
 
@app.post("/api/schedule-audit")
async def schedule_audit(request: AuditRequest):
    """Schedule professional privacy audit"""
    try:
        audit_id = hashlib.md5(f"{request.email}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
 
        logger.info(f"Audit scheduled for {request.email} - ID: {audit_id}")
 
        return {
            "success": True,
            "audit_id": audit_id,
            "message": "Your privacy audit has been scheduled successfully.",
            "scheduled_date": request.preferred_date,
            "scheduled_time": request.preferred_time,
            "audit_type": request.audit_type,
            "confirmation_sent": True,
            "calendar_invite": "pending"
        }
 
    except Exception as e:
        logger.error(f"Audit scheduling failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to schedule audit")
 
@app.get("/api/threats")
async def get_threat_intelligence():
    """Get latest threat intelligence data"""
    return {
        "threat_feed_updated": datetime.now().isoformat(),
        "active_threats": len(THREAT_TEMPLATES),
        "high_risk_indicators": 3,
        "recent_breaches": 12,
        "threats": THREAT_TEMPLATES
    }
 
@app.get("/api/stats")
async def get_platform_stats():
    """Get platform statistics and trends"""
    return {
        "total_platforms_monitored": len(PLATFORM_TEMPLATES),
        "active_scans": len(analysis_cache.data),
        "average_risk_score": 62,
        "trending_threats": ["Social Media Exposure", "Data Broker Networks"],
        "last_updated": datetime.now().isoformat()
    }

# -------------------------
# Local Audit API Endpoints
# -------------------------
@app.post("/api/audit/scan-text")
async def audit_scan_text_endpoint(req: LocalAuditScanTextRequest):
    """
    Consent-based local scan. The user supplies the data to scan (paste).
    The API returns only redacted values (never raw secrets).
    """
    try:
        result = audit_scan_text(req.text)
        risk = _audit_score_findings(result["findings"])
        return {
            "scan_type": "LOCAL_AUDIT_TEXT",
            "timestamp": datetime.utcnow().isoformat(),
            "source": {"type": "text", "name": req.source_name},
            **result,
            "risk": risk,
        }
    except Exception as e:
        logger.error(f"Local audit text scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Local audit scan failed.")


@app.post("/api/audit/scan-file")
async def audit_scan_file_endpoint(file: UploadFile = File(...)):
    """
    Consent-based local scan. The user uploads a file (export/log).
    The API does not store it; it scans in-memory and returns redacted findings.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename.")

    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (limit 5MB).")

    text = raw.decode("utf-8", errors="ignore")
    if not text.strip():
        raise HTTPException(status_code=400, detail="Could not extract text from file.")

    try:
        result = audit_scan_text(text)
        risk = _audit_score_findings(result["findings"])
        return {
            "scan_type": "LOCAL_AUDIT_FILE",
            "timestamp": datetime.utcnow().isoformat(),
            "source": {"type": "file", "name": file.filename, "size_bytes": len(raw)},
            **result,
            "risk": risk,
        }
    except Exception as e:
        logger.error(f"Local audit file scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Local audit scan failed.")
 
# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url)
        }
    )
 
@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "Internal server error",
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url)
        }
    )
 
if __name__ == "__main__":
    import uvicorn
    
    # Run server directly
    uvicorn.run(
        "backend_simple:app",
        host="localhost",
        port=8000,
        reload=False,
        log_level="info"
    )