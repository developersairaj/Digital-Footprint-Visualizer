import hashlib
import re
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urlparse
from collections import Counter, defaultdict
 
 
@dataclass(frozen=True)
class MatchLocation:
    line: int
    column: int
 
 
@dataclass(frozen=True)
class Finding:
    kind: str
    value_redacted: str
    value_hash: str
    count: int
    locations: list[MatchLocation]
 
 
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@(?:[A-Za-z0-9.-]+\.[A-Za-z]{2,}|gmail\.com)\b")
GMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@gmail\.com\b", re.IGNORECASE)
URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PHONE_RE = re.compile(
    r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}\b"
)
 
 
def _sha256_12(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:12]
 
 
def redact_email(email: str) -> str:
    if "@" not in email:
        return redact_generic(email)
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        local_r = local[:1] + "*"
    else:
        local_r = local[:1] + ("*" * min(8, max(2, len(local) - 2))) + local[-1:]
    return f"{local_r}@{domain.lower()}"
 
 
def redact_phone(phone: str) -> str:
    digits = re.sub(r"\D+", "", phone)
    if len(digits) <= 4:
        return "*" * len(digits)
    return ("*" * (len(digits) - 4)) + digits[-4:]
 
 
def redact_generic(value: str) -> str:
    v = value.strip()
    if len(v) <= 6:
        return "*" * len(v)
    return v[:3] + ("*" * min(12, len(v) - 5)) + v[-2:]
 
 
def _valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= n <= 255 for n in nums)
 
 
def _extract_domains_from_urls(urls: Iterable[str]) -> Counter:
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
 
 
SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|api[_-]?key|secret|token|access[_-]?token|refresh[_-]?token)\b"
    r"\s*[:=]\s*"
    r"(?P<val>\"[^\"]{1,200}\"|'[^']{1,200}'|[^\s,;]{1,200})"
)
 
 
def scan_text(text: str, *, max_findings_per_kind: int = 250) -> dict:
    """
    Local-only pattern scan.
    Returns redacted findings plus a domain summary for "where it's used" signals (URLs/domains mentioned).
    """
    lines = text.splitlines()
    buckets: dict[str, list[tuple[str, MatchLocation]]] = defaultdict(list)
 
    def add(kind: str, raw: str, loc: MatchLocation):
        if len(buckets[kind]) >= max_findings_per_kind:
            return
        buckets[kind].append((raw, loc))
 
    for i, line in enumerate(lines, start=1):
        for m in GMAIL_RE.finditer(line):
            add("gmail", m.group(0), MatchLocation(i, m.start() + 1))
        for m in EMAIL_RE.finditer(line):
            add("email", m.group(0), MatchLocation(i, m.start() + 1))
        for m in PHONE_RE.finditer(line):
            add("phone", m.group(0), MatchLocation(i, m.start() + 1))
        for m in URL_RE.finditer(line):
            add("url", m.group(0), MatchLocation(i, m.start() + 1))
        for m in IPV4_RE.finditer(line):
            ip = m.group(0)
            if _valid_ipv4(ip):
                add("ipv4", ip, MatchLocation(i, m.start() + 1))
        for m in JWT_RE.finditer(line):
            add("jwt", m.group(0), MatchLocation(i, m.start() + 1))
        for m in AWS_ACCESS_KEY_RE.finditer(line):
            add("aws_access_key_id", m.group(0), MatchLocation(i, m.start() + 1))
 
        # Secret-like key/value occurrences (never return raw, only redacted)
        for m in SECRET_KV_RE.finditer(line):
            key = m.group(1).lower()
            raw_val = m.group("val").strip()
            # strip quotes for hashing/redaction
            if (raw_val.startswith('"') and raw_val.endswith('"')) or (
                raw_val.startswith("'") and raw_val.endswith("'")
            ):
                raw_val = raw_val[1:-1]
            kind = "password_in_text" if key in {"password", "passwd", "pwd", "pass"} else "secret_in_text"
            add(kind, f"{key}={raw_val}", MatchLocation(i, m.start() + 1))
 
    findings: list[Finding] = []
    for kind, items in buckets.items():
        # Group by raw to count duplicates, but keep a few locations
        by_raw: dict[str, list[MatchLocation]] = defaultdict(list)
        for raw, loc in items:
            if len(by_raw[raw]) < 25:
                by_raw[raw].append(loc)
        for raw, locs in by_raw.items():
            h = _sha256_12(f"{kind}:{raw}")
            if kind in {"email", "gmail"}:
                red = redact_email(raw)
            elif kind == "phone":
                red = redact_phone(raw)
            elif kind in {"url", "ipv4"}:
                red = raw
            elif kind in {"jwt", "aws_access_key_id"}:
                red = redact_generic(raw)
            elif kind in {"password_in_text", "secret_in_text"}:
                # raw format key=value
                if "=" in raw:
                    k, v = raw.split("=", 1)
                    red = f"{k}={redact_generic(v)}"
                else:
                    red = redact_generic(raw)
            else:
                red = redact_generic(raw)
            findings.append(
                Finding(
                    kind=kind,
                    value_redacted=red,
                    value_hash=h,
                    count=len(locs),
                    locations=locs,
                )
            )
 
    # Domain summary for "where used" signals
    urls = [raw for raw, _loc in buckets.get("url", [])]
    domains = _extract_domains_from_urls(urls)
 
    # Also derive domains from emails
    email_domains: Counter = Counter()
    for raw, _loc in buckets.get("email", []):
        if "@" in raw:
            email_domains[raw.split("@", 1)[1].lower()] += 1
    for raw, _loc in buckets.get("gmail", []):
        email_domains["gmail.com"] += 1
 
    return {
        "stats": {
            "lines_scanned": len(lines),
            "total_findings": len(findings),
        },
        "findings": [
            {
                "kind": f.kind,
                "value_redacted": f.value_redacted,
                "value_hash": f.value_hash,
                "count": f.count,
                "locations": [{"line": l.line, "column": l.column} for l in f.locations],
            }
            for f in sorted(findings, key=lambda x: (x.kind, x.value_hash))
        ],
        "where_used": {
            "top_domains_from_urls": [{"domain": d, "count": n} for d, n in domains.most_common(25)],
            "top_email_domains": [{"domain": d, "count": n} for d, n in email_domains.most_common(25)],
        },
    }

