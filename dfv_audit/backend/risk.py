from __future__ import annotations

import math
from typing import Any


DEFAULT_WEIGHTS: dict[str, int] = {
    # Identity
    "gmail": 6,
    "email": 6,
    "phone": 12,
    "ipv4": 6,
    "url": 3,
    # Secrets / credentials (highest severity)
    "password_in_text": 55,
    "secret_in_text": 40,
    "jwt": 45,
    "aws_access_key_id": 60,
}


def risk_level(score_0_100: int) -> str:
    if score_0_100 >= 80:
        return "CRITICAL"
    if score_0_100 >= 60:
        return "HIGH"
    if score_0_100 >= 35:
        return "MODERATE"
    return "LOW"


def score_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Turn findings into:
    - risk score (0-100)
    - threat level string
    - per-kind breakdown
    - recommendations
    """
    per_kind: dict[str, dict[str, int]] = {}
    total = 0.0

    for f in findings:
        kind = str(f.get("kind") or "unknown")
        count = int(f.get("count") or 1)
        weight = DEFAULT_WEIGHTS.get(kind, 5)

        # diminishing returns: first hit matters most, then slowly increases
        contribution = weight * math.log1p(count)
        total += contribution

        if kind not in per_kind:
            per_kind[kind] = {"count": 0, "weight": weight}
        per_kind[kind]["count"] += count

    # baseline gives a bit of signal even for small scans
    raw_score = 8 + total
    score = int(max(0, min(100, round(raw_score))))

    recs: list[dict[str, str]] = []
    kinds_present = set(per_kind.keys())

    if {"password_in_text", "secret_in_text", "jwt", "aws_access_key_id"} & kinds_present:
        recs.append(
            {
                "priority": "CRITICAL",
                "title": "Rotate exposed secrets immediately",
                "details": "If any tokens/keys/passwords appear in files or logs, assume compromise. Rotate/ revoke, then investigate access logs.",
            }
        )
        recs.append(
            {
                "priority": "HIGH",
                "title": "Remove secrets from source & history",
                "details": "Move secrets to a secret manager (.env locally, vault in production). Rewrite git history if secrets were committed.",
            }
        )

    if "email" in kinds_present or "gmail" in kinds_present:
        recs.append(
            {
                "priority": "MEDIUM",
                "title": "Enable MFA and review account recovery",
                "details": "Turn on MFA, review recovery email/phone, and remove unknown third‑party access in your Google Account security settings.",
            }
        )

    if "phone" in kinds_present:
        recs.append(
            {
                "priority": "MEDIUM",
                "title": "Reduce phone-number exposure",
                "details": "Remove phone numbers from public profiles, and prefer app-based MFA over SMS when possible.",
            }
        )

    if "url" in kinds_present:
        recs.append(
            {
                "priority": "LOW",
                "title": "Audit linked services",
                "details": "Review the extracted domains to identify old accounts, third‑party integrations, and high‑risk services to close or secure.",
            }
        )

    return {
        "score": score,
        "level": risk_level(score),
        "breakdown": {
            k: {"count": v["count"], "weight": v["weight"]} for k, v in sorted(per_kind.items())
        },
        "recommendations": recs,
    }

