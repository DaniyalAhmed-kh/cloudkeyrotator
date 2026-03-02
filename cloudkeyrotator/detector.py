"""
Credential type detection via regex pattern matching.
Identifies provider, format, and confidence before any network call.
"""
import re
import json
from typing import Optional, Dict, Any

# Pattern definitions: (name, provider, cred_type, regex, confidence)
PATTERNS = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    ("AWS Access Key ID",      "AWS",    "aws_access_key",
     re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),

    ("AWS Temporary Access Key","AWS",   "aws_access_key",
     re.compile(r'\b(ASIA[0-9A-Z]{16})\b')),

    # ── GitHub ────────────────────────────────────────────────────────────────
    ("GitHub Classic PAT",     "GitHub", "github_pat",
     re.compile(r'\b(ghp_[A-Za-z0-9]{36,})\b')),

    ("GitHub Fine-Grained PAT","GitHub", "github_fine_grained",
     re.compile(r'\b(github_pat_[A-Za-z0-9_]{80,})\b')),

    ("GitHub OAuth Token",     "GitHub", "github_pat",
     re.compile(r'\b(gho_[A-Za-z0-9]{36,})\b')),

    ("GitHub Actions Token",   "GitHub", "github_pat",
     re.compile(r'\b(ghs_[A-Za-z0-9]{36,})\b')),

    # ── Azure ─────────────────────────────────────────────────────────────────
    ("Azure Storage Conn String","Azure","azure_connection_string",
     re.compile(r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}', re.IGNORECASE)),

    ("Azure SAS Token",        "Azure",  "azure_sas_token",
     re.compile(r'(sv=\d{4}-\d{2}-\d{2}&s[a-z]=&s[a-z]=)', re.IGNORECASE)),

    ("Azure Client Secret",    "Azure",  "azure_client_secret",
     re.compile(r'\b([A-Za-z0-9~._\-]{34,40})\b')),   # low-confidence fallback

    # ── GCP ───────────────────────────────────────────────────────────────────
    # GCP keys are JSON files — handled separately below
]

GCP_SA_FIELDS = {"type", "project_id", "private_key_id", "private_key", "client_email"}


def detect_credential(raw: str) -> Optional[Dict[str, Any]]:
    """
    Auto-detect a credential's type and provider.

    Returns a dict with keys: type, provider, confidence, meta
    or None if unrecognised.
    """
    raw_stripped = raw.strip()

    # ── GCP Service Account JSON ─────────────────────────────────────────────
    if raw_stripped.startswith("{"):
        try:
            data = json.loads(raw_stripped)
            if GCP_SA_FIELDS.issubset(data.keys()):
                return {
                    "type": "gcp_service_account",
                    "provider": "GCP",
                    "confidence": "high",
                    "meta": {
                        "pattern_name": "GCP Service Account JSON",
                        "project_id":   data.get("project_id"),
                        "client_email": data.get("client_email"),
                        "key_id":       data.get("private_key_id"),
                        "raw_json":     data,
                    },
                }
        except json.JSONDecodeError:
            pass

    # ── Azure Connection String ───────────────────────────────────────────────
    if "DefaultEndpointsProtocol" in raw_stripped and "AccountKey=" in raw_stripped:
        parts = dict(p.split("=", 1) for p in raw_stripped.split(";") if "=" in p)
        return {
            "type": "azure_connection_string",
            "provider": "Azure",
            "confidence": "high",
            "meta": {
                "pattern_name": "Azure Storage Connection String",
                "account_name": parts.get("AccountName"),
                "endpoint_suffix": parts.get("EndpointSuffix", "core.windows.net"),
            },
        }

    # ── Regex patterns ────────────────────────────────────────────────────────
    for name, provider, cred_type, pattern in PATTERNS:
        if cred_type == "azure_client_secret":
            continue   # handled below as low-confidence fallback
        m = pattern.search(raw_stripped)
        if m:
            return {
                "type": cred_type,
                "provider": provider,
                "confidence": "high",
                "meta": {
                    "pattern_name": name,
                    "matched_value": m.group(1) if m.lastindex else m.group(0),
                },
            }

    # ── Azure SAS Token ───────────────────────────────────────────────────────
    if raw_stripped.startswith("?sv=") or ("sv=" in raw_stripped and "sig=" in raw_stripped):
        return {
            "type": "azure_sas_token",
            "provider": "Azure",
            "confidence": "high",
            "meta": {"pattern_name": "Azure SAS Token"},
        }

    # ── Azure Client Secret (GUID-like 32–40 char string) ────────────────────
    if re.match(r'^[A-Za-z0-9~._\-]{32,44}$', raw_stripped):
        return {
            "type": "azure_client_secret",
            "provider": "Azure",
            "confidence": "medium",
            "meta": {"pattern_name": "Azure Client Secret (format heuristic)"},
        }

    return None
