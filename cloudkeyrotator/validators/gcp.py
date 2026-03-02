"""
GCP Service Account key validator.
Validates SA JSON keys via the Google IAM API.
"""
import json
import time
from typing import Any, Dict, List

import requests

from .base import BaseValidator

try:
    import google.auth
    import google.oauth2.service_account as sa_module
    from google.auth.transport.requests import Request as GoogleRequest
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False

GCP_IAM_API   = "https://iam.googleapis.com/v1"
GCP_CRM_API   = "https://cloudresourcemanager.googleapis.com/v1"
GCP_TOKEN_URL = "https://oauth2.googleapis.com/token"

SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/iam",
]

# Services to probe for blast radius
BLAST_PROBES = [
    ("https://storage.googleapis.com/storage/v1/b?project={project}", "GCS bucket listing"),
    ("https://compute.googleapis.com/compute/v1/projects/{project}/zones",     "Compute Engine access"),
    ("https://cloudresourcemanager.googleapis.com/v1/projects/{project}/getIamPolicy", "IAM policy read"),
    ("https://secretmanager.googleapis.com/v1/projects/{project}/secrets",     "Secret Manager access"),
    ("https://container.googleapis.com/v1/projects/{project}/clusters",        "GKE cluster access"),
    ("https://sqladmin.googleapis.com/v1/projects/{project}/instances",        "Cloud SQL access"),
    ("https://cloudfunctions.googleapis.com/v2/projects/{project}/locations",  "Cloud Functions access"),
    ("https://pubsub.googleapis.com/v1/projects/{project}/topics",             "Pub/Sub access"),
    ("https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets","BigQuery access"),
    ("https://run.googleapis.com/v2/projects/{project}/locations",             "Cloud Run access"),
]


class GCPValidator(BaseValidator):

    def validate(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "provider":    "GCP",
            "cred_type":   "service_account_key",
            "valid":       False,
            "identity":    {},
            "permissions": [],
            "blast_radius":{},
            "error":       None,
            "remediation": {
                "cli_command": "gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL",
                "docs": "https://cloud.google.com/iam/docs/creating-managing-service-account-keys",
            }
        }

        # Parse the service account JSON
        raw_json = self.meta.get("raw_json")
        if not raw_json:
            try:
                raw_json = json.loads(self.credential)
            except json.JSONDecodeError as e:
                result["error"] = f"Invalid JSON: {e}"
                return result

        if not GOOGLE_AUTH_AVAILABLE:
            # Fallback: try getting a token via raw HTTP JWT
            return self._validate_raw_jwt(result, raw_json)

        try:
            credentials = sa_module.Credentials.from_service_account_info(
                raw_json, scopes=SCOPES
            )
            auth_req = GoogleRequest()
            credentials.refresh(auth_req)

            result["valid"] = True
            result["identity"] = {
                "service_account": raw_json.get("client_email"),
                "project_id":      raw_json.get("project_id"),
                "key_id":          raw_json.get("private_key_id"),
                "token_uri":       raw_json.get("token_uri"),
            }
            result["_credentials"] = credentials
            result["_project"]     = raw_json.get("project_id")

        except Exception as e:
            result["error"] = f"Token refresh failed — key may be revoked: {e}"

        return result

    def _validate_raw_jwt(self, result, raw_json):
        """Validate without google-auth by constructing a JWT manually."""
        try:
            import base64, hashlib, hmac
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend

            private_key_pem = raw_json.get("private_key", "").encode()
            client_email    = raw_json.get("client_email", "")
            token_uri       = raw_json.get("token_uri", GCP_TOKEN_URL)

            # Build JWT header + claim
            now = int(time.time())
            header  = {"alg": "RS256", "typ": "JWT"}
            payload = {
                "iss": client_email,
                "sub": client_email,
                "aud": token_uri,
                "iat": now,
                "exp": now + 3600,
                "scope": " ".join(SCOPES),
            }

            def b64url(data):
                import base64, json as _j
                s = _j.dumps(data, separators=(",", ":")).encode()
                return base64.urlsafe_b64encode(s).rstrip(b"=").decode()

            signing_input = f"{b64url(header)}.{b64url(payload)}".encode()

            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None, backend=default_backend()
            )
            signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
            jwt_token = f"{signing_input.decode()}.{sig_b64}"

            resp = requests.post(token_uri, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion":  jwt_token,
            }, timeout=15)

            if resp.ok:
                result["valid"] = True
                result["identity"] = {
                    "service_account": client_email,
                    "project_id":      raw_json.get("project_id"),
                    "key_id":          raw_json.get("private_key_id"),
                }
                result["_access_token"] = resp.json().get("access_token")
                result["_project"]      = raw_json.get("project_id")
            else:
                result["error"] = f"Token request failed [{resp.status_code}]: {resp.text[:200]}"

        except ImportError:
            result["error"] = ("Neither google-auth nor cryptography is installed. "
                               "Run: pip install google-auth cryptography")
        except Exception as e:
            result["error"] = str(e)

        return result

    def enumerate(self, result: Dict[str, Any]) -> None:
        if not result.get("valid"):
            result.setdefault("permissions", [])
            result.setdefault("blast_radius", {})
            return

        credentials = result.pop("_credentials", None)
        access_token = result.pop("_access_token", None)
        project     = result.pop("_project", None)

        # Build auth headers
        if credentials and hasattr(credentials, "token"):
            headers = {"Authorization": f"Bearer {credentials.token}"}
        elif access_token:
            headers = {"Authorization": f"Bearer {access_token}"}
        else:
            result.setdefault("permissions", [])
            result.setdefault("blast_radius", {})
            return

        # ── Service Blast-Radius Probes ───────────────────────────────────────
        accessible: List[str] = []
        for url_template, label in BLAST_PROBES:
            url = url_template.format(project=project or "")
            try:
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code in (200, 206):
                    accessible.append(label)
                elif r.status_code == 403:
                    pass  # Denied
            except Exception:
                pass

        # ── IAM Roles for this SA ─────────────────────────────────────────────
        sa_email = result["identity"].get("service_account", "")
        roles: List[str] = []
        try:
            r = requests.post(
                f"{GCP_CRM_API}/projects/{project}:getIamPolicy",
                headers=headers,
                json={"options": {"requestedPolicyVersion": 3}},
                timeout=10,
            )
            if r.ok:
                policy = r.json()
                for binding in policy.get("bindings", []):
                    members = binding.get("members", [])
                    if any(sa_email in m for m in members):
                        roles.append(binding["role"])
        except Exception:
            pass

        is_editor  = any("editor" in r or "owner" in r for r in roles)
        is_admin   = any("admin" in r for r in roles)
        has_viewer = any("viewer" in r for r in roles)

        severity = ("CRITICAL" if is_editor or is_admin
                    else "HIGH" if len(accessible) >= 3
                    else "MEDIUM" if accessible
                    else "LOW")

        result["permissions"] = {
            "iam_roles":         roles,
            "accessible_apis":   accessible,
        }
        result["blast_radius"] = {
            "severity":          severity,
            "accessible_services":accessible,
            "iam_roles":         roles,
            "is_editor_or_owner":is_editor or is_admin,
            "summary": _gcp_summary(severity, roles, accessible, project),
        }


def _gcp_summary(severity, roles, services, project):
    if any("owner" in r for r in roles):
        return f"⚠️  Project Owner on {project} — full GCP project compromise."
    if any("editor" in r for r in roles):
        return f"⚠️  Project Editor on {project} — read/write all services, deploy code, exfiltrate data."
    if any("admin" in r for r in roles):
        return f"🔴 Admin role(s): {', '.join(r for r in roles if 'admin' in r)[:3]}."
    if services:
        return f"🟡 Access confirmed to: {', '.join(services[:4])}."
    return "🟢 Key valid but limited confirmed access."
