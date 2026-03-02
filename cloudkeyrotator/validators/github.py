"""
GitHub PAT validator.
Validates tokens via the GitHub REST API and enumerates repo/org scopes.
"""
import re
from typing import Any, Dict, List

import requests

from .base import BaseValidator

GITHUB_API = "https://api.github.com"

# Scope → what damage it enables
SCOPE_RISK = {
    "repo":             ("HIGH",    "Full read/write on all private repositories"),
    "repo:status":      ("LOW",     "Commit status read/write"),
    "repo:deployment":  ("MEDIUM",  "Deployments read/write"),
    "public_repo":      ("MEDIUM",  "Write access to public repos"),
    "repo:invite":      ("LOW",     "Accept/decline repo invites"),
    "security_events":  ("MEDIUM",  "Read/write security alerts"),
    "admin:repo_hook":  ("HIGH",    "Manage repo webhooks — data exfiltration vector"),
    "admin:org":        ("CRITICAL","Full org admin — manage members, teams, billing"),
    "admin:org_hook":   ("HIGH",    "Org-level webhooks — intercept all events"),
    "gist":             ("MEDIUM",  "Create/edit gists — code exfiltration"),
    "notifications":    ("LOW",     "Read notifications"),
    "user":             ("MEDIUM",  "Read/write profile — email harvesting"),
    "delete_repo":      ("HIGH",    "Delete repositories — destructive"),
    "write:packages":   ("HIGH",    "Publish packages — supply chain attack vector"),
    "admin:gpg_key":    ("MEDIUM",  "Manage GPG keys"),
    "workflow":         ("CRITICAL","Modify GitHub Actions — CI/CD code injection"),
    "write:discussion": ("LOW",     "Post in discussions"),
    "admin:enterprise": ("CRITICAL","Enterprise-level admin access"),
    "audit_log":        ("HIGH",    "Read org audit logs"),
    "codespace":        ("HIGH",    "Manage Codespaces environments"),
    "project":          ("MEDIUM",  "Manage Projects"),
    "read:user":        ("LOW",     "Read public user data"),
    "read:org":         ("LOW",     "Read org membership"),
    "read:packages":    ("LOW",     "Download packages"),
}

CRITICAL_SCOPES = {"admin:org", "admin:enterprise", "workflow", "repo"}


class GitHubValidator(BaseValidator):

    def validate(self) -> Dict[str, Any]:
        token = self.credential.strip()
        if self.meta.get("matched_value"):
            token = self.meta["matched_value"]

        result: Dict[str, Any] = {
            "provider":    "GitHub",
            "cred_type":   "personal_access_token",
            "valid":       False,
            "identity":    {},
            "permissions": [],
            "blast_radius":{},
            "error":       None,
            "remediation": {
                "revoke_url": "https://github.com/settings/tokens",
                "docs": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
            }
        }

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            resp = requests.get(f"{GITHUB_API}/user", headers=headers, timeout=10)
        except requests.RequestException as e:
            result["error"] = f"Network error: {e}"
            return result

        if resp.status_code == 401:
            result["error"] = "Token is invalid or expired (HTTP 401)"
            return result
        if resp.status_code == 403:
            result["error"] = "Token is valid but access forbidden (HTTP 403)"
            return result
        if resp.status_code != 200:
            result["error"] = f"Unexpected HTTP {resp.status_code}"
            return result

        data = resp.json()
        result["valid"] = True

        # Parse scopes from response header
        scopes_header = resp.headers.get("X-OAuth-Scopes", "")
        scopes = [s.strip() for s in scopes_header.split(",") if s.strip()]

        result["identity"] = {
            "login":       data.get("login"),
            "name":        data.get("name"),
            "email":       data.get("email"),
            "company":     data.get("company"),
            "site_admin":  data.get("site_admin", False),
            "two_fa":      data.get("two_factor_authentication"),
            "created_at":  data.get("created_at"),
            "public_repos":data.get("public_repos", 0),
            "followers":   data.get("followers", 0),
        }
        result["_token"]  = token
        result["_headers"]= headers
        result["_scopes"] = scopes

        return result

    def enumerate(self, result: Dict[str, Any]) -> None:
        if not result.get("valid"):
            result.setdefault("permissions", [])
            result.setdefault("blast_radius", {})
            return

        token   = result.pop("_token",   None)
        headers = result.pop("_headers", {})
        scopes  = result.pop("_scopes",  [])

        # ── Scope Risk Assessment ─────────────────────────────────────────────
        scope_details: List[Dict] = []
        critical_scopes: List[str] = []
        highest = "LOW"
        severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

        for scope in scopes:
            risk_level, description = SCOPE_RISK.get(scope, ("MEDIUM", "Custom or unknown scope"))
            scope_details.append({"scope": scope, "risk": risk_level, "description": description})
            if risk_level == "CRITICAL" or scope in CRITICAL_SCOPES:
                critical_scopes.append(scope)
            if severity_rank.get(risk_level, 0) > severity_rank.get(highest, 0):
                highest = risk_level

        # ── Org Memberships ───────────────────────────────────────────────────
        orgs: List[str] = []
        try:
            resp = requests.get(f"{GITHUB_API}/user/orgs", headers=headers, timeout=10)
            if resp.ok:
                orgs = [o["login"] for o in resp.json()]
        except Exception:
            pass

        # ── Private Repos accessible ──────────────────────────────────────────
        private_repos = 0
        try:
            resp = requests.get(
                f"{GITHUB_API}/user/repos",
                headers=headers,
                params={"visibility": "private", "per_page": 100},
                timeout=10,
            )
            if resp.ok:
                private_repos = len(resp.json())
        except Exception:
            pass

        # ── Check for admin on any org ────────────────────────────────────────
        org_admin: List[str] = []
        for org in orgs:
            try:
                resp = requests.get(
                    f"{GITHUB_API}/orgs/{org}/members",
                    headers=headers,
                    params={"role": "admin"},
                    timeout=10,
                )
                if resp.ok:
                    me = result["identity"]["login"]
                    if any(m["login"] == me for m in resp.json()):
                        org_admin.append(org)
                        if "CRITICAL" not in [s["risk"] for s in scope_details]:
                            critical_scopes.append(f"org_admin:{org}")
                            highest = "CRITICAL"
            except Exception:
                pass

        result["permissions"] = {
            "scopes":       scopes,
            "scope_details": scope_details,
            "org_memberships": orgs,
            "org_admin_of": org_admin,
            "private_repos_accessible": private_repos,
        }

        result["blast_radius"] = {
            "severity":        highest,
            "critical_scopes": critical_scopes,
            "org_count":       len(orgs),
            "org_admin_count": len(org_admin),
            "private_repos":   private_repos,
            "is_site_admin":   result["identity"].get("site_admin", False),
            "summary": _github_summary(
                highest, scopes, critical_scopes, private_repos, orgs, org_admin
            ),
        }


def _github_summary(severity, scopes, critical, private_repos, orgs, org_admin):
    if not scopes:
        return "🟢 No scopes granted — read-only public access only."
    if "admin:enterprise" in critical:
        return "⚠️  Enterprise admin — complete GitHub enterprise compromise possible."
    if org_admin:
        return (f"⚠️  Org admin on {len(org_admin)} organization(s) — "
                "member manipulation, repo deletion, webhook injection.")
    if "workflow" in critical:
        return ("🔴 workflow scope — can modify GitHub Actions. "
                "Supply chain attack via CI/CD code injection.")
    if "admin:org" in critical:
        return "🔴 admin:org — full organization control."
    if "repo" in critical:
        return (f"🔴 Full repo scope + {private_repos} private repo(s) accessible. "
                "Source code, secrets, and deployment keys at risk.")
    if private_repos:
        return (f"🟡 Access to {private_repos} private repos. "
                f"Member of {len(orgs)} org(s).")
    return "🟢 Limited scopes — low blast radius."
