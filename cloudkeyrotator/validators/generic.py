"""
Generic token validator — probes common API endpoints to see if a token is valid.
Used as fallback when provider cannot be detected.
"""
from typing import Any, Dict

import requests
import logging

from .base import BaseValidator

GENERIC_PROBES = [
    ("https://api.github.com/user",                      {"Authorization": "Bearer {tok}"},   "GitHub"),
    ("https://slack.com/api/auth.test",                  {"Authorization": "Bearer {tok}"},   "Slack"),
    ("https://discord.com/api/v10/users/@me",            {"Authorization": "Bearer {tok}"},   "Discord"),
    ("https://api.stripe.com/v1/balance",                {"Authorization": "Bearer {tok}"},   "Stripe"),
    ("https://api.sendgrid.com/v3/user/profile",         {"Authorization": "Bearer {tok}"},   "SendGrid"),
    ("https://api.twilio.com/2010-04-01/Accounts.json",  {"Authorization": "Bearer {tok}"},   "Twilio"),
    ("https://api.heroku.com/account",                   {"Authorization": "Bearer {tok}", "Accept": "application/vnd.heroku+json; version=3"}, "Heroku"),
    ("https://api.digitalocean.com/v2/account",          {"Authorization": "Bearer {tok}"},   "DigitalOcean"),
    ("https://api.cloudflare.com/client/v4/user/tokens/verify", {"Authorization": "Bearer {tok}"}, "Cloudflare"),
    ("https://api.npmjs.org/-/whoami",                   {"Authorization": "Bearer {tok}"},   "NPM"),
]

logger = logging.getLogger("cloudkeyrotator")


class GenericValidator(BaseValidator):
    def validate(self) -> Dict[str, Any]:
        """
        Validate generic token by probing common API endpoints.
        """
        result: Dict[str, Any] = {
            "provider":    "Unknown",
            "cred_type":   "generic_token",
            "valid":       False,
            "identity":    {},
            "permissions": [],
            "blast_radius":{},
            "error":       None,
            "remediation": {
                "note": "Manually identify provider and revoke via its dashboard/API."
            }
        }

        token = self.credential.strip()
        matches = []

        for url, header_template, provider_name in GENERIC_PROBES:
            headers = {k: v.replace("{tok}", token) for k, v in header_template.items()}
            try:
                r = requests.get(url, headers=headers, timeout=8)
                if r.status_code == 200:
                    matches.append({"provider": provider_name, "url": url, "response": r.json()})
                elif r.status_code not in (401, 403):
                    pass  # Ignore connection-level errors
            except Exception as e:
                logger.warning(f"Generic probe error for {provider_name}: {e}")

        if matches:
            result["valid"]    = True
            result["provider"] = matches[0]["provider"]
            result["identity"] = {"matched_services": [m["provider"] for m in matches]}
            result["blast_radius"] = {
                "severity": "HIGH",
                "matched_providers": [m["provider"] for m in matches],
                "summary": (f"⚠️  Token valid for: {', '.join(m['provider'] for m in matches)}. "
                            "Determine scope and revoke immediately.")
            }
        else:
            result["error"] = "Token did not match any known provider API."
            result["blast_radius"] = {
                "severity": "UNKNOWN",
                "summary": "Could not validate — token format unknown or all probe endpoints returned 401/403."
            }

        return result

    def enumerate(self, result: Dict[str, Any]) -> None:
        """
        No-op: generic probe already enumerates in validate().
        """
        result.setdefault("permissions", [])
