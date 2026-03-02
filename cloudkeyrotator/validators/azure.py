"""
Azure credential validator.
Supports: Client Secrets, Storage Connection Strings, SAS tokens.
"""
import re
import json
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

import requests

from .base import BaseValidator

AZURE_LOGIN = "https://login.microsoftonline.com"
GRAPH_API   = "https://graph.microsoft.com/v1.0"
ARM_API     = "https://management.azure.com"


class AzureValidator(BaseValidator):

    def validate(self) -> Dict[str, Any]:
        cred_type = self.meta.get("pattern_name", "")

        if "Connection String" in cred_type:
            return self._validate_storage_connection()
        elif "SAS" in cred_type:
            return self._validate_sas_token()
        else:
            return self._validate_client_secret()

    # ── Client Secret ──────────────────────────────────────────────────────
    def _validate_client_secret(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "provider":    "Azure",
            "cred_type":   "client_secret",
            "valid":       False,
            "identity":    {},
            "permissions": [],
            "blast_radius":{},
            "error":       None,
            "remediation": {
                "portal_url": "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps",
                "cli_command": "az ad app credential delete --id <app-id> --key-id <key-id>",
                "docs": "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal",
            }
        }

        tenant_id = self.meta.get("tenant_id")
        client_id = self.meta.get("client_id")

        if not tenant_id or not client_id:
            result["error"] = ("Azure Client Secret validation requires --tenant-id and --client-id. "
                               "Run: cloudkeyrotator scan <secret> --tenant-id <tid> --client-id <cid>")
            return result

        # Request token for Microsoft Graph
        token_url = f"{AZURE_LOGIN}/{tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": self.credential,
            "scope":         "https://graph.microsoft.com/.default",
        }

        try:
            resp = requests.post(token_url, data=data, timeout=15)
        except requests.RequestException as e:
            result["error"] = f"Network error: {e}"
            return result

        if resp.status_code == 400:
            err = resp.json()
            result["error"] = f"Bad request: {err.get('error_description', err)}"
            return result
        if resp.status_code == 401:
            result["error"] = "Invalid client secret (HTTP 401)"
            return result

        token_data = resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            result["error"] = f"Token acquisition failed: {token_data}"
            return result

        result["valid"]    = True
        result["_token"]   = access_token
        result["_tenant"]  = tenant_id
        result["_client"]  = client_id
        result["identity"] = {
            "tenant_id": tenant_id,
            "client_id": client_id,
            "token_type": token_data.get("token_type"),
            "expires_in": token_data.get("expires_in"),
        }
        return result

    # ── Storage Connection String ──────────────────────────────────────────
    def _validate_storage_connection(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "provider":    "Azure",
            "cred_type":   "storage_connection_string",
            "valid":       False,
            "identity":    {},
            "permissions": [],
            "blast_radius":{},
            "error":       None,
            "remediation": {
                "cli_command": "az storage account keys renew --account-name <name> -g <rg> --key key1",
                "docs": "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage",
            }
        }

        # Try to list containers via Blob REST API
        parts = {}
        for part in self.credential.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                parts[k] = v

        account_name   = parts.get("AccountName")
        endpoint_suffix = parts.get("EndpointSuffix", "core.windows.net")

        if not account_name:
            result["error"] = "Could not parse AccountName from connection string"
            return result

        try:
            from azure.storage.blob import BlobServiceClient
            client = BlobServiceClient.from_connection_string(self.credential)
            containers = list(client.list_containers(timeout=10))
            result["valid"] = True
            result["identity"] = {
                "account_name":    account_name,
                "container_count": len(containers),
                "containers":      [c["name"] for c in containers[:20]],
                "endpoint_suffix": endpoint_suffix,
            }
            result["_blob_client"] = client
        except Exception as e:
            # Fallback: try unauthenticated REST probe to confirm account exists
            url = f"https://{account_name}.blob.{endpoint_suffix}/?comp=list"
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 403:
                    # 403 means the key is wrong OR account exists but is locked
                    result["error"] = f"azure-storage-blob not installed or key invalid: {e}"
                elif resp.status_code == 200:
                    result["valid"] = True
                    result["identity"] = {
                        "account_name": account_name,
                        "note": "Public listing enabled — no auth needed (misconfiguration!)"
                    }
                else:
                    result["error"] = str(e)
            except Exception:
                result["error"] = str(e)

        return result

    # ── SAS Token ──────────────────────────────────────────────────────────
    def _validate_sas_token(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "provider":    "Azure",
            "cred_type":   "sas_token",
            "valid":       False,
            "identity":    {},
            "permissions": [],
            "blast_radius":{},
            "error":       None,
            "remediation": {
                "docs": "https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview",
                "note": "SAS tokens cannot be revoked directly — rotate storage account keys to invalidate."
            }
        }

        sas = self.credential.strip().lstrip("?")
        params = parse_qs(sas)

        result["identity"] = {
            "signed_version":   params.get("sv", [None])[0],
            "signed_services":  params.get("ss", [None])[0],
            "signed_resource_types": params.get("srt", [None])[0],
            "signed_permissions": params.get("sp", [None])[0],
            "signed_expiry":    params.get("se", [None])[0],
            "signed_start":     params.get("st", [None])[0],
            "allowed_ip":       params.get("sip", [None])[0],
            "protocols":        params.get("spr", [None])[0],
        }

        # A well-formed SAS that parses is considered "structurally valid"
        # Actual validation requires the account URL
        if params.get("sv") and params.get("sig"):
            result["valid"] = True
            result["error"] = ("Note: SAS token structure is valid. "
                               "Full validation requires the storage account URL.")
        else:
            result["error"] = "Malformed SAS token — missing required parameters"

        return result

    def enumerate(self, result: Dict[str, Any]) -> None:
        token  = result.pop("_token",  None)
        tenant = result.pop("_tenant", None)
        client = result.pop("_client", None)
        blob_c = result.pop("_blob_client", None)

        if not result.get("valid"):
            result.setdefault("permissions", [])
            result.setdefault("blast_radius", {})
            return

        cred_type = result.get("cred_type")

        if cred_type == "storage_connection_string":
            self._enumerate_storage(result, blob_c)
        elif token:
            self._enumerate_sp(result, token, tenant, client)
        else:
            result.setdefault("permissions", [])
            result.setdefault("blast_radius", {
                "severity": "MEDIUM",
                "summary": "🟡 SAS token grants storage access. Expiry determines risk window.",
            })

    def _enumerate_sp(self, result, token, tenant, client_id):
        headers = {"Authorization": f"Bearer {token}"}
        perms: List[str] = []
        critical: List[str] = []

        # Check what Graph API endpoints are accessible
        probes = [
            (f"{GRAPH_API}/organization",             "Read tenant/org info"),
            (f"{GRAPH_API}/users?$top=5",             "List Entra ID users"),
            (f"{GRAPH_API}/groups?$top=5",            "List Entra ID groups"),
            (f"{GRAPH_API}/applications?$top=5",      "List registered apps"),
            (f"{GRAPH_API}/servicePrincipals?$top=5", "List service principals"),
            (f"{GRAPH_API}/directoryRoles",           "Read directory roles"),
            (f"{GRAPH_API}/domains",                  "List tenant domains"),
        ]

        accessible_graph: List[str] = []
        for url, label in probes:
            try:
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code == 200:
                    accessible_graph.append(label)
                    perms.append(f"Graph: {label}")
            except Exception:
                pass

        # Check ARM (Azure Resource Manager) scopes
        arm_token_data = None
        try:
            arm_resp = requests.post(
                f"{AZURE_LOGIN}/{tenant}/oauth2/v2.0/token",
                data={
                    "grant_type":    "client_credentials",
                    "client_id":     client_id,
                    "client_secret": self.credential,
                    "scope":         "https://management.azure.com/.default",
                },
                timeout=15,
            )
            if arm_resp.ok:
                arm_token = arm_resp.json().get("access_token")
                if arm_token:
                    arm_headers = {"Authorization": f"Bearer {arm_token}"}
                    subs_resp = requests.get(
                        f"{ARM_API}/subscriptions?api-version=2022-12-01",
                        headers=arm_headers, timeout=10
                    )
                    if subs_resp.ok:
                        subs = subs_resp.json().get("value", [])
                        for sub in subs:
                            perms.append(f"ARM: Subscription {sub['subscriptionId']} ({sub.get('displayName','')})")
                            critical.append(f"arm_subscription_access:{sub['subscriptionId']}")
        except Exception:
            pass

        severity = "CRITICAL" if critical else "HIGH" if accessible_graph else "LOW"
        result["permissions"] = {"allowed": perms}
        result["blast_radius"] = {
            "severity":             severity,
            "accessible_graph_apis":accessible_graph,
            "arm_subscriptions":    len([p for p in perms if p.startswith("ARM:")]),
            "critical_access":      critical,
            "summary": _azure_sp_summary(severity, accessible_graph, critical),
        }

    def _enumerate_storage(self, result, blob_client):
        if not blob_client:
            result.setdefault("permissions", [])
            result.setdefault("blast_radius", {
                "severity": "HIGH",
                "summary": "🔴 Storage account access confirmed. All blobs potentially readable/writable.",
            })
            return

        containers = result["identity"].get("containers", [])
        total_blobs = 0
        sensitive_containers = []
        sensitive_keywords = ["backup", "secret", "key", "config", "env", "password",
                              "private", "credential", "cert", "token"]

        try:
            for cname in containers[:10]:
                try:
                    cc = blob_client.get_container_client(cname)
                    blobs = list(cc.list_blobs(timeout=10))
                    total_blobs += len(blobs)
                    if any(kw in cname.lower() for kw in sensitive_keywords):
                        sensitive_containers.append(cname)
                    for blob in blobs[:20]:
                        if any(kw in blob.name.lower() for kw in sensitive_keywords):
                            if cname not in sensitive_containers:
                                sensitive_containers.append(cname)
                            break
                except Exception:
                    pass
        except Exception:
            pass

        severity = "CRITICAL" if sensitive_containers else "HIGH"
        result["permissions"] = {
            "allowed": ["storage:list_containers", "storage:list_blobs", "storage:read", "storage:write"]
        }
        result["blast_radius"] = {
            "severity":             severity,
            "total_containers":     len(containers),
            "total_blobs_sampled":  total_blobs,
            "sensitive_containers": sensitive_containers,
            "summary": (
                f"⚠️  Storage account key — full read/write to {len(containers)} container(s), "
                f"~{total_blobs}+ blobs. "
                + (f"Sensitive containers: {', '.join(sensitive_containers[:3])}." if sensitive_containers else "")
            ),
        }


def _azure_sp_summary(severity, graph_apis, arm):
    if arm:
        return ("⚠️  Service principal has Azure subscription access via ARM. "
                "Resource modification, data exfiltration, and persistence possible.")
    if graph_apis:
        return (f"🔴 Graph API access confirmed — {len(graph_apis)} endpoint(s) accessible. "
                "User enumeration, app enumeration, and lateral movement possible.")
    return "🟢 Token valid but minimal permissions confirmed."
