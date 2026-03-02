"""
AWS credential validator.
Validates access key pairs via STS and enumerates attached IAM permissions.
"""
import re
import logging
from typing import Any, Dict, List

from .base import BaseValidator

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("cloudkeyrotator")

# Services we probe to assess blast radius
BLAST_RADIUS_PROBES = [
    ("s3",         "list_buckets",          {},                              "S3 full bucket access"),
    ("iam",        "list_users",            {},                              "IAM user enumeration"),
    ("iam",        "list_roles",            {},                              "IAM role enumeration"),
    ("ec2",        "describe_instances",    {"MaxResults": 5},              "EC2 instance access"),
    ("lambda",     "list_functions",        {"MaxItems": 5},                "Lambda function access"),
    ("secretsmanager","list_secrets",       {"MaxResults": 5},              "Secrets Manager access"),
    ("rds",        "describe_db_instances", {"MaxRecords": 5},              "RDS database access"),
    ("sts",        "get_caller_identity",   {},                              "STS identity"),
    ("sns",        "list_topics",           {},                              "SNS topic access"),
    ("sqs",        "list_queues",           {},                              "SQS queue access"),
    ("cloudtrail", "describe_trails",       {},                              "CloudTrail access"),
    ("route53",    "list_hosted_zones",     {},                              "Route53 DNS access"),
    ("ecr",        "describe_repositories", {},                              "ECR container access"),
    ("eks",        "list_clusters",         {},                              "EKS cluster access"),
    ("dynamodb",   "list_tables",           {},                              "DynamoDB table access"),
]


class AWSValidator(BaseValidator):
    def validate(self) -> Dict[str, Any]:
        """
        Validate AWS access key and secret key, returning a result dictionary.
        """
        result: Dict[str, Any] = {
            "provider":    "AWS",
            "cred_type":   "access_key",
            "valid":       False,
            "identity":    {},
            "permissions": [],
            "blast_radius":{},
            "error":       None,
            "remediation": {
                "revoke_command": f"aws iam delete-access-key --access-key-id {self.credential[:20]}... --user-name <username>",
                "docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
            }
        }

        if not BOTO3_AVAILABLE:
            result["error"] = "boto3 not installed. Run: pip install boto3"
            return result

        access_key = self.credential.strip()
        # Try to pull the raw matched value if present
        if self.meta.get("matched_value"):
            access_key = self.meta["matched_value"]

        secret_key = self.meta.get("secret_key")
        if not secret_key:
            result["error"] = "AWS Secret Access Key required for full validation"
            result["valid"] = False
            return result

        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            sts = session.client("sts")
            identity = sts.get_caller_identity()

            result["valid"]    = True
            result["identity"] = {
                "account_id": identity.get("Account"),
                "arn":        identity.get("Arn"),
                "user_id":    identity.get("UserId"),
                "is_root":    ":root" in identity.get("Arn", ""),
            }
            result["_session"] = session    # carry session for enumeration
        except ClientError as e:
            code = e.response["Error"]["Code"]
            logger.warning(f"AWS ClientError: {code} - {e.response['Error']['Message']}")
            result["error"] = f"AWS Error [{code}]: {e.response['Error']['Message']}"
        except Exception as e:
            logger.error(f"AWS Exception: {e}")
            result["error"] = str(e)

        return result

    def enumerate(self, result: Dict[str, Any]) -> None:
        """
        Enrich result with permissions and blast radius assessment for AWS credentials.
        """
        session = result.pop("_session", None)
        if not session or not result.get("valid"):
            result.setdefault("permissions", [])
            result.setdefault("blast_radius", {})
            return

        # ── IAM Policy Enumeration ────────────────────────────────────────────
        allowed:  List[str] = []
        denied:   List[str] = []
        critical: List[str] = []

        iam = session.client("iam")
        try:
            # Simulate policy for the caller identity
            arn = result["identity"].get("arn", "")
            if arn and not result["identity"].get("is_root"):
                sim_actions = [
                    "s3:*", "iam:CreateUser", "iam:AttachRolePolicy",
                    "ec2:*", "lambda:InvokeFunction", "secretsmanager:GetSecretValue",
                    "sts:AssumeRole", "cloudtrail:DeleteTrail",
                    "iam:CreateAccessKey", "iam:PassRole",
                    "s3:PutBucketPolicy", "ec2:CreateVpc",
                    "route53:CreateHostedZone", "sns:Publish",
                    "iam:UpdateAssumeRolePolicy",
                ]
                resp = iam.simulate_principal_policy(
                    PolicySourceArn=arn,
                    ActionNames=sim_actions,
                )
                for eval_result in resp.get("EvaluationResults", []):
                    action = eval_result["EvalActionName"]
                    decision = eval_result["EvalDecision"]
                    if decision == "allowed":
                        allowed.append(action)
                        if action in ("iam:CreateUser","iam:AttachRolePolicy",
                                      "iam:CreateAccessKey","cloudtrail:DeleteTrail",
                                      "iam:PassRole","iam:UpdateAssumeRolePolicy"):
                            critical.append(action)
                    else:
                        denied.append(action)
        except ClientError as e:
            logger.warning(f"AWS IAM ClientError: {e}")
        except Exception as e:
            logger.error(f"AWS IAM Exception: {e}")

        # ── Service Blast-Radius Probes ───────────────────────────────────────
        accessible_services: List[str] = []
        for svc, method, kwargs, label in BLAST_RADIUS_PROBES:
            try:
                client = session.client(svc, region_name="us-east-1")
                getattr(client, method)(**kwargs)
                accessible_services.append(label)
                if svc not in [a.split(":")[0] for a in allowed]:
                    allowed.append(f"{svc}:{method}")
            except ClientError as e:
                if e.response["Error"]["Code"] not in ("AccessDenied", "AuthFailure",
                                                        "UnauthorizedOperation"):
                    accessible_services.append(f"{label} (partial)")
            except Exception:
                pass

        # ── Attached Policies ─────────────────────────────────────────────────
        attached_policies: List[str] = []
        try:
            arn = result["identity"].get("arn", "")
            username = arn.split("/")[-1] if "/user/" in arn else None
            if username:
                resp = iam.list_attached_user_policies(UserName=username)
                attached_policies = [p["PolicyName"] for p in resp.get("AttachedPolicies", [])]
                # Check for admin
                for pol in attached_policies:
                    if "AdministratorAccess" in pol or pol == "AdministratorAccess":
                        critical.append("FULL_ADMIN_ACCESS")
        except ClientError:
            pass

        # ── Summarise ─────────────────────────────────────────────────────────
        result["permissions"] = {
            "allowed":           allowed,
            "denied":            denied[:10],
            "attached_policies": attached_policies,
        }

        severity = "CRITICAL" if (result["identity"].get("is_root") or "FULL_ADMIN_ACCESS" in critical
                                   or len(critical) >= 2) \
                 else "HIGH"   if critical \
                 else "MEDIUM" if accessible_services \
                 else "LOW"

        result["blast_radius"] = {
            "severity":           severity,
            "accessible_services":accessible_services,
            "critical_actions":   critical,
            "is_root_account":    result["identity"].get("is_root", False),
            "account_id":         result["identity"].get("account_id"),
            "summary": _aws_summary(severity, result["identity"], accessible_services, critical),
        }


def _aws_summary(severity, identity, services, critical):
    if identity.get("is_root"):
        return ("⚠️  ROOT account credentials — complete account compromise. "
                "All resources, billing, and sub-accounts are at risk.")
    if "FULL_ADMIN_ACCESS" in critical:
        return ("⚠️  AdministratorAccess policy attached — full account compromise. "
                "Attacker can create users, assume any role, access all data.")
    if critical:
        return (f"🔴 High-privilege actions available ({', '.join(critical[:3])}). "
                "Privilege escalation to admin likely possible.")
    if services:
        return (f"🟡 Read/write access to {len(services)} service(s). "
                "Data exfiltration and lateral movement possible.")
    return "🟢 Limited access — low blast radius."
