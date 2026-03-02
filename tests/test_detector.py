"""Tests for the credential detector."""
import pytest
from cloudkeyrotator.detector import detect_credential


class TestAWSDetection:
    def test_iam_access_key(self):
        r = detect_credential("AKIAIOSFODNN7EXAMPLE")
        assert r is not None
        assert r["provider"] == "AWS"
        assert r["type"] == "aws_access_key"
        assert r["confidence"] == "high"

    def test_sts_temp_key(self):
        r = detect_credential("ASIAIOSFODNN7EXAMPLE")
        assert r is not None
        assert r["provider"] == "AWS"


class TestGitHubDetection:
    def test_classic_pat(self):
        token = "ghp_" + "A" * 36
        r = detect_credential(token)
        assert r is not None
        assert r["provider"] == "GitHub"
        assert r["type"] == "github_pat"

    def test_fine_grained(self):
        token = "github_pat_" + "A" * 82
        r = detect_credential(token)
        assert r is not None
        assert r["type"] == "github_fine_grained"

    def test_actions_token(self):
        token = "ghs_" + "A" * 36
        r = detect_credential(token)
        assert r is not None
        assert r["provider"] == "GitHub"


class TestGCPDetection:
    def test_service_account_json(self):
        sa_json = '''{
            "type": "service_account",
            "project_id": "my-project",
            "private_key_id": "abc123",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----",
            "client_email": "sa@my-project.iam.gserviceaccount.com",
            "client_id": "123456",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }'''
        r = detect_credential(sa_json)
        assert r is not None
        assert r["provider"] == "GCP"
        assert r["type"] == "gcp_service_account"
        assert r["meta"]["project_id"] == "my-project"


class TestAzureDetection:
    def test_storage_connection_string(self):
        conn = ("DefaultEndpointsProtocol=https;AccountName=mystorageaccount;"
                "AccountKey=" + "A" * 88 + ";EndpointSuffix=core.windows.net")
        r = detect_credential(conn)
        assert r is not None
        assert r["provider"] == "Azure"
        assert r["type"] == "azure_connection_string"
        assert r["meta"]["account_name"] == "mystorageaccount"

    def test_sas_token(self):
        sas = "?sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacupiytfx&se=2024-12-31T00:00:00Z&sig=xxx"
        r = detect_credential(sas)
        assert r is not None
        assert r["provider"] == "Azure"
        assert r["type"] == "azure_sas_token"


class TestUnknown:
    def test_random_string_short(self):
        r = detect_credential("hello")
        # Short strings shouldn't match confidently
        assert r is None or r["confidence"] in ("low", "medium")

    def test_empty(self):
        r = detect_credential("")
        assert r is None
