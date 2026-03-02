import pytest
from cloudkeyrotator.detector import detect_credential
from cloudkeyrotator.validators.aws import AWSValidator
from cloudkeyrotator.validators.azure import AzureValidator
from cloudkeyrotator.validators.gcp import GCPValidator
from cloudkeyrotator.validators.github import GitHubValidator
from cloudkeyrotator.validators.generic import GenericValidator

class DummyResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {}
        self.ok = status_code == 200
    def json(self):
        return self._json

# Edge case: AWS key detected but no secret provided
def test_aws_missing_secret():
    cred = "AKIAIOSFODNN7EXAMPLE"
    meta = {"matched_value": cred}
    validator = AWSValidator(cred, meta)
    result = validator.validate()
    assert not result["valid"]
    assert "Secret Access Key" in result["error"]

# Edge case: Azure client secret with random string
def test_azure_client_secret_random():
    cred = "A" * 40
    meta = {"pattern_name": "Azure Client Secret"}
    validator = AzureValidator(cred, meta)
    result = validator.validate()
    assert not result["valid"] or result["error"]

# Edge case: GCP service account with invalid JSON
def test_gcp_invalid_json():
    cred = "{not:valid_json}"
    meta = {}
    validator = GCPValidator(cred, meta)
    result = validator.validate()
    assert not result["valid"]
    assert "Invalid JSON" in result["error"]

# Edge case: GitHub token with invalid format
def test_github_invalid_token():
    cred = "ghp_invalidtoken"
    meta = {"matched_value": cred}
    validator = GitHubValidator(cred, meta)
    result = validator.validate()
    assert not result["valid"] or result["error"]

# Edge case: Generic token not matching any provider
def test_generic_token_no_match():
    cred = "notarealtoken1234567890"
    meta = {}
    validator = GenericValidator(cred, meta)
    result = validator.validate()
    assert not result["valid"]
    assert "did not match" in result["error"]

# Edge case: Empty credential
def test_empty_credential():
    cred = ""
    result = detect_credential(cred)
    assert result is None
