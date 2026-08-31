from agentguard.scanners.pii import PIIScanner
from agentguard.scanners.secrets import SecretsScanner
from agentguard.scanners.url_threat import URLThreatScanner


def test_pii_redacts_email_and_ssn():
    r = PIIScanner().scan("Contact me at alice@example.com or via SSN 123-45-6789.")
    assert "[REDACTED_EMAIL]" in r.sanitized_text
    assert "[REDACTED_SSN]" in r.sanitized_text
    cats = {f.category for f in r.findings}
    assert "email" in cats and "ssn" in cats


def test_pii_luhn_valid_credit_card():
    # 4111 1111 1111 1111 is a famous Luhn-valid test card
    r = PIIScanner().scan("My card is 4111 1111 1111 1111, please charge it.")
    cats = {f.category for f in r.findings}
    assert "credit_card" in cats


def test_secrets_redacts_openai_key():
    r = SecretsScanner().scan("My key is sk-abc123def456ghi789jkl0mnopqr.")
    assert "[REDACTED_OPENAI_API_KEY]" in r.sanitized_text
    cats = {f.category for f in r.findings}
    assert "openai_api_key" in cats


def test_secrets_redacts_aws_and_github():
    text = "aws AKIAIOSFODNN7EXAMPLE and gh ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    r = SecretsScanner().scan(text)
    cats = {f.category for f in r.findings}
    assert "aws_access_key" in cats
    assert "github_pat" in cats


def test_url_blocks_cloud_metadata():
    r = URLThreatScanner().scan("fetch http://169.254.169.254/latest/meta-data/")
    cats = {f.category for f in r.findings}
    assert "cloud_metadata_url" in cats


def test_url_blocks_private_ip():
    r = URLThreatScanner(block_private_ranges=True).scan("call http://10.0.0.5/internal")
    cats = {f.category for f in r.findings}
    assert "private_ip_url" in cats


def test_url_allowlist_enforcement():
    r = URLThreatScanner(allowed_domains=["api.openai.com"]).scan(
        "fetch https://evil.com/payload and https://api.openai.com/v1/x"
    )
    cats = {f.category for f in r.findings}
    assert "domain_not_allowlisted" in cats
    # api.openai.com should not be flagged
    snippets = [f.snippet for f in r.findings if f.category == "domain_not_allowlisted"]
    assert all("evil.com" in s for s in snippets)
