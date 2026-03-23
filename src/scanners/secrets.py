"""Secrets and credential detection scanner."""
from .base import BaseScanner, ScanRule, Severity


class SecretsScanner(BaseScanner):
    name = "secrets"
    description = "Detects hardcoded secrets, API keys, and credentials"

    rules = [
        ScanRule(
            rule_id="SEC001",
            pattern=r"""(?:api[_-]?key|apikey)\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{20,}[\"']""",
            severity=Severity.CRITICAL,
            message="Hardcoded API key detected",
            suggestion="Use environment variables: os.environ['API_KEY'] or process.env.API_KEY",
            cwe_id="CWE-798",
        ),
        ScanRule(
            rule_id="SEC002",
            pattern=r"""(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{4,}[\"']""",
            severity=Severity.CRITICAL,
            message="Hardcoded password detected",
            suggestion="Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault)",
            cwe_id="CWE-798",
        ),
        ScanRule(
            rule_id="SEC003",
            pattern=r"""(?:secret|token|auth)\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{20,}[\"']""",
            severity=Severity.CRITICAL,
            message="Hardcoded secret/token detected",
            suggestion="Use environment variables or a secrets manager",
            cwe_id="CWE-798",
        ),
        ScanRule(
            rule_id="SEC004",
            pattern=r"""(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}""",
            severity=Severity.CRITICAL,
            message="AWS Access Key ID detected",
            suggestion="Use IAM roles or AWS credentials file, never hardcode AWS keys",
            cwe_id="CWE-798",
        ),
        ScanRule(
            rule_id="SEC005",
            pattern=r"""(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}""",
            severity=Severity.CRITICAL,
            message="GitHub personal access token detected",
            suggestion="Use GITHUB_TOKEN environment variable or GitHub Apps",
            cwe_id="CWE-798",
        ),
        ScanRule(
            rule_id="SEC006",
            pattern=r"""sk-[a-zA-Z0-9]{20,}""",
            severity=Severity.CRITICAL,
            message="OpenAI/Stripe secret key pattern detected",
            suggestion="Store API keys in environment variables, never in source code",
            cwe_id="CWE-798",
        ),
        ScanRule(
            rule_id="SEC007",
            pattern=r"""-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----""",
            severity=Severity.CRITICAL,
            message="Private key embedded in source code",
            suggestion="Store private keys in secure file storage with restricted permissions, not in code",
            cwe_id="CWE-321",
        ),
        ScanRule(
            rule_id="SEC008",
            pattern=r"""(?:jdbc|mysql|postgres|mongodb|redis)://[^/\s]+:[^/\s]+@""",
            severity=Severity.HIGH,
            message="Database connection string with embedded credentials",
            suggestion="Use environment variables for connection strings: DATABASE_URL",
            cwe_id="CWE-798",
        ),
    ]
