"""Dependency and configuration vulnerability scanner."""
from .base import BaseScanner, ScanRule, Severity


class DependencyScanner(BaseScanner):
    name = "dependency"
    description = "Detects insecure dependency usage and misconfigurations"

    rules = [
        ScanRule(
            rule_id="DEP001",
            pattern=r"""(?:requests|urllib|http)\.get\s*\(.*verify\s*=\s*False""",
            severity=Severity.HIGH,
            message="SSL verification disabled — man-in-the-middle attack risk",
            suggestion="Remove verify=False. If using self-signed certs, specify CA bundle path",
            cwe_id="CWE-295",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="DEP002",
            pattern=r"""(?:rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED)\s*[:=]\s*(?:false|0|'0')""",
            severity=Severity.HIGH,
            message="TLS certificate validation disabled",
            suggestion="Enable TLS validation. Use proper CA certificates for internal services",
            cwe_id="CWE-295",
            file_types=[".js", ".ts"],
        ),
        ScanRule(
            rule_id="DEP003",
            pattern=r"""(?:pickle|cPickle|shelve|marshal)\.load""",
            severity=Severity.HIGH,
            message="Deserialization of untrusted data — remote code execution risk",
            suggestion="Use json.load() or a safe serialization format. Never unpickle untrusted data",
            cwe_id="CWE-502",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="DEP004",
            pattern=r"""yaml\.load\s*\([^)]*(?!Loader)""",
            severity=Severity.HIGH,
            message="yaml.load() without safe Loader — code execution risk",
            suggestion="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
            cwe_id="CWE-502",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="DEP005",
            pattern=r"""DEBUG\s*=\s*True""",
            severity=Severity.MEDIUM,
            message="Debug mode enabled — should be disabled in production",
            suggestion="Use environment variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
            cwe_id="CWE-489",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="DEP006",
            pattern=r"""(?:ALLOWED_HOSTS|allowed_hosts)\s*=\s*\[\s*[\"']\*[\"']\s*\]""",
            severity=Severity.MEDIUM,
            message="Django ALLOWED_HOSTS set to wildcard — host header attack risk",
            suggestion="Set ALLOWED_HOSTS to specific domain names",
            cwe_id="CWE-20",
            file_types=[".py"],
        ),
    ]
