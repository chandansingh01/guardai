"""Authentication and authorization vulnerability scanner."""
from .base import BaseScanner, ScanRule, Severity


class AuthScanner(BaseScanner):
    name = "auth"
    description = "Detects authentication and authorization vulnerabilities"

    rules = [
        ScanRule(
            rule_id="AUTH001",
            pattern=r"""(?:verify|check).*(?:jwt|token|auth).*=\s*False""",
            severity=Severity.CRITICAL,
            message="Authentication/JWT verification disabled",
            suggestion="Always verify tokens: jwt.decode(token, key, algorithms=['HS256'])",
            cwe_id="CWE-287",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="AUTH002",
            pattern=r"""algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']""",
            severity=Severity.CRITICAL,
            message="JWT 'none' algorithm allowed — allows token forgery",
            suggestion="Explicitly specify allowed algorithms: algorithms=['HS256']",
            cwe_id="CWE-327",
            file_types=[".py", ".js", ".ts"],
        ),
        ScanRule(
            rule_id="AUTH003",
            pattern=r"""(?:cors|CORS).*(?:origin|Origin)\s*[:=]\s*[\"']\*[\"']""",
            severity=Severity.HIGH,
            message="CORS allows all origins — potential credential theft",
            suggestion="Restrict CORS to specific trusted domains",
            cwe_id="CWE-346",
        ),
        ScanRule(
            rule_id="AUTH004",
            pattern=r"""(?:hash|hashlib)\.md5\s*\(""",
            severity=Severity.HIGH,
            message="MD5 used for hashing — cryptographically broken",
            suggestion="Use bcrypt, scrypt, or argon2 for passwords; SHA-256+ for integrity",
            cwe_id="CWE-328",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="AUTH005",
            pattern=r"""\.createHash\s*\(\s*[\"'](?:md5|sha1)[\"']\s*\)""",
            severity=Severity.HIGH,
            message="Weak hash algorithm (MD5/SHA1) — use SHA-256 or better",
            suggestion="Use crypto.createHash('sha256') or bcrypt for passwords",
            cwe_id="CWE-328",
            file_types=[".js", ".ts"],
        ),
        ScanRule(
            rule_id="AUTH006",
            pattern=r"""(?:session|cookie).*(?:secure|httponly|samesite)\s*[:=]\s*(?:False|false|0)""",
            severity=Severity.HIGH,
            message="Insecure cookie/session configuration",
            suggestion="Set secure=True, httponly=True, samesite='Lax' on cookies",
            cwe_id="CWE-614",
        ),
        ScanRule(
            rule_id="AUTH007",
            pattern=r"""(?:password|secret).*(?:==|===|!=|!==|\.equals)""",
            severity=Severity.MEDIUM,
            message="String comparison for secrets — vulnerable to timing attacks",
            suggestion="Use hmac.compare_digest() (Python) or crypto.timingSafeEqual() (Node)",
            cwe_id="CWE-208",
            file_types=[".py", ".js", ".ts"],
        ),
    ]
