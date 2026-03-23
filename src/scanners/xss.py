"""Cross-Site Scripting (XSS) vulnerability scanner."""
from .base import BaseScanner, ScanRule, Severity


class XSSScanner(BaseScanner):
    name = "xss"
    description = "Detects Cross-Site Scripting vulnerabilities"

    rules = [
        ScanRule(
            rule_id="XSS001",
            pattern=r"""innerHTML\s*=\s*(?!['"][^'"]*['"])""",
            severity=Severity.HIGH,
            message="Dynamic innerHTML assignment — XSS risk",
            suggestion="Use textContent for text, or sanitize with DOMPurify before innerHTML",
            cwe_id="CWE-79",
            file_types=[".js", ".ts", ".jsx", ".tsx"],
        ),
        ScanRule(
            rule_id="XSS002",
            pattern=r"""dangerouslySetInnerHTML\s*=\s*\{""",
            severity=Severity.HIGH,
            message="React dangerouslySetInnerHTML — ensure input is sanitized",
            suggestion="Sanitize with DOMPurify: dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}}",
            cwe_id="CWE-79",
            file_types=[".jsx", ".tsx", ".js", ".ts"],
        ),
        ScanRule(
            rule_id="XSS003",
            pattern=r"""document\.write\s*\(""",
            severity=Severity.HIGH,
            message="document.write() with potential user input — XSS risk",
            suggestion="Use DOM manipulation methods instead of document.write()",
            cwe_id="CWE-79",
            file_types=[".js", ".ts", ".html"],
        ),
        ScanRule(
            rule_id="XSS004",
            pattern=r"""\|\s*safe\b""",
            severity=Severity.MEDIUM,
            message="Jinja2/Django |safe filter — disables auto-escaping",
            suggestion="Only use |safe on content you fully control. Sanitize user input first",
            cwe_id="CWE-79",
            file_types=[".html", ".jinja", ".jinja2", ".j2"],
        ),
        ScanRule(
            rule_id="XSS005",
            pattern=r"""\{!!.*!!\}""",
            severity=Severity.HIGH,
            message="Blade unescaped output {!! !!} — XSS risk",
            suggestion="Use {{ }} for escaped output unless content is trusted and sanitized",
            cwe_id="CWE-79",
            file_types=[".blade.php"],
        ),
        ScanRule(
            rule_id="XSS006",
            pattern=r"""v-html\s*=""",
            severity=Severity.MEDIUM,
            message="Vue v-html directive — renders raw HTML, XSS risk",
            suggestion="Sanitize content with DOMPurify before using v-html",
            cwe_id="CWE-79",
            file_types=[".vue", ".js", ".ts"],
        ),
    ]
