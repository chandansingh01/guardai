"""SQL Injection and Command Injection scanner."""
from .base import BaseScanner, ScanRule, Severity


class InjectionScanner(BaseScanner):
    name = "injection"
    description = "Detects SQL injection and command injection vulnerabilities"

    rules = [
        # SQL Injection
        ScanRule(
            rule_id="SQL001",
            pattern=r"""(execute|cursor\.execute|\.query|\.raw)\s*\(\s*f[\"']""",
            severity=Severity.CRITICAL,
            message="SQL query built with f-string — high risk of SQL injection",
            suggestion="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            cwe_id="CWE-89",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="SQL002",
            pattern=r"""(execute|query|raw)\s*\(.*\+\s*(request|req|params|input|user|args)""",
            severity=Severity.CRITICAL,
            message="SQL query concatenated with user input — SQL injection risk",
            suggestion="Use parameterized queries instead of string concatenation",
            cwe_id="CWE-89",
            file_types=[".py", ".js", ".ts", ".rb", ".php"],
        ),
        ScanRule(
            rule_id="SQL003",
            pattern=r"""(execute|query)\s*\(\s*[\"'].*%s.*%s.*[\"']\s*%\s*\(""",
            severity=Severity.HIGH,
            message="SQL query using %-formatting — prefer parameterized queries",
            suggestion="Use cursor.execute('query', (params,)) instead of string formatting",
            cwe_id="CWE-89",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="SQL004",
            pattern=r"""\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|FROM|WHERE)|\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\$\{""",
            severity=Severity.CRITICAL,
            message="SQL query with template literal interpolation — SQL injection risk",
            suggestion="Use parameterized queries with placeholders",
            cwe_id="CWE-89",
            file_types=[".js", ".ts"],
        ),

        # Command Injection
        ScanRule(
            rule_id="CMD001",
            pattern=r"""os\.system\s*\(.*(\+|f[\"']|\.format|%s)""",
            severity=Severity.CRITICAL,
            message="OS command with user-controlled input — command injection risk",
            suggestion="Use subprocess.run() with a list of arguments instead of os.system()",
            cwe_id="CWE-78",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="CMD002",
            pattern=r"""subprocess\.(call|run|Popen)\s*\(\s*[f\"'].*shell\s*=\s*True""",
            severity=Severity.HIGH,
            message="subprocess with shell=True and string command — command injection risk",
            suggestion="Use subprocess.run(['cmd', 'arg1', 'arg2']) without shell=True",
            cwe_id="CWE-78",
            file_types=[".py"],
        ),
        ScanRule(
            rule_id="CMD003",
            pattern=r"""child_process\.(exec|execSync)\s*\(.*(\+|\$\{|concat)""",
            severity=Severity.CRITICAL,
            message="child_process.exec with dynamic input — command injection risk",
            suggestion="Use child_process.execFile() or spawn() with argument arrays",
            cwe_id="CWE-78",
            file_types=[".js", ".ts"],
        ),
        ScanRule(
            rule_id="CMD004",
            pattern=r"""eval\s*\(.*(\+|request|req|params|input|user|args|\$\{)""",
            severity=Severity.CRITICAL,
            message="eval() with dynamic input — code injection risk",
            suggestion="Avoid eval(). Use JSON.parse() for data, or a safe expression parser",
            cwe_id="CWE-94",
            file_types=[".py", ".js", ".ts", ".rb", ".php"],
        ),
    ]
