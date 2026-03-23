"""Base scanner interface."""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
import re


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file_path: str
    line_number: int
    line_content: str
    suggestion: Optional[str] = None
    cwe_id: Optional[str] = None

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "suggestion": self.suggestion,
            "cwe_id": self.cwe_id,
        }


@dataclass
class ScanRule:
    rule_id: str
    pattern: str
    severity: Severity
    message: str
    suggestion: Optional[str] = None
    cwe_id: Optional[str] = None
    file_types: List[str] = field(default_factory=list)

    @property
    def compiled_pattern(self):
        if not hasattr(self, "_compiled"):
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self._compiled


class BaseScanner:
    name: str = "base"
    description: str = ""
    rules: List[ScanRule] = []

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for rule in self.rules:
                if rule.file_types and not any(
                    file_path.endswith(ext) for ext in rule.file_types
                ):
                    continue
                if rule.compiled_pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=file_path,
                            line_number=i,
                            line_content=line,
                            suggestion=rule.suggestion,
                            cwe_id=rule.cwe_id,
                        )
                    )
        return findings

    def scan_files(self, files: dict) -> List[Finding]:
        all_findings = []
        for path, content in files.items():
            all_findings.extend(self.scan_file(path, content))
        return all_findings
