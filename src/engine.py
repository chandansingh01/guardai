"""Core scanning engine that orchestrates all scanners."""
import os
import time
from pathlib import Path
from typing import Dict, List, Optional
from .scanners import ALL_SCANNERS
from .scanners.base import Finding, Severity

IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
    ".nuxt", "vendor", "target", "bin", "obj",
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".php", ".go",
    ".java", ".html", ".vue", ".jinja", ".jinja2", ".j2",
    ".blade.php", ".yml", ".yaml", ".toml", ".cfg", ".ini",
}


class ScanResult:
    def __init__(self, target_path: str):
        self.target_path = target_path
        self.findings: List[Finding] = []
        self.files_scanned: int = 0
        self.scan_duration: float = 0.0

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def score(self) -> int:
        """Security score 0-100. 100 = no issues."""
        if self.files_scanned == 0:
            return 100
        penalty = (
            self.critical_count * 25
            + self.high_count * 10
            + self.medium_count * 3
            + self.low_count * 1
        )
        return max(0, 100 - penalty)

    def to_dict(self):
        return {
            "target": self.target_path,
            "score": self.score,
            "files_scanned": self.files_scanned,
            "duration_seconds": round(self.scan_duration, 2),
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class GuardAIEngine:
    def __init__(self, scanners=None):
        self.scanners = [cls() for cls in (scanners or ALL_SCANNERS)]

    def collect_files(
        self, target_path: str, extensions: Optional[set] = None
    ) -> Dict[str, str]:
        exts = extensions or SCAN_EXTENSIONS
        files = {}
        target = Path(target_path)

        if target.is_file():
            try:
                content = target.read_text(errors="ignore")
                files[str(target)] = content
            except (OSError, PermissionError):
                pass
            return files

        for root, dirs, filenames in os.walk(target):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in filenames:
                fpath = Path(root) / fname
                if fpath.suffix in exts:
                    try:
                        content = fpath.read_text(errors="ignore")
                        rel_path = str(fpath.relative_to(target))
                        files[rel_path] = content
                    except (OSError, PermissionError):
                        pass
        return files

    def scan(self, target_path: str) -> ScanResult:
        start = time.time()
        result = ScanResult(target_path)

        files = self.collect_files(target_path)
        result.files_scanned = len(files)

        for scanner in self.scanners:
            findings = scanner.scan_files(files)
            result.findings.extend(findings)

        # Sort: critical first, then by file
        result.findings.sort(
            key=lambda f: (
                list(Severity).index(f.severity),
                f.file_path,
                f.line_number,
            )
        )

        result.scan_duration = time.time() - start
        return result
