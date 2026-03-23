"""GuardAI CLI — scan code for security vulnerabilities."""
import json
import sys
import os

# Add parent dir to path for direct execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.engine import GuardAIEngine
from src.scanners.base import Severity

# ANSI colors
COLORS = {
    "critical": "\033[91m",  # red
    "high": "\033[93m",      # yellow
    "medium": "\033[33m",    # orange
    "low": "\033[36m",       # cyan
    "info": "\033[37m",      # white
    "reset": "\033[0m",
    "bold": "\033[1m",
    "green": "\033[92m",
    "dim": "\033[2m",
}


def colorize(text, color):
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_banner():
    print(colorize("""
  ╔══════════════════════════════════════╗
  ║   🛡️  GuardAI Security Scanner      ║
  ║   Catch vulnerabilities before       ║
  ║   they reach production              ║
  ╚══════════════════════════════════════╝
""", "bold"))


def print_finding(finding, index):
    sev = finding.severity.value
    color = sev
    badge = f"[{sev.upper()}]"

    print(f"  {colorize(badge, color)} {colorize(finding.rule_id, 'dim')} — {finding.message}")
    print(f"    {colorize('File:', 'dim')} {finding.file_path}:{finding.line_number}")
    print(f"    {colorize('Code:', 'dim')} {finding.line_content.strip()[:120]}")
    if finding.suggestion:
        print(f"    {colorize('Fix:', 'green')} {finding.suggestion}")
    if finding.cwe_id:
        print(f"    {colorize('Ref:', 'dim')} {finding.cwe_id}")
    print()


def print_score(score):
    if score >= 90:
        color = "green"
        grade = "A"
    elif score >= 70:
        color = "medium"
        grade = "B"
    elif score >= 50:
        color = "high"
        grade = "C"
    else:
        color = "critical"
        grade = "F"

    bar_filled = score // 2
    bar_empty = 50 - bar_filled
    bar = colorize("█" * bar_filled, color) + colorize("░" * bar_empty, "dim")

    print(f"  Security Score: {colorize(f'{score}/100 ({grade})', color)}")
    print(f"  [{bar}]")
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="guardai",
        description="GuardAI — AI Code Security Scanner",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit with code 1 if findings at this severity or above",
    )

    args = parser.parse_args()

    engine = GuardAIEngine()
    result = engine.scan(args.target)

    # Filter by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    min_idx = severity_order.index(args.min_severity)
    result.findings = [
        f for f in result.findings
        if severity_order.index(f.severity.value) <= min_idx
    ]

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_banner()
        print(f"  Scanned {colorize(str(result.files_scanned), 'bold')} files in {result.scan_duration:.2f}s")
        print()

        if result.findings:
            print(f"  Found {colorize(str(len(result.findings)), 'critical')} potential vulnerabilities:\n")
            for i, finding in enumerate(result.findings, 1):
                print_finding(finding, i)
        else:
            print(f"  {colorize('No vulnerabilities found!', 'green')}\n")

        print_score(result.score)

    # Exit code
    if args.fail_on:
        fail_idx = severity_order.index(args.fail_on)
        severe_findings = [
            f for f in result.findings
            if severity_order.index(f.severity.value) <= fail_idx
        ]
        if severe_findings:
            sys.exit(1)


if __name__ == "__main__":
    main()
