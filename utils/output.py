"""Console and report output helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from colorama import Fore, Style, init

init(autoreset=True)


def print_banner() -> None:
    print(Fore.CYAN + "=" * 66)
    print(Fore.CYAN + " Sentinel WebScanner | Authorized Security Testing Utility")
    print(Fore.CYAN + "=" * 66)


def _severity_color(severity: str) -> str:
    mapping = {
        "critical": Fore.MAGENTA,
        "high": Fore.RED,
        "medium": Fore.YELLOW,
        "low": Fore.GREEN,
        "info": Fore.CYAN,
    }
    return mapping.get(severity.lower(), Fore.WHITE)


def print_finding(finding: Dict[str, object]) -> None:
    severity = str(finding.get("severity", "info")).lower()
    color = _severity_color(severity)
    print(
        color
        + f"[{severity.upper():7}]"
        + Style.RESET_ALL
        + f" {finding.get('module')} | {finding.get('url')}\n"
        + f"         Param: {finding.get('parameter')} | Evidence: {finding.get('evidence')}"
    )


def print_summary(summary: Dict[str, int]) -> None:
    print("\n" + Fore.CYAN + "Scan Summary")
    print(Fore.CYAN + "-" * 66)
    print(
        f"Total: {summary.get('total', 0)} | "
        f"Critical: {summary.get('critical', 0)} | "
        f"High: {summary.get('high', 0)} | "
        f"Medium: {summary.get('medium', 0)} | "
        f"Low: {summary.get('low', 0)} | "
        f"Info: {summary.get('info', 0)}"
    )


def write_json_report(output_path: Path, report: Dict[str, object], logger) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("JSON report saved to %s", output_path.resolve())

