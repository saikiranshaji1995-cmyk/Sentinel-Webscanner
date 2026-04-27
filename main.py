#!/usr/bin/env python3
"""Sentinel WebScanner entrypoint."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from modules.crawler import Crawler
from modules.headers_scanner import HeaderScanner
from modules.open_redirect_scanner import OpenRedirectScanner
from modules.sqli_scanner import SQLiScanner
from modules.xss_scanner import XSSScanner
from utils.http_client import HTTPClient
from utils.logger import configure_logging
from utils.output import print_banner, print_finding, print_summary, write_json_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sentinel WebScanner - authorized web application security scanner "
            "for reflected XSS, SQLi error patterns, open redirects, and security headers."
        )
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target URL to scan (for example: https://testphp.vulnweb.com).",
    )
    parser.add_argument(
        "-m",
        "--modules",
        default="xss,sqli,redirect,headers",
        help="Comma-separated modules: xss,sqli,redirect,headers",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=8,
        help="Number of worker threads per module (default: 8).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Request timeout in seconds (default: 8.0).",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Crawler depth (default: 1).",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Maximum pages to crawl (default: 50).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="reports/scan_report.json",
        help="Path for JSON report output (default: reports/scan_report.json).",
    )
    parser.add_argument(
        "--user-agent",
        default="Sentinel-WebScanner/1.0",
        help="HTTP User-Agent header.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (use only in controlled labs).",
    )
    parser.add_argument(
        "--log-file",
        default="scanner.log",
        help="Path to log file (default: scanner.log).",
    )
    return parser.parse_args()


def build_modules(
    selected: List[str], payload_dir: Path, client: HTTPClient
) -> List[object]:
    module_registry = {
        "xss": XSSScanner(client, payload_dir / "xss_payloads.txt"),
        "sqli": SQLiScanner(client, payload_dir / "sqli_payloads.txt"),
        "redirect": OpenRedirectScanner(client, payload_dir / "redirect_payloads.txt"),
        "headers": HeaderScanner(client),
    }

    unknown = [name for name in selected if name not in module_registry]
    if unknown:
        raise ValueError(
            f"Unknown module(s): {', '.join(unknown)}. "
            "Allowed: xss,sqli,redirect,headers."
        )
    return [module_registry[name] for name in selected]


def summarize_findings(findings: List[Dict[str, object]]) -> Dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        summary.setdefault(severity, 0)
        summary[severity] += 1
        summary["total"] += 1
    return summary


def main() -> int:
    args = parse_args()
    logger = configure_logging(Path(args.log_file))

    print_banner()
    logger.info("Starting scan for target: %s", args.target)

    payload_dir = Path(__file__).resolve().parent / "payloads"
    modules_requested = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
    if not modules_requested:
        logger.error("No scanner modules selected.")
        return 2

    client = HTTPClient(
        timeout=args.timeout,
        user_agent=args.user_agent,
        verify_tls=not args.insecure,
        logger=logger,
    )
    crawler = Crawler(client, logger)

    try:
        crawl_result = crawler.crawl(
            start_url=args.target, max_depth=args.depth, max_pages=args.max_pages
        )
        logger.info(
            "Crawl completed. URLs discovered: %d, forms discovered: %d",
            len(crawl_result.urls),
            len(crawl_result.forms),
        )
    except Exception as exc:
        logger.exception("Crawler failed: %s", exc)
        return 1

    try:
        scanners = build_modules(modules_requested, payload_dir, client)
    except ValueError as exc:
        logger.error(str(exc))
        return 2

    all_findings: List[Dict[str, object]] = []
    for scanner in scanners:
        logger.info("Running module: %s", scanner.name)
        try:
            findings = scanner.run(crawl_result=crawl_result, target_url=args.target, threads=args.threads)
            all_findings.extend(findings)
            logger.info("Module %s completed with %d findings.", scanner.name, len(findings))
        except Exception as exc:
            logger.exception("Module %s failed: %s", scanner.name, exc)

    for finding in all_findings:
        print_finding(finding)

    summary = summarize_findings(all_findings)
    print_summary(summary)

    report = {
        "target": args.target,
        "scan_started_at": datetime.now(timezone.utc).isoformat(),
        "modules": modules_requested,
        "crawl_stats": {
            "discovered_urls": len(crawl_result.urls),
            "discovered_forms": len(crawl_result.forms),
        },
        "summary": summary,
        "findings": all_findings,
    }
    write_json_report(Path(args.output), report, logger)
    logger.info("Scan finished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

