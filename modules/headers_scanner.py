"""HTTP security header scanner module."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from modules.crawler import CrawlResult
from utils.http_client import HTTPClient


class HeaderScanner:
    name = "headers"

    REQUIRED_HEADERS = {
        "Content-Security-Policy": "Mitigates script injection and data injection attacks.",
        "X-Frame-Options": "Mitigates clickjacking attacks.",
        "X-Content-Type-Options": "Prevents MIME type sniffing.",
        "Referrer-Policy": "Controls referrer data leakage.",
        "Permissions-Policy": "Restricts browser feature access.",
    }

    def __init__(self, client: HTTPClient):
        self.client = client

    def run(self, crawl_result: CrawlResult, target_url: str, threads: int = 8) -> List[Dict[str, object]]:
        targets = sorted(crawl_result.urls)[: min(25, len(crawl_result.urls))]
        if target_url not in targets:
            targets.insert(0, target_url)

        findings: List[Dict[str, object]] = []
        with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
            futures = [executor.submit(self._scan_url, url) for url in targets]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                except Exception:
                    continue
        return findings

    def _scan_url(self, url: str) -> Dict[str, object] | None:
        response = self.client.get(url)
        if response is None:
            return None

        missing = [name for name in self.REQUIRED_HEADERS if name not in response.headers]
        if not missing:
            return None

        severity = "low" if len(missing) <= 2 else "medium"
        return {
            "module": self.name,
            "severity": severity,
            "url": url,
            "method": "GET",
            "parameter": "N/A",
            "payload": "N/A",
            "evidence": f"Missing security headers: {', '.join(missing)}",
            "details": {name: self.REQUIRED_HEADERS[name] for name in missing},
        }

