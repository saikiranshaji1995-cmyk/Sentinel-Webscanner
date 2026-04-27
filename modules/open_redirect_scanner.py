"""Open redirect scanner module."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from modules.crawler import CrawlResult
from utils.http_client import HTTPClient
from utils.payload_loader import load_payloads


class OpenRedirectScanner:
    name = "redirect"
    REDIRECT_KEYS = {
        "next",
        "url",
        "redirect",
        "redirect_url",
        "return",
        "returnurl",
        "continue",
        "dest",
        "destination",
        "callback",
        "redirect_uri",
    }

    def __init__(self, client: HTTPClient, payload_file: Path):
        self.client = client
        self.payloads = load_payloads(payload_file)

    def run(self, crawl_result: CrawlResult, target_url: str, threads: int = 8) -> List[Dict[str, object]]:
        candidate_urls: List[str] = []
        for url in crawl_result.urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            keys = set(parse_qs(parsed.query, keep_blank_values=True).keys())
            if any(k.lower() in self.REDIRECT_KEYS for k in keys):
                candidate_urls.append(url)

        findings: List[Dict[str, object]] = []
        with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
            futures = [executor.submit(self._scan_url, url) for url in candidate_urls]
            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception:
                    continue
        return findings

    def _scan_url(self, url: str) -> List[Dict[str, object]]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        findings: List[Dict[str, object]] = []

        for param_name in params.keys():
            if param_name.lower() not in self.REDIRECT_KEYS:
                continue

            for payload in self.payloads:
                mutated = {k: list(v) for k, v in params.items()}
                mutated[param_name] = [payload]
                test_url = f"{base_url}?{urlencode(mutated, doseq=True)}"
                response = self.client.get(test_url, allow_redirects=False)
                if response is None:
                    continue

                location = response.headers.get("Location", "")
                if response.status_code in {301, 302, 303, 307, 308} and payload in location:
                    findings.append(
                        {
                            "module": self.name,
                            "severity": "medium",
                            "url": test_url,
                            "method": "GET",
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"External redirect detected in Location header: {location}",
                        }
                    )
                    break
        return findings

