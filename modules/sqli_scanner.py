"""Error-based SQL injection scanner module."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from modules.crawler import CrawlResult, FormDetails
from utils.http_client import HTTPClient
from utils.payload_loader import load_payloads


class SQLiScanner:
    name = "sqli"

    SQL_ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"pg_query\(\):",
        r"sqliteexception",
        r"sqlstate\[\w+\]",
        r"odbc sql server driver",
    ]

    def __init__(self, client: HTTPClient, payload_file: Path):
        self.client = client
        self.payloads = load_payloads(payload_file)
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.SQL_ERROR_PATTERNS]

    def run(self, crawl_result: CrawlResult, target_url: str, threads: int = 8) -> List[Dict[str, object]]:
        findings: List[Dict[str, object]] = []
        candidate_urls = [u for u in crawl_result.urls if urlparse(u).query]
        forms = [f for f in crawl_result.forms if f.inputs]

        with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
            future_map = {}
            for url in candidate_urls:
                future_map[executor.submit(self._scan_query_endpoint, url)] = f"URL:{url}"
            for form in forms:
                future_map[executor.submit(self._scan_form, form)] = f"FORM:{form.source_url}"

            for future in as_completed(future_map):
                try:
                    findings.extend(future.result())
                except Exception:
                    continue
        return findings

    def _find_error_signature(self, text: str) -> Optional[str]:
        for pattern in self.compiled_patterns:
            match = pattern.search(text)
            if match:
                return match.group(0)
        return None

    def _scan_query_endpoint(self, url: str) -> List[Dict[str, object]]:
        parsed = urlparse(url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        params = parse_qs(parsed.query, keep_blank_values=True)
        findings: List[Dict[str, object]] = []

        for param_name in params.keys():
            for payload in self.payloads:
                mutated = {k: list(v) for k, v in params.items()}
                mutated[param_name] = [payload]
                test_url = f"{base_url}?{urlencode(mutated, doseq=True)}"
                response = self.client.get(test_url)
                if response is None:
                    continue

                signature = self._find_error_signature(response.text)
                if signature:
                    findings.append(
                        {
                            "module": self.name,
                            "severity": "high",
                            "url": test_url,
                            "method": "GET",
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"Detected SQL error signature: {signature}",
                        }
                    )
                    break
        return findings

    def _scan_form(self, form: FormDetails) -> List[Dict[str, object]]:
        findings: List[Dict[str, object]] = []
        action_url = urljoin(form.source_url, form.action)
        base_data = {name: "sentinel" for name in form.inputs}

        for target_input in form.inputs:
            for payload in self.payloads:
                data = dict(base_data)
                data[target_input] = payload

                if form.method == "post":
                    response = self.client.post(action_url, data=data)
                else:
                    response = self.client.get(action_url, params=data)

                if response is None:
                    continue

                signature = self._find_error_signature(response.text)
                if signature:
                    findings.append(
                        {
                            "module": self.name,
                            "severity": "high",
                            "url": action_url,
                            "method": form.method.upper(),
                            "parameter": target_input,
                            "payload": payload,
                            "evidence": f"Detected SQL error signature: {signature}",
                        }
                    )
                    break
        return findings

