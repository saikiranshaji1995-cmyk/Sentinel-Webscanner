"""Reflected XSS scanner module."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from modules.crawler import CrawlResult, FormDetails
from utils.http_client import HTTPClient
from utils.payload_loader import load_payloads


class XSSScanner:
    name = "xss"

    def __init__(self, client: HTTPClient, payload_file: Path):
        self.client = client
        self.payloads = load_payloads(payload_file)

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

                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type:
                    continue

                body = response.text
                if payload in body:
                    findings.append(
                        {
                            "module": self.name,
                            "severity": "high",
                            "url": test_url,
                            "method": "GET",
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": "Payload reflected in HTML response body.",
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

                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type:
                    continue

                if payload in response.text:
                    findings.append(
                        {
                            "module": self.name,
                            "severity": "high",
                            "url": action_url,
                            "method": form.method.upper(),
                            "parameter": target_input,
                            "payload": payload,
                            "evidence": "Payload reflected after form submission.",
                        }
                    )
                    break
        return findings
