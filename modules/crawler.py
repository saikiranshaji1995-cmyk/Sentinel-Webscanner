"""Domain-scoped crawler and HTML form discovery."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, List, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from utils.http_client import HTTPClient


@dataclass
class FormDetails:
    action: str
    method: str
    inputs: List[str]
    source_url: str


@dataclass
class CrawlResult:
    urls: Set[str] = field(default_factory=set)
    forms: List[FormDetails] = field(default_factory=list)


class Crawler:
    def __init__(self, client: HTTPClient, logger):
        self.client = client
        self.logger = logger

    def crawl(self, start_url: str, max_depth: int = 1, max_pages: int = 50) -> CrawlResult:
        parsed_start = urlparse(start_url)
        if not parsed_start.scheme or not parsed_start.netloc:
            raise ValueError(f"Invalid target URL: {start_url}")

        allowed_domain = parsed_start.netloc
        queue: Deque[Tuple[str, int]] = deque([(self._normalize_url(start_url), 0)])
        visited: Set[str] = set()
        result = CrawlResult()

        while queue and len(visited) < max_pages:
            current_url, depth = queue.popleft()
            if current_url in visited or depth > max_depth:
                continue

            visited.add(current_url)
            response = self.client.get(current_url)
            if response is None:
                continue

            result.urls.add(current_url)
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            result.forms.extend(self._extract_forms(soup, current_url))

            for next_url in self._extract_links(soup, current_url, allowed_domain):
                if next_url not in visited:
                    queue.append((next_url, depth + 1))

        return result

    @staticmethod
    def _normalize_url(url: str) -> str:
        parsed = urlparse(url)
        cleaned = parsed._replace(fragment="")
        return urlunparse(cleaned)

    @staticmethod
    def _extract_forms(soup: BeautifulSoup, source_url: str) -> List[FormDetails]:
        forms: List[FormDetails] = []
        for form in soup.find_all("form"):
            action = form.get("action") or source_url
            method = (form.get("method") or "get").lower()
            input_names: List[str] = []

            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                field_type = (field.get("type") or "").lower()
                if not name or field_type in {"submit", "button", "reset"}:
                    continue
                input_names.append(name)

            forms.append(
                FormDetails(
                    action=action,
                    method=method,
                    inputs=sorted(set(input_names)),
                    source_url=source_url,
                )
            )
        return forms

    @staticmethod
    def _extract_links(soup: BeautifulSoup, current_url: str, allowed_domain: str) -> List[str]:
        urls: List[str] = []
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue

            candidate = urljoin(current_url, href)
            parsed = urlparse(candidate)
            if parsed.netloc != allowed_domain:
                continue

            normalized = urlunparse(parsed._replace(fragment=""))
            urls.append(normalized)
        return sorted(set(urls))

