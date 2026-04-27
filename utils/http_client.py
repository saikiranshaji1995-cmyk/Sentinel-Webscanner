"""HTTP helper with sane defaults and retries."""

from __future__ import annotations

from typing import Any, Optional

import requests
from requests import Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HTTPClient:
    def __init__(self, timeout: float, user_agent: str, verify_tls: bool, logger):
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "*/*"})

        retries = Retry(
            total=2,
            backoff_factor=0.4,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=50, pool_maxsize=50)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self, method: str, url: str, **kwargs: Any) -> Optional[Response]:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        try:
            response = self.session.request(method=method.upper(), url=url, **kwargs)
            return response
        except requests.RequestException as exc:
            self.logger.warning("Request failed (%s %s): %s", method.upper(), url, exc)
            return None

    def get(self, url: str, **kwargs: Any) -> Optional[Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Optional[Response]:
        return self.request("POST", url, **kwargs)

