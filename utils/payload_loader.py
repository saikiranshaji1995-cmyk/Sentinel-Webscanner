"""Payload loading helpers."""

from __future__ import annotations

from pathlib import Path
from typing import List


def load_payloads(payload_file: Path) -> List[str]:
    if not payload_file.exists():
        return []

    payloads: List[str] = []
    for line in payload_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        payloads.append(stripped)
    return payloads

