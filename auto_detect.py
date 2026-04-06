"""File type detection for the unified DataGuard CLI."""

from __future__ import annotations

import csv
import io
import os
import re

EXTENSION_TO_MODULE = {
    ".log": "logs",
    ".csv": "csv",
    ".tsv": "csv",
    ".html": "html",
    ".htm": "html",
}

MODULE_PRIORITY = ["logs", "csv", "html", "contacts", "audit", "sanitize"]

_HTTP_METHOD_RE = re.compile(
    r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
)

_SAMPLE_MAX_SCAN = 250
_SAMPLE_MAX_NONEMPTY = 35

def sample_lines(text: str) -> list[str]:
    """Prefer non-empty, non-comment lines up to limits; fall back to raw prefix if sample is empty."""
    sampled: list[str] = []
    scanned = 0
    for line in text.splitlines():
        scanned += 1
        if scanned > _SAMPLE_MAX_SCAN:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        sampled.append(line)
        if len(sampled) >= _SAMPLE_MAX_NONEMPTY:
            break
    if sampled:
        return sampled
    raw = text.splitlines()[:25]
    return raw