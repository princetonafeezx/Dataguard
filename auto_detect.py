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

def score_as_log(lines: list[str]) -> float:
    score = 0.0
    line_count = max(len(lines), 1)
    for line in lines:
        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line):
            score += 0.2
        # Bracketed segment long enough to resemble a log timestamp, not just "[]"
        if re.search(r"\[[^\]\n]{4,}\]", line):
            score += 0.1
        if _HTTP_METHOD_RE.search(line):
            score += 0.2
        if re.search(r"\b[1-5]\d{2}\b", line):
            score += 0.1
    return min(score / line_count, 1.0)

def _parsed_column_counts(lines: list[str], delimiter: str) -> list[int]:
    counts: list[int] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            row = next(csv.reader(io.StringIO(line, newline=""), delimiter=delimiter))
        except csv.Error:
            continue
        if not row:
            continue
        if len(row) == 1 and not (row[0] or "").strip():
            continue
        counts.append(len(row))
    return counts

    