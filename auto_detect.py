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

def _row_cells(line: str, delimiter: str) -> list[str]:
    try:
        return list(next(csv.reader(io.StringIO(line.strip(), newline=""), delimiter=delimiter)))
    except (csv.Error, StopIteration):
        return []

def score_as_csv(lines: list[str]) -> float:
    if not lines:
        return 0.0
    delimiters = [",", ";", "\t", "|"]
    scores: list[float] = []
    for delimiter in delimiters:
        counts = _parsed_column_counts(lines, delimiter)
        if len(counts) < 2:
            continue
        head = counts[: min(8, len(counts))]
        if len(set(head)) != 1:
            continue
        col_count = head[0]
        if col_count < 2:
            continue
        full_consistent = len(set(counts)) == 1
        score = 0.3
        if col_count >= 3:
            score += 0.15
        if full_consistent:
            score += 0.25
        if len(counts) >= 5:
            score += 0.1
        first_cells = _row_cells(lines[0], delimiter)
        if len(first_cells) == col_count and first_cells:
            nonempty = [(c or "").strip() for c in first_cells if (c or "").strip()]
            if nonempty and not all(re.fullmatch(r"-?\d+(?:\.\d+)?", c) for c in nonempty):
                score += 0.15
        scores.append(min(score, 1.0))
    return min(max(scores or [0.0]), 1.0)

def score_as_html(lines: list[str]) -> float:
    score = 0.0
    text = "\n".join(lines)
    if re.search(r"<!DOCTYPE|<html|<body|<div|<span|<p\b", text, re.IGNORECASE):
        score += 0.55
    if re.search(r"<script|<a\b|<img\b|</\w+>", text, re.IGNORECASE):
        score += 0.4
    # No extra score for bare "<" and ">" (reduces false positives in logs/code)
    return min(score, 1.0)

def score_as_contacts(lines: list[str]) -> float:
    score = 0.0
    text = "\n".join(lines)
    if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", text):
        score += 0.45
    if re.search(r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}", text):
        score += 0.3
    if re.search(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b", text):
        score += 0.12
    if re.search(r"(?m)^From:\s", text):
        score += 0.1
    if re.search(r"<[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}>", text):
        score += 0.08
    return min(score, 1.0)

def score_as_passwords(lines: list[str], *, csv_score: float = 0.0, html_score: float = 0.0) -> float:
    if not lines:
        return 0.0
    usable_lines = [line for line in lines if line.strip()]
    if not usable_lines:
        return 0.0
    if len(usable_lines) < 3:
        return 0.15

    score = 0.0
    simple_lines = sum(
        1
        for line in usable_lines
        if len(line.split()) == 1 and "@" not in line and "<" not in line and not line.strip().startswith("#")
    )
    if simple_lines / len(usable_lines) >= 0.75:
        score += 0.35
    if any(re.search(r"[A-Z]", line) and re.search(r"\d", line) for line in usable_lines):
        score += 0.2
    if all("," not in line and ";" not in line and "\t" not in line and "|" not in line for line in usable_lines):
        score += 0.15
    if all(len(line) <= 64 for line in usable_lines):
        score += 0.15

    score = min(score, 1.0)
    if csv_score >= 0.5:
        score *= 0.4
    elif csv_score >= 0.35:
        score *= 0.65
    if html_score >= 0.55:
        score *= 0.45
    return min(score, 1.0)

def score_as_plain_text(lines: list[str]) -> float:
    text = "\n".join(lines)
    if not text.strip():
        return 0.0
    if re.search(r"[\u200b\u200c\u200d\u2060]", text):
        return 0.8
    return 0.35