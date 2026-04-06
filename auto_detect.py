"""File type detection for the unified DataGuard CLI."""

from __future__ import annotations

import csv
import io
import os
import re

# Map file extensions to the module that should be used to process them
EXTENSION_TO_MODULE = {
    ".log": "logs",
    ".csv": "csv",
    ".tsv": "csv",
    ".html": "html",
    ".htm": "html",
}

MODULE_PRIORITY = ["logs", "csv", "html", "contacts", "audit", "sanitize"]

# Word-boundary HTTP methods (avoids matching "TARGETED", "wget", etc.)
_HTTP_METHOD_RE = re.compile(
    r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
)

_SAMPLE_MAX_SCAN = 250
_SAMPLE_MAX_NONEMPTY = 35