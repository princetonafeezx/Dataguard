from __future__ import annotations

import sys
from typing import TypedDict

from dataguard.errors import InputError

UTF8_BOM = b"\xef\xbb\xbf"

_LATIN1_FALLBACK_WARNING = (
    "UTF-8 decode failed; interpreted bytes as Latin-1 (ISO-8859-1); "
    "if this is wrong, convert the input to UTF-8."
)

class InputReadMetadata(TypedDict):
        path: str
    encoding: str
    read_warnings: list[str]

def decode_bytes(raw_bytes: bytes) -> tuple[str, str, list[str]]:
    warnings: list[str] = []
    payload = raw_bytes
    if payload.startswith(UTF8_BOM):
        payload = payload[len(UTF8_BOM) :]
        warnings.append("Stripped UTF-8 BOM marker before decoding input.")

    try:
        return payload.decode("utf-8"), "utf-8", warnings
    except UnicodeDecodeError:
        text = payload.decode("latin-1")
        return text, "latin-1", warnings + [_LATIN1_FALLBACK_WARNING]

def read_text_file(path: str) -> tuple[str, InputReadMetadata]:
    try:
        with open(path, "rb") as handle:
            raw_bytes = handle.read()
    except OSError as exc:
        raise InputError(f"Could not read file: {path}") from exc

    text, encoding, warnings = decode_bytes(raw_bytes)
    metadata: InputReadMetadata = {"path": path, "encoding": encoding, "read_warnings": warnings}
    return text, metadata

def stdin_has_data() -> bool:
    return not sys.stdin.isatty()