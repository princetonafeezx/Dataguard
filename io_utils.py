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