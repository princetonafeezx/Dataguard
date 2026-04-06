"""Config loading and persistence helpers."""

from __future__ import annotations

import json
from pathlib import Path

from dataguard.errors import InputError


CONFIG_FILE_NAME = ".dataguardrc"

DEFAULT_CONFIG = {
    "default_output_format": "text",     
    "color_enabled": True,                  
    "verbosity": 0,                       
    "strict_mode": False,                   
    "min_confidence_threshold": 0.3,      
    "password_min_length": 8,               
    "log_top_n": 10,                      
    "pipe_format": "text",                
    "report_format": "text",              
}

_KNOWN_KEYS = frozenset(DEFAULT_CONFIG)

def get_config_path(cwd: str | None = None) -> Path:
    base_path = Path(cwd or Path.cwd())
    return base_path / CONFIG_FILE_NAME

def _constrain_config_value(key: str, value: object) -> object:
    if key == "min_confidence_threshold":
        v = float(value)
        return max(0.0, min(1.0, v))
    if key == "verbosity":
        return max(0, min(10, int(value)))
    if key == "password_min_length":
        return max(1, min(256, int(value)))
    if key == "log_top_n":
        return max(1, min(10_000, int(value)))
    if key == "pipe_format":
        v = str(value).lower()
        allowed = ("text", "json", "raw")
        if v not in allowed:
            raise ValueError(f"must be one of {list(allowed)}, got {value!r}")
        return v
    if key == "report_format":
        v = str(value).lower()
        allowed = ("text", "json", "csv")
        if v not in allowed:
            raise ValueError(f"must be one of {list(allowed)}, got {value!r}")
        return v
    if key == "default_output_format":
        s = str(value).strip()
        if not s:
            raise ValueError("cannot be empty")
        return s
    return value