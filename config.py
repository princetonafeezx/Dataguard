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

def coerce_config_value(key: str, value: object) -> object:
    default = DEFAULT_CONFIG[key]

    if type(default) is bool:
        if type(value) is bool:
            coerced = value
        elif isinstance(value, str):
            low = value.strip().lower()
            if low in ("true", "1", "yes", "on"):
                coerced = True
            elif low in ("false", "0", "no", "off"):
                coerced = False
            else:
                raise ValueError(f"expected a boolean, got {value!r}")
        elif type(value) is int:
            coerced = value != 0
        else:
            raise TypeError(f"expected boolean-like value, got {type(value).__name__}")

    elif type(default) is int:
        if type(value) is bool:
            raise TypeError("expected integer, not boolean")
        if isinstance(value, float) and not value.is_integer():
            raise TypeError("expected a whole number")
        coerced = int(value)

    elif type(default) is float:
        if type(value) is bool:
            raise TypeError("expected number, not boolean")
        coerced = float(value)

    elif isinstance(default, str):
        coerced = str(value).strip()

    else:
        coerced = value

    return _constrain_config_value(key, coerced)

def _merge_loaded_dict(base: dict, loaded: dict) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    out = dict(base)
    for key, raw in loaded.items():
        if key not in _KNOWN_KEYS:
            warnings.append(f"Ignored unknown config key {key!r}.")
            continue
        try:
            out[key] = coerce_config_value(key, raw)
        except (TypeError, ValueError) as exc:
            raise InputError(f"Invalid value for config key {key!r}: {exc}") from exc
    return out, warnings

def load_config(cwd: str | None = None) -> tuple[dict, Path, list[str]]:
    config = dict(DEFAULT_CONFIG)
    config_path = get_config_path(cwd)
    if not config_path.exists():
        return config, config_path, []

    try:
        text = config_path.read_text(encoding="utf-8")
        loaded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"Invalid JSON in config file {config_path}: {exc}") from exc

    if not isinstance(loaded, dict):
        raise InputError(
            f"Config file must contain a JSON object, not {type(loaded).__name__}."
        )

    merged, warnings = _merge_loaded_dict(config, loaded)
    return merged, config_path, warnings