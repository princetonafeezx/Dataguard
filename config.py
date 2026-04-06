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



