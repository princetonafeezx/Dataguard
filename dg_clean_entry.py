from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

def _loaded_dataguard_package_root(module: object) -> Path | None:
    init_file = getattr(module, "__file__", None)
    if init_file:
        try:
            return Path(init_file).resolve().parent
        except OSError:
            return None
    paths = getattr(module, "__path__", None)
    if paths:
        try:
            return Path(next(iter(paths))).resolve()
        except (OSError, StopIteration):
            return None
    return None

def _purge_dataguard_modules() -> None:
    for key in list(sys.modules):
        if key == "dataguard" or key.startswith("dataguard."):
            del sys.modules[key]























def main() -> int:
    pass


if __name__ == "__main__":
    raise SystemExit(main())
