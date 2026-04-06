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

def _ensure_local_dataguard() -> None:
    repo_root = Path(__file__).resolve().parent
    init_path = repo_root / "__init__.py"
    if not init_path.is_file():
        raise ImportError(f"Expected DataGuard package at {repo_root} (missing __init__.py).")

    existing = sys.modules.get("dataguard")
    if existing is not None:
        loaded_root = _loaded_dataguard_package_root(existing)
        if loaded_root is not None and loaded_root == repo_root:
            return

    _purge_dataguard_modules()

    spec = importlib.util.spec_from_file_location(
        "dataguard",
        init_path,
        submodule_search_locations=[str(repo_root)],
    )
    if spec is None or spec.loader is None:
        raise ImportError("Could not create a loader for the local dataguard package.")

    package = importlib.util.module_from_spec(spec)
    sys.modules["dataguard"] = package
    spec.loader.exec_module(package)





















def main() -> int:
    pass


if __name__ == "__main__":
    raise SystemExit(main())
