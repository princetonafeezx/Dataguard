# DataGuard

DataGuard is a standard-library-only Python package for cleaning and validating messy real-world data.

It ships with:

- `sanitize` for invisible character cleanup
- `contacts` for email and phone extraction
- `audit` for password strength analysis
- `logs` for server log parsing
- `csv` for CSV repair and JSON conversion
- `html` for HTML/script sanitization
- `auto` for file-type detection and routing
- `batch` for directory-wide processing

Run it with:

```bash
python -m dataguard --help
```

## `dg-clean` (avoid wrong `dataguard` installs)

If another PyPI package named `dataguard` is on your environment, `python -m dataguard` may load that install instead of this project. Use the **`dg-clean`** entry point (defined in `pyproject.toml`) so this tree’s package is loaded:

```bash
dg-clean --help
```

You can also run `dg_clean_entry.py` in this directory the same way. See `dg_clean_entry.py` for details.

## Configuration (`.dataguardrc`)

Optional JSON config file **`.dataguardrc`** in the **current working directory** is merged with built-in defaults. Unknown keys are ignored with a warning; invalid values produce a clear error.

Inspect or update from the CLI:

```bash
python -m dataguard config
python -m dataguard config --set verbosity=1 pipe_format=json
```

Common keys include `color_enabled`, `strict_mode`, `pipe_format`, `report_format`, `min_confidence_threshold` (contacts), `password_min_length`, and `log_top_n`. Valid keys and constraints are described in **`schema/config.schema.json`**.

## JSON Schema (`schema/`)

Machine-readable descriptions of config, module result shapes, batch summaries, and related payloads live under **`schema/`**. Start from **`schema/manifest.json`** for a list of documents and their `$id` URLs.

Only the **`*.json` files in `schema/`** are shipped as package data (see `pyproject.toml`); they are independent of local tooling directories such as **`.claude/`**, which is not part of the schema set or the published package layout.
