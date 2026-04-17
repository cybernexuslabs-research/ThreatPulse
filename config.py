"""
ThreatPulse - Shared configuration
Continuous CVE threat monitoring and reporting tool.
"""

import json
import logging
import os
import shutil
import sys

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database / network constants
# ---------------------------------------------------------------------------

DB_PATH = 'cves.db'
NVD_RECENT_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
REQUEST_TIMEOUT = 30
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'INFO'

# Path to the default assets template shipped alongside this file
_DEFAULT_ASSETS_FILENAME = 'assets.default.json'
_DEFAULT_ASSETS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), _DEFAULT_ASSETS_FILENAME)

# ---------------------------------------------------------------------------
# Asset configuration helpers
# ---------------------------------------------------------------------------

def _find_assets_file():
    """
    Resolve the assets file path using this priority chain:
      1. --assets-file <path> from sys.argv
      2. assets.json in the current working directory
      3. assets.default.json alongside config.py

    Emits a warning and falls through to steps 2-3 if --assets-file is
    present but no path follows it.
    Returns a path string, or None if no file exists at any location.
    """
    for i, arg in enumerate(sys.argv):
        if arg == '--assets-file':
            if i + 1 >= len(sys.argv) or sys.argv[i + 1].startswith('--'):
                logger.warning(
                    "--assets-file flag provided but no path given — "
                    "falling back to default resolution"
                )
                break  # fall through to steps 2 and 3
            return sys.argv[i + 1]

    if os.path.exists('assets.json'):
        return 'assets.json'

    if os.path.exists(_DEFAULT_ASSETS_PATH):
        return _DEFAULT_ASSETS_PATH

    return None


def _fatal(file_path, errors):
    """Print validation errors to stderr and raise SystemExit(1)."""
    msg = f"ERROR: Invalid asset configuration in '{file_path}':\n"
    msg += "\n".join(f"  - {e}" for e in errors)
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def load_assets_config(file_path):
    """
    Read and JSON-parse an external asset configuration file.
    Calls _fatal() on FileNotFoundError or JSONDecodeError.
    On success, calls validate_assets_config() and returns the parsed dict.
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        _fatal(file_path, [f"File not found: '{file_path}'"])
    except json.JSONDecodeError as exc:
        _fatal(file_path, [f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"])

    validate_assets_config(data, file_path)
    return data


def validate_assets_config(data, file_path):
    """
    Enforce schema constraints on the parsed asset config dict.
    Structural errors (missing keys, bad types, out-of-range weights) are
    fatal. Key mismatches between 'assets' and 'category_weights' emit
    warnings — unknown categories fall back to weight 0.5 at runtime.
    """
    errors = []

    if 'assets' not in data:
        errors.append("Missing required key: 'assets'")
    if 'category_weights' not in data:
        errors.append("Missing required key: 'category_weights'")

    # Both keys must be present before we can iterate or cross-check.
    if errors:
        _fatal(file_path, errors)

    # Validate assets structure
    for cat, keywords in data['assets'].items():
        if not isinstance(keywords, list) or len(keywords) == 0:
            errors.append(f"assets.{cat}: must be a non-empty list of strings")
        elif not all(isinstance(k, str) for k in keywords):
            errors.append(f"assets.{cat}: all items must be strings")

    # Validate weights — bool subclasses int in Python, reject it explicitly
    for cat, weight in data['category_weights'].items():
        if isinstance(weight, bool) or not isinstance(weight, (int, float)):
            errors.append(
                f"category_weights.{cat}: must be a number, got {type(weight).__name__}"
            )
        elif not (0.0 <= weight <= 1.0):
            errors.append(
                f"category_weights.{cat}: {weight} is out of range [0.0, 1.0]"
            )

    if errors:
        _fatal(file_path, errors)

    # Cross-check key sets — warnings only, runtime falls back to 0.5
    asset_keys = set(data['assets'].keys())
    weight_keys = set(data['category_weights'].keys())
    missing_weights = asset_keys - weight_keys
    extra_weights = weight_keys - asset_keys

    if missing_weights:
        logger.warning(
            f"[{file_path}] Categories in 'assets' with no weight "
            f"(will use 0.5 fallback): {', '.join(sorted(missing_weights))}"
        )
    if extra_weights:
        logger.warning(
            f"[{file_path}] Categories in 'category_weights' not present in "
            f"'assets' (unused): {', '.join(sorted(extra_weights))}"
        )


def init_assets_file(output_path='assets.json'):
    """
    Copy assets.default.json to output_path.
    Prompts for confirmation if the output file already exists.
    Raises SystemExit when done (success or abort).
    """
    if not os.path.exists(_DEFAULT_ASSETS_PATH):
        print(
            f"ERROR: Default assets template not found: '{_DEFAULT_ASSETS_PATH}'\n"
            f"  '{_DEFAULT_ASSETS_FILENAME}' should ship alongside config.py.",
            file=sys.stderr
        )
        raise SystemExit(1)

    if os.path.exists(output_path):
        try:
            confirm = input(f"'{output_path}' already exists. Overwrite? [y/N] ")
        except EOFError:
            # Non-interactive context (piped stdin, CI environments)
            confirm = 'n'
        if confirm.strip().lower() != 'y':
            print("Aborted.")
            raise SystemExit(0)

    shutil.copy2(_DEFAULT_ASSETS_PATH, output_path)

    print(f"Wrote default asset configuration to '{output_path}'")
    print("Edit the file to customize your asset inventory and weights, then run:")
    print(f"  python cve_collector.py --assets-file {output_path}")
    raise SystemExit(0)


# ---------------------------------------------------------------------------
# Module-level resolution — runs once at import time via _resolve_assets()
# ---------------------------------------------------------------------------

def _resolve_assets():
    """
    Determine MY_ASSETS and CATEGORY_WEIGHTS at import time.

    Resolution order:
      1. --init-assets in sys.argv     → copy assets.default.json to assets.json,
                                         open for editing, exit
      2. --assets-file <path>          → load and validate the specified file
      3. assets.json in cwd            → load and validate if present
      4. assets.default.json (shipped) → load and validate if present
      5. No file found                 → fatal error with instructions

    Wrapped in a function so it can be called in isolation by tests without
    reimporting the module.
    """
    if '--init-assets' in sys.argv:
        init_assets_file()  # always raises SystemExit

    assets_file = _find_assets_file()
    if assets_file:
        loaded = load_assets_config(assets_file)
        kw_count = sum(len(v) for v in loaded['assets'].values())
        logger.info(
            f"Loaded asset configuration from '{assets_file}' "
            f"({len(loaded['assets'])} categories, {kw_count} keywords)"
        )
        return loaded['assets'], loaded['category_weights']

    print(
        f"ERROR: No asset configuration found.\n"
        f"  Run:    python cve_collector.py --init-assets\n"
        f"  Or ensure '{_DEFAULT_ASSETS_FILENAME}' exists alongside config.py.",
        file=sys.stderr
    )
    raise SystemExit(1)


MY_ASSETS, CATEGORY_WEIGHTS = _resolve_assets()
