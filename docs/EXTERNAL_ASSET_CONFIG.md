# Design: External Asset Configuration File

**Status:** Proposed
**Date:** 2026-04-16
**Author:** Jason

---

## Overview

This feature moves `MY_ASSETS` and `CATEGORY_WEIGHTS` out of `config.py` and into an external JSON file loaded at runtime. Users will be able to customize their asset watch list and category weights without editing Python source code, version-control asset configurations independently, and swap profiles per environment using a `--assets-file` CLI flag.

## Motivation

Today, `MY_ASSETS` (a dictionary mapping 11 category names to lists of keyword strings) and `CATEGORY_WEIGHTS` (a dictionary mapping those same categories to float multipliers between 0.0 and 1.0) are hard-coded in `config.py`. Changing them requires editing Python source, which creates several problems:

- Users unfamiliar with Python may introduce syntax errors.
- Asset lists and application code are coupled in the same version-control history.
- Switching between environments (e.g., production vs. lab) requires manual edits or branching.
- There is no validation that the two dictionaries stay in sync (every category in `MY_ASSETS` should have a corresponding weight).

## File Format

**JSON** is the chosen format. It requires no additional dependencies (Python's `json` module is in the standard library) and is widely understood. The trade-off is that JSON does not support comments; a well-structured example file and clear field names mitigate this.

### Schema

The external file contains a single JSON object with two required top-level keys:

```json
{
  "assets": {
    "<category_name>": ["<keyword>", "..."],
    "...": []
  },
  "category_weights": {
    "<category_name>": 0.0
  }
}
```

**Constraints enforced at load time:**

| Rule | Description |
|------|-------------|
| `assets` is required | Must be a non-empty object. |
| Each category value is a list of strings | Every key in `assets` must map to a non-empty array of strings. |
| `category_weights` is required | Must be a non-empty object. |
| Each weight is a float in [0.0, 1.0] | Values outside this range are rejected. |
| Keys must match | Every key in `assets` must have a corresponding key in `category_weights`, and vice versa. Mismatches are fatal. |

### Example File (`assets.json`)

```json
{
  "assets": {
    "web_servers": ["apache", "nginx", "iis", "httpd", "tomcat"],
    "operating_systems": ["windows", "ubuntu", "centos", "rhel", "linux", "macos"],
    "databases": ["mysql", "postgresql", "sql server", "oracle", "mongodb", "mssql"],
    "network_devices": ["cisco", "palo alto", "fortinet", "juniper", "f5"],
    "cloud_services": ["aws", "azure", "google cloud", "office 365", "oci"],
    "applications": ["wordpress", "drupal", "joomla", "exchange", "sharepoint"],
    "pam_tools": ["delinea", "cyberark", "thycotic", "one identity", "okta", "beyond trust", "strongdm", "duo"],
    "security_tools": ["splunk", "sentinel", "crowdstrike", "defender", "firewall"],
    "types": ["buffer overflow", "xss", "csrf", "xsrf", "sql injection", "rce", "directory traversal"],
    "devops": ["ansible", "terraform", "jenkins", "git", "github", "gitlab", "docker", "kubernetes", "openshift"],
    "ai": ["chatgpt", "gpt-4", "bard", "claude", "dall-e", "midjourney", "openclaw"]
  },
  "category_weights": {
    "web_servers": 1.0,
    "databases": 0.9,
    "operating_systems": 0.8,
    "security_tools": 1.0,
    "pam_tools": 1.0,
    "network_devices": 0.7,
    "cloud_services": 0.9,
    "applications": 0.6,
    "devops": 0.7,
    "ai": 0.5,
    "types": 0.8
  }
}
```

## Architecture

### Loading Strategy — Shared via `config.py`

The asset-loading logic lives in `config.py` itself, so both `cve_collector.py` and `cve_reporter.py` (and any future scripts) inherit the behavior automatically through their existing `import config` statements. No changes to the import structure are needed.

```
┌─────────────────────┐     ┌──────────────┐     ┌──────────────────┐
│  cve_collector.py   │────▶│  config.py   │◀────│  cve_reporter.py │
│                     │     │              │     │                  │
│ config.MY_ASSETS    │     │  load_assets │     │ config.MY_ASSETS │
│ config.CAT_WEIGHTS  │     │  ─────────── │     │ config.CAT_WEIGHTS│
└─────────────────────┘     │  1. CLI flag? │     └──────────────────┘
                            │  2. Default   │
                            │     file?     │
                            │  3. Built-in  │
                            │     defaults  │
                            └──────┬───────┘
                                   │
                            ┌──────▼───────┐
                            │ assets.json  │
                            │ (external)   │
                            └──────────────┘
```

### Resolution Order

When `config.py` is imported, it resolves `MY_ASSETS` and `CATEGORY_WEIGHTS` using this priority chain:

1. **CLI flag** — If the process was started with `--assets-file <path>`, load that file.
2. **Default file** — If `assets.json` exists in the working directory, load it.
3. **Built-in defaults** — Use the current hard-coded dictionaries as a fallback.

The CLI flag is captured via `sys.argv` inspection inside `config.py` at import time. This avoids requiring each script to forward the flag manually. The implementation parses only `--assets-file` from `sys.argv` and leaves all other arguments untouched for each script's own `argparse` setup.

```python
# Sketch of the resolution logic in config.py
import sys
import json
import os

def _find_assets_file():
    """Resolve the assets file path from CLI flag or default location."""
    for i, arg in enumerate(sys.argv):
        if arg == '--assets-file' and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    if os.path.exists('assets.json'):
        return 'assets.json'
    return None
```

### Validation

Validation is **fail-fast**: if the external file exists but is malformed or violates the schema constraints, the process exits immediately with a clear error message. This prevents silent misconfiguration from producing incorrect relevance scores or missed CVE matches.

The `validate_assets_config` function checks:

1. The file is valid JSON.
2. Both `assets` and `category_weights` keys are present.
3. `assets` values are all non-empty lists of strings.
4. `category_weights` values are all floats in [0.0, 1.0].
5. The key sets match — no orphaned categories in either direction.

```python
def validate_assets_config(data: dict, file_path: str) -> None:
    """Validate the external asset config. Raises SystemExit on error."""
    errors = []

    if 'assets' not in data:
        errors.append("Missing required key: 'assets'")
    if 'category_weights' not in data:
        errors.append("Missing required key: 'category_weights'")

    if errors:
        _fatal(file_path, errors)

    # Validate assets structure
    for cat, keywords in data['assets'].items():
        if not isinstance(keywords, list) or len(keywords) == 0:
            errors.append(f"assets.{cat}: must be a non-empty list of strings")
        elif not all(isinstance(k, str) for k in keywords):
            errors.append(f"assets.{cat}: all items must be strings")

    # Validate weights
    for cat, weight in data['category_weights'].items():
        if not isinstance(weight, (int, float)):
            errors.append(f"category_weights.{cat}: must be a number")
        elif not (0.0 <= weight <= 1.0):
            errors.append(f"category_weights.{cat}: {weight} is out of range [0.0, 1.0]")

    # Cross-check keys
    asset_keys = set(data['assets'].keys())
    weight_keys = set(data['category_weights'].keys())
    missing_weights = asset_keys - weight_keys
    extra_weights = weight_keys - asset_keys

    if missing_weights:
        errors.append(f"Categories in 'assets' missing from 'category_weights': {missing_weights}")
    if extra_weights:
        errors.append(f"Categories in 'category_weights' missing from 'assets': {extra_weights}")

    if errors:
        _fatal(file_path, errors)


def _fatal(file_path, errors):
    """Print validation errors and exit."""
    msg = f"ERROR: Invalid asset configuration in '{file_path}':\n"
    msg += "\n".join(f"  - {e}" for e in errors)
    print(msg, file=sys.stderr)
    sys.exit(1)
```

### Error Handling Summary

| Scenario | Behavior |
|----------|----------|
| `--assets-file` given, file not found | Exit with `FileNotFoundError` message |
| `--assets-file` given, file is invalid JSON | Exit with parse error and line number |
| File loads but fails validation | Exit with all validation errors listed |
| No `--assets-file`, no `assets.json` in cwd | Silently use built-in defaults |
| No `--assets-file`, `assets.json` exists and is valid | Load it, log which file was used |

## CLI: `--init-assets` Flag

A new `--init-assets` flag writes the built-in defaults to an `assets.json` file in the current directory, then opens the file for editing. This gives users a starting point they can customize.

**Behavior:**

1. If `assets.json` already exists, prompt the user for confirmation before overwriting.
2. Write the built-in `MY_ASSETS` and `CATEGORY_WEIGHTS` as a formatted JSON file.
3. Attempt to open the file in the user's default editor (`$EDITOR`, falling back to `vi` on Unix or `notepad` on Windows).
4. Print the file path and a short help message explaining next steps.

**Implementation location:** This flag is handled in `config.py` via a standalone function that either script can invoke, or it can be detected during the `sys.argv` scan at import time. If `--init-assets` is present, the init runs and the process exits before any collection or reporting begins.

```python
def init_assets_file(output_path='assets.json'):
    """Write built-in defaults to a JSON file and open it for editing."""
    if os.path.exists(output_path):
        confirm = input(f"'{output_path}' already exists. Overwrite? [y/N] ")
        if confirm.lower() != 'y':
            print("Aborted.")
            sys.exit(0)

    data = {
        "assets": _BUILTIN_ASSETS,
        "category_weights": _BUILTIN_WEIGHTS
    }

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"Wrote default asset configuration to '{output_path}'")
    _open_in_editor(output_path)
```

**Usage:**

```bash
# Generate the starter file and open it in your editor
python cve_collector.py --init-assets

# Then run the collector with your customized file
python cve_collector.py --assets-file assets.json
```

## Changes Required

### `config.py`

This is the primary file that changes. The modifications are:

1. **Rename current dictionaries** to `_BUILTIN_ASSETS` and `_BUILTIN_WEIGHTS` (private, prefixed with underscore) so they remain available as fallback defaults.
2. **Add `_find_assets_file()`** — resolves the file path from `--assets-file` or the default location.
3. **Add `load_assets_config()`** — reads and parses the JSON file.
4. **Add `validate_assets_config()`** — enforces the schema constraints described above.
5. **Add `init_assets_file()`** — writes defaults to disk and opens an editor.
6. **Module-level loading** — at the bottom of `config.py`, run the resolution logic and bind `MY_ASSETS` and `CATEGORY_WEIGHTS` to the loaded (or default) values. This preserves the existing API so no consuming code needs to change.

```python
# End of config.py — resolution at import time
_assets_file = _find_assets_file()

if '--init-assets' in sys.argv:
    init_assets_file()
    sys.exit(0)

if _assets_file:
    _loaded = load_assets_config(_assets_file)
    MY_ASSETS = _loaded['assets']
    CATEGORY_WEIGHTS = _loaded['category_weights']
else:
    MY_ASSETS = _BUILTIN_ASSETS
    CATEGORY_WEIGHTS = _BUILTIN_WEIGHTS
```

### `cve_collector.py`

No code changes needed. The existing `config.MY_ASSETS` and `config.CATEGORY_WEIGHTS` references continue to work because `config.py` resolves them at import time.

The only change is that `--assets-file` and `--init-assets` should be documented in the script's `--help` text. Add these to the argparse epilog or description so they appear in help output, even though they are consumed by `config.py` before argparse runs.

### `cve_reporter.py`

Same as above — no code changes needed beyond documenting the new flags in help text.

## Logging

When an external file is loaded, `config.py` logs a message at `INFO` level:

```
2026-04-16 10:00:00 - config - INFO - Loaded asset configuration from 'assets.json' (11 categories, 78 keywords)
```

When falling back to defaults:

```
2026-04-16 10:00:00 - config - INFO - Using built-in asset defaults (no external assets file found)
```

## Backward Compatibility

This change is fully backward-compatible:

- If no `--assets-file` flag is provided and no `assets.json` exists in the working directory, the behavior is identical to today.
- The `config.MY_ASSETS` and `config.CATEGORY_WEIGHTS` names remain the same, so all consuming code works without modification.
- The built-in defaults are preserved as `_BUILTIN_ASSETS` and `_BUILTIN_WEIGHTS` for fallback and for `--init-assets`.

## Testing

| Test Case | Description |
|-----------|-------------|
| No external file | Verify `MY_ASSETS` and `CATEGORY_WEIGHTS` equal the built-in defaults. |
| Valid `assets.json` in cwd | Verify values are loaded from the file. |
| `--assets-file custom.json` | Verify the specified file is loaded. |
| `--assets-file missing.json` | Verify the process exits with a `FileNotFoundError` message. |
| Invalid JSON syntax | Verify the process exits with a parse error. |
| Missing `assets` key | Verify validation catches and reports the error. |
| Weight out of range | Verify validation catches `1.5` or `-0.1`. |
| Mismatched keys | Verify validation catches a category present in `assets` but absent from `category_weights`. |
| Empty keyword list | Verify validation rejects `"web_servers": []`. |
| `--init-assets` | Verify file is written with correct content and structure. |
| `--init-assets` with existing file | Verify overwrite prompt works correctly. |

## Future Considerations

- **Asset Profiles**: The JSON schema could be extended with a top-level `profiles` key containing named configurations (e.g., "production", "lab"), selectable via `--profile`. This is a natural follow-on tracked in `FEATURE_IDEAS.md` under "Asset Grouping / Profiles."
- **YAML support**: If users request comment support, a future version could accept `.yaml` files by checking the extension and importing `pyyaml` conditionally.
- **JSON Schema file**: A formal JSON Schema (`.schema.json`) could be published alongside the tool for editor-based validation and autocompletion.
