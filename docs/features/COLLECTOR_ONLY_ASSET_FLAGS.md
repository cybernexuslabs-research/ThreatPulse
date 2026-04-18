# Feature Design: Scope `--assets-file` and `--init-assets` to `cve_collector.py`

## Problem

`--assets-file` and `--init-assets` are collector-specific CLI flags — they control which asset
inventory the collector uses when scoring CVE relevance. The reporter never reads `MY_ASSETS` or
`CATEGORY_WEIGHTS` at runtime; all asset-related data it displays was pre-computed by the collector
and stored in the database.

Despite this, both flags currently work when passed to `cve_reporter.py`. The reason is
architectural: `config.py` scans `sys.argv` for those flags unconditionally at **import time**,
inside `_resolve_assets()` which is called at module level (line 220). Every script that does
`import config` — including the reporter — triggers this scan before any of its own code runs.

This creates two issues:

1. **False affordance** — the reporter silently accepts flags that have no effect on its output,
   which misleads users who might pass `--assets-file` expecting it to influence report results.
2. **Tight coupling** — collector-specific CLI concerns bleed into every module that imports config.

---

## Scope

**In scope:**
- Gate `--init-assets` processing on the calling script being `cve_collector.py`
- Gate `--assets-file` `sys.argv` scanning on the calling script being `cve_collector.py`
- Non-collector callers still load assets from `assets.json` / `assets.default.json` via normal
  file resolution (no behavior change for the common case)
- After the change, passing `--assets-file` or `--init-assets` to `cve_reporter.py` produces an
  argparse "unrecognized arguments" error, which is the correct and expected behavior

**Out of scope:**
- Adding `--assets-file` / `--init-assets` to reporter's argparse — the reporter has no use for them
- Changing how the collector processes these flags — collector behavior is unchanged
- Lazy-loading `MY_ASSETS` / `CATEGORY_WEIGHTS` — the reporter is fine loading the defaults at
  import time; the loaded values are simply never referenced

---

## Current Behavior

```
cve_collector.py --assets-file /etc/tp/assets.json   → works correctly
cve_collector.py --init-assets                        → works correctly

cve_reporter.py --assets-file /etc/tp/assets.json    → silently accepted, has no effect
cve_reporter.py --init-assets                         → copies assets.default.json and exits
                                                         (side-effect from within the reporter)
```

## Target Behavior

```
cve_collector.py --assets-file /etc/tp/assets.json   → works correctly (unchanged)
cve_collector.py --init-assets                        → works correctly (unchanged)

cve_reporter.py --assets-file /etc/tp/assets.json    → error: unrecognized arguments: --assets-file
cve_reporter.py --init-assets                         → error: unrecognized arguments: --init-assets
```

---

## Implementation

All changes are in `config.py`. Zero changes to `cve_reporter.py` or `cve_collector.py`.

### 1. Add a caller-identity constant

```python
# Near the top of config.py, after the existing constants
_ASSET_FLAG_CALLERS = {'cve_collector.py'}
```

A set rather than a single string makes it straightforward to extend to additional scripts in the
future (e.g. a future `cve_admin.py`) without modifying the logic.

### 2. Add a `check_argv` parameter to `_find_assets_file()`

```python
def _find_assets_file(check_argv=True):
    """
    Resolve the assets file path using this priority chain:
      1. --assets-file <path> from sys.argv  (only when check_argv=True)
      2. assets.json in the current working directory
      3. assets.default.json alongside config.py
    ...
    """
    if check_argv:
        for i, arg in enumerate(sys.argv):
            if arg == '--assets-file':
                if i + 1 >= len(sys.argv) or sys.argv[i + 1].startswith('--'):
                    logger.warning(
                        "--assets-file flag provided but no path given — "
                        "falling back to default resolution"
                    )
                    break
                return sys.argv[i + 1]

    if os.path.exists('assets.json'):
        return 'assets.json'

    if os.path.exists(_DEFAULT_ASSETS_PATH):
        return _DEFAULT_ASSETS_PATH

    return None
```

The only change to this function is wrapping the `sys.argv` loop in `if check_argv:`. Steps 2 and
3 (file-based resolution) are unaffected and always run.

### 3. Gate flag processing in `_resolve_assets()`

```python
def _resolve_assets():
    _caller = os.path.basename(sys.argv[0])
    _process_flags = _caller in _ASSET_FLAG_CALLERS

    if _process_flags and '--init-assets' in sys.argv:
        init_assets_file()  # always raises SystemExit

    assets_file = _find_assets_file(check_argv=_process_flags)

    if assets_file:
        loaded = load_assets_config(assets_file)
        kw_count = sum(len(v) for v in loaded['assets'].values())
        logger.info(
            f"Loaded asset configuration from '{assets_file}' "
            f"({len(loaded['assets'])} categories, {kw_count} keywords)"
        )
        return loaded['assets'], loaded['category_weights']

    if _process_flags:
        # Collector requires a valid assets file — fatal if none found
        print(
            f"ERROR: No asset configuration found.\n"
            f"  Run:    python cve_collector.py --init-assets\n"
            f"  Or ensure '{_DEFAULT_ASSETS_FILENAME}' exists alongside config.py.",
            file=sys.stderr
        )
        raise SystemExit(1)

    # Non-collector callers (reporter, setup, etc.) — assets are optional
    # MY_ASSETS and CATEGORY_WEIGHTS will be empty dicts; this is safe because
    # only the collector uses them.
    logger.debug("No asset configuration found; MY_ASSETS and CATEGORY_WEIGHTS will be empty.")
    return {}, {}
```

Two changes from the current implementation:

- `--init-assets` is checked only when `_process_flags` is True
- `_find_assets_file()` is called with `check_argv=_process_flags`
- The fatal "no asset configuration found" branch is also guarded by `_process_flags` — if the
  reporter is run in an environment where neither `assets.json` nor `assets.default.json` exists,
  it should not crash (the reporter doesn't need them)

---

## Why the Reporter Gets "Unrecognized Arguments" After This Change

Before this change, `config.py` strips `--assets-file <path>` from `sys.argv` during its import.
By the time `argparse.parse_args()` runs in `main()`, those arguments are gone.

After this change, `config.py` no longer touches `sys.argv` for non-collector callers. The flags
remain in `sys.argv`, argparse sees them as unknown arguments, and raises:

```
error: unrecognized arguments: --assets-file /etc/tp/assets.json
```

This is the correct behavior — no additional argparse changes are needed in `cve_reporter.py`.

---

## Edge Cases

| Scenario | Current behavior | Behavior after change |
|---|---|---|
| `cve_reporter.py --assets-file /path` | Silently accepted, no effect | argparse error: unrecognized argument |
| `cve_reporter.py --init-assets` | Copies default file and exits | argparse error: unrecognized argument |
| `cve_collector.py --assets-file /path` | Works correctly | Unchanged |
| `cve_collector.py --init-assets` | Works correctly | Unchanged |
| Reporter run with no `assets.json` present | Fatally exits (can't find assets) | Logs debug message, returns `{}` — reporter continues normally |
| `setup.py` imports config (no assets file) | Fatally exits | Returns `{}`, setup continues normally |
| Script other than collector or reporter imports config | Same as reporter above | Same as reporter above |

---

## Testing Checklist

- [ ] `cve_collector.py --init-assets` copies `assets.default.json` → `assets.json` and exits
- [ ] `cve_collector.py --assets-file /path/to/custom.json` loads from the specified file
- [ ] `cve_reporter.py --init-assets` exits with argparse "unrecognized arguments" error
- [ ] `cve_reporter.py --assets-file /path` exits with argparse "unrecognized arguments" error
- [ ] `cve_reporter.py --dashboard` works normally with `assets.json` present
- [ ] `cve_reporter.py --dashboard` works normally with no `assets.json` present
- [ ] `cve_collector.py` without any asset flags still loads from `assets.json` / `assets.default.json`
- [ ] `setup.py` runs to completion in an environment with no `assets.json`

---

## Files Changed

| File | Change |
|---|---|
| `config.py` | Add `_ASSET_FLAG_CALLERS` constant; add `check_argv` param to `_find_assets_file()`; add `_process_flags` guard to `_resolve_assets()` |
| `cve_reporter.py` | None |
| `cve_collector.py` | None |
