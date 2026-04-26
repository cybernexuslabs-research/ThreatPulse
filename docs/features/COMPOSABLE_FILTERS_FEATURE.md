# Feature Design: Composable Flag Filtering

## Overview

Today, `cve_reporter.py` dispatches report modes through a single `if/elif` chain. When multiple
primary flags are passed together — for example `--category types --critical --new` — only the first
matching branch runs; every other flag is silently ignored. The analyst gets `--new` results with no
severity or category filtering applied, which is not what they asked for.

This feature restructures the dispatch logic so that flags compose with AND logic. Running
`--category types --critical --new` should return CVEs that are **all three** of: seen in the last N
hours, rated CRITICAL, and belonging to the `types` category.

---

## Scope

**In scope (v1):**
- Treat the following as **primary modes** — they select the base result set independently:
  `--new`, `--updated`, `--unprocessed`, `--relevant`, `--since`, `--dashboard`, `--cve`
- Treat the following as **composable filters** — they narrow any base result set and can be
  combined freely with each other and with any primary mode:
  `--critical`, `--severity`, `--category`, `--asset`, `--exploits-only`, `--pocs-only`
- When no primary mode is given, composable filters run against the full CVE table (current
  `--critical` / `--severity` / `--category` / `--asset` standalone behavior is preserved)
- Report title reflects all active flags so saved output is self-describing
- All existing flags (`--with-exploits`, `--with-pocs`, `--format`, `--output`, `--mark-processed`,
  `--hours`) remain unchanged

**Out of scope (deferred):**
- Combining two primary modes (e.g., `--new --updated`) — behavior would be ambiguous; one will be
  chosen as the winner or argparse mutual exclusion will be used to reject the combination
- SQL-level composition for `--category` + `--asset` (AND within a single query) — handled by the
  existing mutual exclusion on those two flags; no change here

---

## CLI Design

### New valid combinations

```bash
# New critical CVEs in the "types" category
python cve_reporter.py --category types --critical --new

# Critical CVEs seen in the last 48 hours
python cve_reporter.py --critical --new --hours 48

# New CVEs in the databases category with a known exploit
python cve_reporter.py --new --category databases --exploits-only

# Unprocessed CVEs that are CRITICAL or HIGH
python cve_reporter.py --unprocessed --severity CRITICAL,HIGH

# CVEs published since a date, filtered to critical severity, in a category
python cve_reporter.py --since 2026-01-01 --critical --category network_devices

# Standalone filters (no primary mode) — current behavior preserved
python cve_reporter.py --critical
python cve_reporter.py --category web_servers
python cve_reporter.py --category web_servers --with-exploits
```

### Flag classification

| Flag | Role | Notes |
|---|---|---|
| `--new` | Primary mode | Base set: `first_seen > now - N hours` |
| `--updated` | Primary mode | Base set: `last_updated_date > now - N hours` |
| `--unprocessed` | Primary mode | Base set: `processed = 0` |
| `--relevant` | Primary mode | Base set: `affects_infrastructure = 1` |
| `--since DATE` | Primary mode | Base set: `published_date >= DATE` |
| `--dashboard` | Primary mode | Aggregate statistics; filters silently ignored |
| `--cve CVE-ID` | Primary mode | Single CVE lookup; filters silently ignored |
| `--critical` | Composable filter | Adds `base_severity = 'CRITICAL'` |
| `--severity LIST` | Composable filter | Adds `base_severity IN (...)` |
| `--category NAME` | Composable filter | Adds `affected_categories LIKE '%"NAME"%'` |
| `--asset KEYWORD` | Composable filter | Adds `affected_assets LIKE '%"KEYWORD"%'` |
| `--exploits-only` | Composable filter | Adds `has_known_exploit = 1` |
| `--pocs-only` | Composable filter | Adds `has_poc = 1` |
| `--with-exploits` | Post-query modifier | Unchanged — passed into query method where supported |
| `--with-pocs` | Post-query modifier | Unchanged — Python-level list filter after fetch |

`--critical` and `--severity` remain mutually exclusive with each other at the argparse level (one
sets the severity filter; both at once is ambiguous). `--category` and `--asset` remain mutually
exclusive with each other.

---

## Implementation

### Approach: single composable query builder

Replace the `if/elif` dispatch block with a two-phase approach:

1. **Base query phase** — detect the primary mode (if any) and build the initial WHERE clause
2. **Filter phase** — append AND conditions for each active composable filter

This is implemented as a new `build_filtered_query()` helper that returns a `(sql, params)` tuple,
which `main()` executes directly. The individual `get_*` reporter methods are preserved for backward
compatibility (they can call the new helper internally, or remain as standalone convenience methods).

### 1. New query builder method (`CVEReporter`, `cve_reporter.py`)

```python
def build_filtered_query(
    self,
    hours: int = 24,
    new: bool = False,
    updated: bool = False,
    unprocessed: bool = False,
    relevant: bool = False,
    since: str | None = None,
    critical: bool = False,
    severities: list[str] | None = None,
    category: str | None = None,
    asset: str | None = None,
    exploits_only: bool = False,
    pocs_only: bool = False,
) -> tuple[str, list]:
    """Build a composable SELECT query from any combination of active flags.

    Primary modes (new, updated, unprocessed, relevant, since) determine the base
    WHERE clause. Composable filters (critical, severities, category, asset,
    exploits_only, pocs_only) are appended as AND conditions on top of any base.

    Returns a (sql, params) tuple ready to pass to cursor.execute().
    """
    conditions: list[str] = []
    params: list = []

    # --- Primary mode ---
    if new:
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        conditions.append("first_seen > ?")
        params.append(cutoff)
    elif updated:
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        conditions.append("last_updated_date > ?")
        params.append(cutoff)
    elif unprocessed:
        conditions.append("processed = 0")
    elif relevant:
        conditions.append("affects_infrastructure = 1")
    elif since:
        conditions.append("published_date >= ?")
        params.append(since)

    # --- Composable filters ---
    if critical:
        conditions.append("base_severity = 'CRITICAL'")
    elif severities:
        placeholders = ", ".join("?" * len(severities))
        conditions.append(f"base_severity IN ({placeholders})")
        params.extend(severities)

    if category:
        conditions.append("affected_categories LIKE ?")
        params.append(f'%"{category}"%')

    if asset:
        conditions.append("affected_assets LIKE ?")
        params.append(f'%"{asset}"%')

    if exploits_only:
        conditions.append("has_known_exploit = 1")

    if pocs_only:
        conditions.append("has_poc = 1")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT * FROM cves {where} ORDER BY base_score DESC, published_date DESC"
    return sql, params
```

### 2. Updated dispatch logic (`main()`, `cve_reporter.py`)

Replace the existing `if/elif` chain with:

```python
# Detect primary mode (mutually exclusive — first one found wins)
is_new        = bool(args.new)
is_updated    = bool(args.updated)
is_unprocessed = bool(args.unprocessed)
is_relevant   = bool(args.relevant)
is_since      = bool(args.since)

# Detect composable filters
is_critical    = bool(args.critical)
severities     = ([s.strip().upper() for s in args.severity.split(',')]
                  if args.severity else None)
category       = _validate_category(args.category) if args.category else None
asset          = args.asset or None
exploits_only  = bool(args.exploits_only)
pocs_only_flag = bool(args.pocs_only)

# Dashboard and single-CVE lookups are unaffected
if args.dashboard:
    reporter.print_dashboard()
    return
if args.cve:
    reporter.print_cve_detail(args.cve)
    return

sql, params = reporter.build_filtered_query(
    hours=args.hours,
    new=is_new,
    updated=is_updated,
    unprocessed=is_unprocessed,
    relevant=is_relevant,
    since=args.since,
    critical=is_critical,
    severities=severities,
    category=category,
    asset=asset,
    exploits_only=exploits_only,
    pocs_only=pocs_only_flag,
)

# Require at least one flag so bare invocation still prints help
no_flags = not any([is_new, is_updated, is_unprocessed, is_relevant, is_since,
                    is_critical, severities, category, asset, exploits_only,
                    pocs_only_flag])
if no_flags:
    parser.print_help()
    return

cursor = reporter.conn.cursor()
cursor.execute(sql, params)
cves = cursor.fetchall()
```

### 3. Dynamic report title

Build the title from all active flags so the report header is self-describing:

```python
title_parts = []
if is_new:
    title_parts.append(f"New (Last {args.hours}h)")
elif is_updated:
    title_parts.append(f"Updated (Last {args.hours}h)")
elif is_unprocessed:
    title_parts.append("Unprocessed")
elif is_relevant:
    title_parts.append("Relevant")
elif is_since:
    title_parts.append(f"Since {args.since}")

if is_critical:
    title_parts.append("Critical")
elif severities:
    title_parts.append(f"Severity: {', '.join(severities)}")

if category:
    title_parts.append(f"Category: {category}")
if asset:
    title_parts.append(f"Asset: {asset}")
if exploits_only:
    title_parts.append("Exploits Only")
if pocs_only_flag:
    title_parts.append("POCs Only")

title = "CVEs — " + " | ".join(title_parts) if title_parts else "All CVEs"
```

Example titles produced:

| Command | Title |
|---|---|
| `--new --critical --category types` | `CVEs — New (Last 24h) \| Critical \| Category: types` |
| `--critical` | `CVEs — Critical` |
| `--category databases --with-exploits` | `CVEs — Category: databases` |
| `--unprocessed --severity HIGH,MEDIUM` | `CVEs — Unprocessed \| Severity: HIGH, MEDIUM` |

### 4. Remove `--with-pocs` post-query filter duplication

`--with-pocs` is currently applied as a Python-level list filter after the `if/elif` block. With this
change, pass it directly into `build_filtered_query()` as `pocs_only` so the condition is in SQL.
Remove the post-query filter block. Behavior is identical; execution is cleaner.

---

## Edge Cases

| Scenario | Behavior |
|---|---|
| No flags at all | `parser.print_help()`, exit 0 — unchanged |
| Only a primary mode (`--new`) | Returns new CVEs with no additional filtering — unchanged |
| Only a composable filter (`--critical`) | No primary mode condition; queries the full table for CRITICAL CVEs — unchanged |
| `--new --critical --category types` | AND of all three conditions in SQL |
| `--critical --severity HIGH` | Argparse mutual-exclusion error (existing constraint, unchanged) |
| `--category X --asset Y` | Argparse mutual-exclusion error (existing constraint, unchanged) |
| `--new --updated` | `--new` wins silently (first evaluated); document in help text |
| `--dashboard` with other flags | Filters silently ignored; dashboard runs as-is |
| `--cve CVE-2026-XXXX` with other flags | Filters silently ignored; single-CVE detail runs as-is |
| Composable filter produces zero results | "No CVEs found." printed, exit 0 |
| Category invalid with combined flags | `_validate_category()` exits 1 with warning before query runs |

---

## Testing Checklist

- [ ] `--category types --critical --new` returns only CVEs that satisfy all three conditions
- [ ] `--critical --new --hours 48` returns new-in-48h CVEs with `base_severity = 'CRITICAL'`
- [ ] `--new --category databases --exploits-only` returns new CVEs in databases with a known exploit
- [ ] `--unprocessed --severity CRITICAL,HIGH` returns unprocessed CVEs at those severities
- [ ] `--since 2026-01-01 --critical --category network_devices` intersects all three conditions
- [ ] `--critical` alone (no primary mode) still returns all CRITICAL CVEs — backward compat
- [ ] `--category web_servers` alone still returns category CVEs — backward compat
- [ ] `--new` alone still returns new CVEs — backward compat
- [ ] `--critical --severity HIGH` produces an argparse error — constraint unchanged
- [ ] `--category X --asset Y` produces an argparse error — constraint unchanged
- [ ] No flags prints help and exits 0 — unchanged
- [ ] Report title reflects all active flags
- [ ] `--format json` and `--output` work with any flag combination
- [ ] `--mark-processed` marks results for any flag combination

---

## Files Changed

| File | Change |
|---|---|
| `cve_reporter.py` | Add `build_filtered_query()` method; replace `if/elif` dispatch with two-phase approach; add dynamic title builder; remove redundant `--with-pocs` post-query filter |

---

## Future Considerations

- **`--new --updated` disambiguation:** Consider an argparse `mutually_exclusive_group` for primary
  modes to make the conflict explicit rather than silently picking a winner.
- **`--category` + `--asset` AND combination:** With the query builder in place, supporting both in
  a single query becomes a one-line change in `build_filtered_query()`. Remove the mutual exclusion
  and add an AND condition when both are present.
- **Multi-value `--category`:** `--category web_servers,databases` would OR two LIKE conditions. The
  query builder can be extended to accept a list rather than a scalar.
