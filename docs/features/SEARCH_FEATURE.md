# Feature Design: Full-Text / Keyword Search (`--search`)

## Overview

Add a `--search` flag to `cve_reporter.py` that performs keyword or regex searches across CVE descriptions. Researchers need to find CVEs by arbitrary terms — vulnerability classes, technique names, library names — that may not appear in the configured asset inventory.

---

## Scope

**In scope (v1):**
- Search the `description` column of the `cves` table
- Plain keyword (substring) matching by default
- Full regex matching via opt-in flag
- Composable with all existing reporter filters
- Multi-term AND / OR logic

**Out of scope (deferred):**
- Searching NVD reference URLs or the content at those URLs — requires further research on whether reference link storage makes sense before adding search support over it

---

## CLI Design

### Basic usage

```bash
# Single keyword search (case-insensitive substring)
./cve_reporter.py --search "use-after-free"

# Regex search (opt-in)
./cve_reporter.py --search "auth(entication)? bypass" --regex

# Combined with existing filters
./cve_reporter.py --search "use-after-free" --critical --exploits-only
./cve_reporter.py --search "openssl" --severity HIGH,CRITICAL
./cve_reporter.py --search "log4j" --new --hours 72
```

### Multi-term AND (default)

Multiple `--search` flags default to AND — all terms must match the description.

```bash
# CVEs mentioning both "use-after-free" AND "heap"
./cve_reporter.py --search "use-after-free" --search "heap"
```

### Multi-term OR

Pass `--search-mode or` to switch to OR — any term may match.

```bash
# CVEs mentioning "authentication bypass" OR "SQL injection"
./cve_reporter.py --search "authentication bypass" --search "SQL injection" --search-mode or
```

---

## Flag Reference

| Flag | Type | Description |
|---|---|---|
| `--search TERM` | `str` (repeatable) | Search term to match against `description`. Repeatable; multiple terms default to AND. |
| `--regex` | `bool` (flag) | Treat `--search` values as Python regex patterns instead of plain substrings. |
| `--search-mode` | `and` \| `or` | How multiple `--search` terms are combined. Default: `and`. |

---

## Behavior

**Case sensitivity:** All searches are case-insensitive by default. Regex patterns are compiled with `re.IGNORECASE`.

**Interaction with other flags:** `--search` is additive — it narrows the result set returned by any other active filter. Every other existing flag (`--new`, `--updated`, `--unprocessed`, `--critical`, `--severity`, `--asset`, `--exploits-only`, `--pocs-only`, `--relevant`, `--since`) continues to work as before; `--search` applies on top.

**Output format:** Results are rendered using the standard text or JSON report format (controlled by `--format`). No special match highlighting in v1. `--mark-processed` and `--output` work as normal.

**Invalid regex:** If `--regex` is set and a pattern fails to compile, the reporter exits with a clear error message rather than crashing silently.

---

## Implementation Notes

### SQL approach

Each `--search` term translates to a `LIKE` clause on `description` for keyword mode, or a `REGEXP` check for regex mode. Terms are appended to whatever WHERE conditions are already built by the active filters.

**AND mode (default):**
```sql
-- --search "use-after-free" --search "heap"
WHERE ... AND description LIKE '%use-after-free%' AND description LIKE '%heap%'
```

**OR mode:**
```sql
-- --search "authentication bypass" --search "SQL injection" --search-mode or
WHERE ... AND (description LIKE '%authentication bypass%' OR description LIKE '%SQL injection%')
```

**Regex mode:**
SQLite does not natively support `REGEXP`. A custom function must be registered on the connection before executing the query:

```python
import re

def regexp(pattern, value):
    if value is None:
        return False
    return bool(re.search(pattern, value, re.IGNORECASE))

conn.create_function("REGEXP", 2, regexp)
```

Then use:
```sql
WHERE ... AND description REGEXP 'auth(entication)? bypass'
```

### New reporter method

A new `search_cves()` method on `CVEReporter` will accept the search terms, mode, and regex flag, build the parameterized query, and return matching rows — consistent with the existing `get_*` methods.

---

## Future Considerations

- **Reference search:** Once the Reference Link Extraction feature is built and a `references` column is populated, `--search` can be extended to search references with a `--search-field` option (`description`, `references`, `all`).
- **Search result count in dashboard:** Surface a count of CVEs matching common research terms in the `--dashboard` view.
- **Saved searches:** Named, reusable search profiles stored in config (e.g., `"watchlist": ["use-after-free", "authentication bypass"]`).
