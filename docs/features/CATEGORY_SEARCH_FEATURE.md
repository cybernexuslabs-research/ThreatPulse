# Feature Design: CVE Search by Asset Category (`--category`)

## Overview

Add a `--category <name>` flag to `cve_reporter.py` that returns all CVEs matching a configured
asset category — such as `web_servers`, `databases`, or `pam_tools` — rather than requiring the
analyst to specify a single keyword.

Today `--asset nginx` works, but an analyst who wants to see everything relevant to their web server
estate has to run multiple queries (one per keyword). `--category web_servers` collapses that into a
single command that queries the `affected_categories` field already stored in the database by the
collector.

All data is served from the local SQLite database. No live external requests are made.

---

## Scope

**In scope (v1):**
- Filter CVEs by a single category name via `--category <name>`
- Composable with `--with-exploits`, `--with-pocs`, `--format json`, `--output <path>`, and
  `--mark-processed`
- Case-insensitive category name matching (e.g., `Web_Servers` → `web_servers`)
- Clean "no results" message when the category name matches no CVEs
- Clear "unknown category" warning when the supplied name is not found in the configured asset
  inventory, with a list of valid category names printed to help the user

**Out of scope (deferred):**
- Multi-category queries (e.g., `--category web_servers,databases`) — use separate invocations for now
- Combining `--category` with `--asset` in a single query — behavior would be ambiguous; defer to v2
- Dynamic category discovery from the database — valid categories are read from the live asset config
  (`MY_ASSETS` in `config.py`) to keep the source of truth consistent

---

## CLI Design

### Basic usage

```bash
# All CVEs matching the web_servers category
python cve_reporter.py --category web_servers

# Category CVEs with known exploits only
python cve_reporter.py --category databases --with-exploits

# Category CVEs that also have a POC
python cve_reporter.py --category pam_tools --with-pocs

# JSON output
python cve_reporter.py --category network_devices --format json

# Save to file
python cve_reporter.py --category cloud_services --output cloud_cves.txt

# Mark results as processed after display
python cve_reporter.py --category operating_systems --mark-processed
```

### Flag reference

| Flag | Type | Description |
|---|---|---|
| `--category NAME` | `str` | Asset category to filter by. Case-insensitive. Must match a top-level key in the asset configuration. |

`--category` is mutually exclusive with `--asset` and all other primary report modes (`--new`,
`--updated`, `--unprocessed`, `--critical`, `--severity`, `--exploits-only`, `--pocs-only`,
`--relevant`, `--since`, `--dashboard`, `--cve`). It shares `--with-exploits`, `--with-pocs`,
`--hours`, `--format`, `--output`, and `--mark-processed`.

### Valid category names (from current asset config)

| Category | Example keywords |
|---|---|
| `web_servers` | apache, nginx, iis, httpd, tomcat |
| `operating_systems` | windows, ubuntu, centos, rhel, linux, macos |
| `databases` | mysql, postgresql, sql server, oracle, mongodb, mssql |
| `network_devices` | cisco, palo alto, fortinet, juniper, f5 |
| `cloud_services` | aws, azure, google cloud, office 365, oci |
| `applications` | wordpress, drupal, joomla, exchange, sharepoint |
| `pam_tools` | delinea, cyberark, thycotic, one identity, okta, beyond trust, strongdm, duo |
| `security_tools` | splunk, sentinel, crowdstrike, defender, firewall |
| `types` | buffer overflow, xss, csrf, sql injection, rce, directory traversal |
| `devops` | ansible, terraform, jenkins, git, github, gitlab, docker, kubernetes, openshift |
| `ai` | chatgpt, gpt-4, bard, claude, dall-e, midjourney, copilot |

---

## Terminal Output Design

Output follows the same header/separator style as `--asset` and all other report modes. The report
title identifies the category so the output is self-describing when saved to a file.

### Example — text output

```
======================================================================
CVEs Affecting Category: web_servers
======================================================================
Generated: 2026-04-26 09:45:00
Total CVEs: 3
======================================================================

CVE: CVE-2026-11234 🚨 EXPLOIT AVAILABLE
Severity: CRITICAL (Score: 9.8)
Published: 2026-01-15
Affects Assets: nginx
Categories: web_servers
Relevance Score: 9.8
⚠️  KNOWN EXPLOIT - IMMEDIATE PATCHING REQUIRED
Description: A heap-based buffer overflow in nginx HTTP/2 ...

----------------------------------------------------------------------
CVE: CVE-2026-10987
Severity: HIGH (Score: 7.5)
Published: 2026-02-03
Affects Assets: apache, httpd
Categories: web_servers
Relevance Score: 7.5
Description: Apache HTTP Server path traversal vulnerability ...

----------------------------------------------------------------------
```

### Unknown category warning

```
Warning: 'webservers' is not a recognized asset category.
Valid categories: web_servers, operating_systems, databases, network_devices,
  cloud_services, applications, pam_tools, security_tools, types, devops, ai
```

The warning is printed to stderr. The process exits with code `1`.

### No results message

```
No CVEs found for category: pam_tools
```

Exits with code `0` — no results is a valid, non-error outcome.

---

## Implementation

### 1. New reporter method (`CVEReporter`, `cve_reporter.py`)

Add after `get_cves_by_asset()`:

```python
def get_cves_by_category(self, category: str, with_exploits: bool = False) -> List[sqlite3.Row]:
    """Get CVEs matching a specific asset category."""
    cursor = self.conn.cursor()
    query = """
        SELECT * FROM cves
        WHERE affected_categories LIKE ?
    """
    params = [f'%"{category}"%']

    if with_exploits:
        query += " AND has_known_exploit = 1"

    query += " ORDER BY relevance_score DESC, base_score DESC"

    cursor.execute(query, params)
    return cursor.fetchall()
```

The LIKE pattern `%"category_name"%` mirrors the approach already used by `get_cves_by_asset()` for
`affected_assets`. Both fields are stored as JSON arrays (e.g., `["web_servers"]`), so quoting the
search term ensures partial-name false matches (e.g., `ai` matching `pam_tools`) are avoided.

### 2. Argument parser (`cve_reporter.py`)

Move `--asset` into a `mutually_exclusive_group` and add `--category` to the same group. This is
required so that `--asset nginx --category web_servers` produces an argparse error rather than
silently dropping `--category`:

```python
asset_group = parser.add_mutually_exclusive_group()
asset_group.add_argument('--asset', type=str,
                        help='Filter by asset name')
asset_group.add_argument('--category', type=str,
                        help='Filter by asset category (e.g. web_servers, databases)')
```

Also update the `--with-exploits` help text from `'use with --asset'` to
`'use with --asset or --category'`.

### 3. Category validation helper (`cve_reporter.py` — module level, above `main()`)

Defined at module level (not nested inside `main()`), consistent with the existing `normalize_cve_id()`
pattern and independently testable. `config` is already imported at the top of the file — no
re-import inside the function body.

```python
def _validate_category(category: str) -> str:
    """Normalize and validate a category name against the loaded asset config.

    Returns the normalized (lowercase) category name on success.
    Prints a warning to stderr and exits with code 1 if unrecognized or if
    no asset configuration is loaded.
    """
    normalized = category.strip().lower()
    valid = sorted(config.MY_ASSETS.keys())
    if not valid:
        print(
            "Warning: No asset categories are configured.\n"
            "Run: python cve_collector.py --init-assets",
            file=sys.stderr
        )
        sys.exit(1)
    if normalized not in valid:
        print(
            f"Warning: '{category}' is not a recognized asset category.\n"
            f"Valid categories: {', '.join(valid)}",
            file=sys.stderr
        )
        sys.exit(1)
    return normalized
```

### 4. Dispatch logic (`main()`, `cve_reporter.py`)

Add a new `elif` branch after the `args.asset` block. Include a "no results" guard inside the branch
— do **not** add it to `generate_report()`, which would silently change behavior for every other mode:

```python
elif args.category:
    category = _validate_category(args.category)
    cves = reporter.get_cves_by_category(category, args.with_exploits)
    if not cves:
        print(f"No CVEs found for category: {category}")
        sys.exit(0)  # safe — context manager closes DB connection on SystemExit
    title = f"CVEs Affecting Category: {category}"
    if args.with_exploits:
        title += " (With Known Exploits)"
```

The `--with-pocs` filter and `--mark-processed` logic already runs after the dispatch block and
requires no changes — both will apply automatically to category results.

> **Note — silent mutual exclusion with other primary modes:** Combining `--category` with another
> primary flag (e.g., `--new --category web_servers`) will silently prefer `--new` and ignore
> `--category`, consistent with how the existing `elif` chain handles all other mode conflicts.
> Only `--category` + `--asset` is enforced at the argparse level via `mutually_exclusive_group`
> (see Step 2 of the argument parser changes). The silent behavior for all other combinations is
> acceptable for v1.

### 5. Help text / epilog update

Add two example lines to the `epilog` in `argparse.ArgumentParser`:

```
  %(prog)s --category web_servers              # All CVEs for a category
  %(prog)s --category databases --with-exploits # Database CVEs with exploits
```

---

## Edge Cases

| Scenario | Behavior |
|---|---|
| Category name in wrong case (`Web_Servers`) | Normalized to lowercase before query and validation |
| Unrecognized category name (`webservers`) | Warning printed to stderr, exit code 1, valid names listed |
| Valid category with zero matching CVEs | "No CVEs found for category: X" printed, exit code 0 |
| `--category` combined with `--asset` | argparse mutual-exclusion error |
| `--category` combined with `--with-exploits` | Supported — filters results to exploit-confirmed CVEs only |
| `--category` combined with `--with-pocs` | Supported — post-query filter applies as with all other modes |
| `--category` combined with `--format json` | Supported — same JSON envelope as other report modes |
| `--category` combined with `--mark-processed` | Supported — marks all returned CVEs as processed |
| `MY_ASSETS` is empty (no assets.json found) | Validation sees no valid categories; any input triggers warning + exit 1 |
| Category stored in DB with different casing than config | Collector is responsible for consistent casing at ingest time; reporter trusts stored values |

---

## Testing Checklist

- [ ] `--category web_servers` returns CVEs whose `affected_categories` contains `"web_servers"`
- [ ] `--category Web_Servers` (mixed case) returns the same results as `--category web_servers`
- [ ] `--category webservers` (unrecognized) prints warning to stderr listing valid names, exits 1
- [ ] `--category databases --with-exploits` returns only CVEs with `has_known_exploit = 1`
- [ ] `--category pam_tools --with-pocs` returns only CVEs with `has_poc = 1`
- [ ] `--category ai --format json` produces valid JSON with correct `title` and `cves` array
- [ ] `--category cloud_services --output /tmp/out.txt` writes report to file, prints nothing to stdout
- [ ] `--category operating_systems --mark-processed` marks all returned CVEs as processed
- [ ] `--category web_servers --asset nginx` is rejected by argparse with a mutual-exclusion error
- [ ] Category with zero results prints "No CVEs found" and exits 0 (not an error)
- [ ] Results are ordered by `relevance_score DESC`, then `base_score DESC`

---

## Files Changed

| File | Change |
|---|---|
| `cve_reporter.py` | Add `get_cves_by_category()` method; add `--category` arg; add `_validate_category()` helper; add dispatch branch in `main()`; update epilog examples |

---

## Future Considerations

- **Multi-category queries:** `--category web_servers,databases` could OR the two LIKE conditions
  together. Defer until there is a clear use case — separate invocations with `--format json` piped
  to `jq` cover most automation needs today.
- **`--category` + `--asset` combination:** Could AND both conditions (assets within a category that
  also match a specific keyword). Useful for narrowing large categories; design the SQL carefully to
  avoid false negatives.
- **Category listing command:** `--list-categories` could print valid category names and their
  keyword counts without requiring a CVE query. Low effort, high discoverability.
- **Category summary in dashboard:** The dashboard could gain a per-category CVE count row once
  category search is in place, replacing the current "top affected assets" heuristic.
