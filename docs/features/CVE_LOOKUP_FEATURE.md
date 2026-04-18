# Feature Design: CVE Lookup by ID (`--cve`)

## Overview

Add a `--cve <CVE-ID>` flag to `cve_reporter.py` that displays everything the local database knows about a single vulnerability in one focused view. Rather than scanning a filtered list of CVEs, an analyst can jump directly to a known CVE and see its full enrichment record — CVSS score, description, exploit and POC status, which keyword watchlist categories it matched, and a chronological processing timeline.

All data is served from the local SQLite database. No live external requests are made at lookup time.

---

## Scope

**In scope (v1):**
- Single CVE lookup by exact ID
- Full-record terminal display (all 18 database columns surfaced)
- Keyword relevance section showing which asset categories and keywords matched
- Chronological processing timeline reconstructed from stored timestamps
- Clean "not found" message when the CVE ID is absent from the database
- Case-insensitive ID normalization (e.g., `cve-2026-1234` → `CVE-2026-1234`)
- Composable with `--format json` and `--output <path>`

**Out of scope (deferred):**
- Live NVD/CISA lookups for CVEs not in the database — that is a separate ingestion concern
- Writing notes or tagging the CVE from this view — see the Research Notes feature idea
- Diff view between enrichment runs — the current schema stores only the latest snapshot per field
- Multiple CVE IDs in one invocation — a `--cve` per call keeps the UX focused; batching can be added later if needed

---

## CLI Design

### Basic usage

```bash
# Look up a CVE by ID
./cve_reporter.py --cve CVE-2026-12345

# Case-insensitive — both forms work
./cve_reporter.py --cve cve-2026-12345

# JSON output
./cve_reporter.py --cve CVE-2026-12345 --format json

# Save to file
./cve_reporter.py --cve CVE-2026-12345 --output /tmp/cve-2026-12345.txt
```

### Flag reference

| Flag | Type | Description |
|---|---|---|
| `--cve ID` | `str` | CVE identifier to look up (e.g., `CVE-2026-12345`). Case-insensitive. |

`--cve` shares the existing `--format` and `--output` flags and is mutually exclusive with all other primary report modes (`--new`, `--updated`, `--unprocessed`, `--critical`, `--severity`, `--asset`, `--exploits-only`, `--pocs-only`, `--relevant`, `--since`, `--dashboard`).

---

## Terminal Output Design

The output follows the existing separator style (`=` for headers, `-` for section breaks) and emoji conventions already established in `format_cve_text()`. A new dedicated formatter `format_cve_detail()` extends the current format with three additional sections not present in list reports: **Keyword Relevance**, **Processing History**, and **All Enrichment Data**.

### Annotated output example

```
======================================================================
CVE DETAIL: CVE-2026-12345
Generated: 2026-04-17 09:15:33
======================================================================

IDENTITY
----------------------------------------------------------------------
CVE ID:          CVE-2026-12345
Severity:        CRITICAL  (CVSS Score: 9.8)
Published:       2026-01-15
Last Updated:    2026-03-02

DESCRIPTION
----------------------------------------------------------------------
A heap-based buffer overflow in the nginx HTTP/2 request parser allows
a remote, unauthenticated attacker to execute arbitrary code via a
crafted HEADERS frame. Affects nginx 1.24.x before 1.24.1.

EXPLOIT STATUS
----------------------------------------------------------------------
Known Exploit:   YES  ⚠️  KNOWN EXPLOIT — IMMEDIATE PATCHING REQUIRED
CISA KEV:        Added (exploit_added_date not yet populated — see roadmap)
POC Available:   YES  (Sources: exploitdb, cvedb)
  → https://exploit-db.com/exploits/51234
  → https://cvedb.shodan.io/cve/CVE-2026-12345

KEYWORD RELEVANCE
----------------------------------------------------------------------
Matches Asset Inventory:  YES
Matched Categories:       web_servers
Matched Keywords:         nginx
Relevance Score:          9.8  (CVSS 9.8 × category weight 1.0)

PROCESSING HISTORY
----------------------------------------------------------------------
  2026-01-15 08:03:11  First ingested by collector
  2026-02-20 06:00:44  Data updated  (score or exploit/POC status changed)
  2026-03-02 06:01:12  Data updated  (score or exploit/POC status changed)
  2026-04-17 06:00:58  Last checked by collector  (no changes)
  [unreviewed]         Not yet marked as processed

ALL ENRICHMENT DATA
----------------------------------------------------------------------
first_seen:            2026-01-15 08:03:11
last_checked:          2026-04-17 06:00:58
last_updated_date:     2026-03-02
processed:             0  (unreviewed)
base_score:            9.8
base_severity:         CRITICAL
affects_infrastructure: 1
affected_categories:   ["web_servers"]
affected_assets:       ["nginx"]
relevance_score:       9.8
has_known_exploit:     1
exploit_added_date:    (not populated)
has_poc:               1
poc_urls:              ["https://exploit-db.com/exploits/51234",
                        "https://cvedb.shodan.io/cve/CVE-2026-12345"]
poc_source:            ["exploitdb", "cvedb"]
======================================================================
```

### Not-found output

```
No data found for CVE-2026-99999.
Run the collector to ingest new CVEs: python cve_collector.py
```

Exit code is `1` on not-found, `0` on success, consistent with standard CLI conventions.

---

## Section Breakdown

### IDENTITY
Surfaces the four most-consulted fields up front: ID, severity + CVSS score on one line, publication date, and last-updated date. Severity is printed in uppercase for visual scanning.

### DESCRIPTION
The full NVD description, word-wrapped at 70 characters to match the separator width. No truncation.

### EXPLOIT STATUS
Combines `has_known_exploit`, `exploit_added_date` (reserved, not yet populated), `has_poc`, `poc_urls`, and `poc_source`. The `⚠️  KNOWN EXPLOIT` alert banner mirrors the behavior in the existing `format_cve_text()` so analysts see a consistent signal regardless of which command produced the output.

### KEYWORD RELEVANCE
This section answers "why did ThreatPulse flag this CVE as relevant?" by surfacing `affects_infrastructure`, `affected_categories`, `affected_assets`, and `relevance_score` with human-readable labels. The relevance score formula is shown inline (`CVSS × weight`) so analysts understand how the number was derived without needing to read `config.py`.

If `affects_infrastructure = 0`, this section reads:

```
KEYWORD RELEVANCE
----------------------------------------------------------------------
Matches Asset Inventory:  NO
(No configured keywords matched the CVE description)
```

### PROCESSING HISTORY
The current schema does not maintain a full audit log, but four timestamps together tell a useful chronological story:

| Timestamp | Source column | Meaning |
|---|---|---|
| First ingested | `first_seen` | When the collector first inserted this CVE row |
| Data updated | `last_updated_date` | Each time the upsert logic detected a change in score, exploit, or POC status — **this column holds only the most recent update date**, so only one "Data updated" line is shown |
| Last checked | `last_checked` | The most recent collector run that touched this row |
| Reviewed | `processed` | `1` → shown as a timestamped "Marked as processed" entry if `last_updated_date` can serve as a proxy; `0` → shown as "[unreviewed]" |

**Known limitation:** Because `last_updated_date` stores only the most recent change, the history cannot enumerate every individual data change. The Timeline View feature idea (FEATURE_IDEAS.md) describes a proper audit-log approach for a future version.

### ALL ENRICHMENT DATA
A machine-readable dump of every column in the `cves` table row, labeled with the exact column name. This section ensures that no information is hidden from the analyst — it is the "raw record" view. JSON arrays (`poc_urls`, `poc_source`, `affected_categories`, `affected_assets`) are pretty-printed for readability.

---

## JSON Output

When `--format json` is active, the output is a single JSON object (not an array) containing all 18 columns plus a `generated_at` field. JSON arrays are returned as native arrays, not escaped strings. The `--output` flag writes to a file.

```json
{
  "generated_at": "2026-04-17T09:15:33",
  "id": "CVE-2026-12345",
  "description": "A heap-based buffer overflow...",
  "published_date": "2026-01-15",
  "last_updated_date": "2026-03-02",
  "base_score": 9.8,
  "base_severity": "CRITICAL",
  "affects_infrastructure": 1,
  "affected_categories": ["web_servers"],
  "affected_assets": ["nginx"],
  "relevance_score": 9.8,
  "has_known_exploit": 1,
  "exploit_added_date": null,
  "first_seen": "2026-01-15 08:03:11",
  "last_checked": "2026-04-17 06:00:58",
  "processed": 0,
  "has_poc": 1,
  "poc_urls": ["https://exploit-db.com/exploits/51234", "https://cvedb.shodan.io/cve/CVE-2026-12345"],
  "poc_source": ["exploitdb", "cvedb"]
}
```

---

## Implementation

### 1. Argument parser (`cve_reporter.py` — arg definitions, lines ~385–422)

Add `--cve` to the report-type argument group:

```python
report_group.add_argument(
    '--cve',
    type=str,
    metavar='CVE-ID',
    help='Display full detail for a specific CVE ID (e.g. CVE-2026-12345)'
)
```

Because `--cve` is added to the same mutually-exclusive `report_group`, argparse will automatically reject combinations like `--cve CVE-X --critical`.

### 2. ID normalization (utility, inline in `main()` or a helper)

```python
def normalize_cve_id(raw: str) -> str:
    """Normalize CVE ID to uppercase canonical form."""
    return raw.strip().upper()
```

Called immediately after argparse to sanitize user input before it reaches the database query.

### 3. Reporter method (`CVEReporter`, `cve_reporter.py` — after existing `get_*` methods, ~line 131)

```python
def get_cve_by_id(self, cve_id: str):
    """Return the single cves row for cve_id, or None if not found."""
    cursor = self.conn.cursor()
    cursor.execute("SELECT * FROM cves WHERE id = ?", (cve_id,))
    return cursor.fetchone()
```

The query is a simple primary-key lookup — O(1) via the SQLite auto-index on `id`. No joins or subqueries needed.

### 4. Detail formatter (`CVEReporter.format_cve_detail()`, new method)

A new method separate from the existing `format_cve_text()`. This keeps list-report formatting unchanged while allowing the detail view to show all sections described above. Key implementation notes:

- Parse `poc_urls`, `poc_source`, `affected_categories`, `affected_assets` with `json.loads()`, guarding against `None` and malformed JSON (return `[]` on error).
- Build the PROCESSING HISTORY block from `first_seen`, `last_updated_date`, `last_checked`, `processed` — sorting by timestamp value.
- Wrap the description at 70 characters using `textwrap.fill()`.
- All column values in the ALL ENRICHMENT DATA section should be printed with their raw column name as the label so the output is self-documenting.

### 5. Dispatch logic (`main()`, `cve_reporter.py` — lines ~425–499)

Insert before the existing `if args.dashboard:` branch:

```python
if args.cve:
    cve_id = normalize_cve_id(args.cve)
    cve = reporter.get_cve_by_id(cve_id)
    if cve is None:
        print(f"No data found for {cve_id}.")
        print(f"Run the collector to ingest new CVEs: python cve_collector.py")
        sys.exit(1)
    if args.format == 'json':
        output = reporter.format_cve_detail_json(cve)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)
    else:
        output = reporter.format_cve_detail(cve)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)
    sys.exit(0)
```

Calling `sys.exit(0)` after the lookup prevents any downstream report-mode logic from running.

### 6. JSON formatter (`CVEReporter.format_cve_detail_json()`, new method)

Parallel to `format_cve_detail()` for the `--format json` path. Returns a `json.dumps()` string of the full record with parsed arrays and a `generated_at` timestamp. Reuses the same JSON parsing logic extracted into a shared `_parse_json_field()` helper to avoid duplication between the two formatters.

---

## Edge Cases

| Scenario | Behavior |
|---|---|
| CVE ID not in database | Print "No data found" + ingest hint, exit 1 |
| CVE ID in wrong case (`cve-2026-1234`) | Normalized to uppercase before query |
| Malformed ID (no dashes, random string) | Still queries the database; returns not-found if absent. No validation of ID format in v1. |
| `poc_urls` / `poc_source` stored as `NULL` | `json.loads()` guard returns `[]`; POC section shows "NO" |
| `affected_categories` / `affected_assets` stored as `NULL` | Same guard; relevance section shows "NO" with no keyword list |
| `exploit_added_date` is `NULL` (currently always true) | Displayed as "(not populated)" in text mode, `null` in JSON |
| `--mark-processed` combined with `--cve` | Should be supported — mark the single looked-up CVE as processed. Implement by calling `mark_as_processed([cve_id])` after display. |

---

## Testing Checklist

- [ ] `--cve CVE-XXXX` returns full detail for a CVE that exists in the database
- [ ] `--cve cve-xxxx` (lowercase) returns the same result
- [ ] `--cve CVE-XXXX-NOTREAL` prints the not-found message and exits with code 1
- [ ] `--cve CVE-XXXX --format json` produces valid, parseable JSON with all 18 fields
- [ ] `--cve CVE-XXXX --output /tmp/out.txt` writes to file instead of stdout
- [ ] `--cve CVE-XXXX --mark-processed` marks the CVE as processed in the database
- [ ] `--cve CVE-XXXX --new` (combined with another mode) is rejected by argparse with a clear error
- [ ] CVE with `NULL` POC fields displays cleanly without crashing
- [ ] CVE with `affects_infrastructure = 0` shows the "no match" relevance message

---

## Future Considerations

- **Audit log / full timeline:** Once a `cve_history` table is added (see Timeline View in FEATURE_IDEAS.md), the PROCESSING HISTORY section can be populated from real per-event records rather than derived timestamps.
- **`--mark-processed` integration:** Already noted in edge cases — straightforward to wire in.
- **Cross-linking to threat actors:** When Threat Actor Association (FEATURE_IDEAS.md) is implemented, the KEYWORD RELEVANCE section could gain a "Known exploitation by:" subsection listing any linked groups.
- **`--cve` + `--search` composition:** May be useful in the future as a "lookup and find similar" workflow once `--search` is implemented.
