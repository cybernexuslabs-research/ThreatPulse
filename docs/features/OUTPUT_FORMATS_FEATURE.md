# Feature Design: Multiple Output Formats (`--format`, `--output`)

## Overview

The reporter currently outputs to the terminal only. Add `--format json`, `--format csv`, and `--format html` flags so output can be piped into other tools, imported into spreadsheets, or viewed in a browser. A `--output <path>` flag writes output to a file instead of stdout.

---

## Scope

**In scope (v1):**
- `--format text` (default, existing behavior)
- `--format json` — structured JSON suitable for piping and programmatic use
- `--format csv` — flat CSV for spreadsheet import
- `--format html` — self-contained HTML file for browser viewing
- `--output <path>` — write to file instead of stdout (works with all formats)
- All existing reporter modes (`--new`, `--critical`, `--cve`, `--dashboard`, etc.) support all formats

**Out of scope (deferred):**
- `--format markdown` — deferred to the Markdown/HTML Report Generation feature (which produces a formatted *brief* rather than a raw data export)
- `--format xlsx` — requires a third-party library; deferred to v2
- Streaming output for very large result sets

---

## CLI Design

```bash
# JSON to stdout
./cve_reporter.py --new --format json

# CSV to file
./cve_reporter.py --critical --format csv --output critical_cves.csv

# HTML to file
./cve_reporter.py --relevant --format html --output briefing.html

# Open in browser (macOS)
./cve_reporter.py --relevant --format html --output /tmp/brief.html && open /tmp/brief.html

# Pipe JSON to jq for field extraction
./cve_reporter.py --exploits-only --format json | jq '[.[] | {id, base_score, has_poc}]'
```

### Flag reference

| Flag | Type | Description |
|---|---|---|
| `--format FORMAT` | `text` \| `json` \| `csv` \| `html` | Output format. Default: `text`. |
| `--output PATH` | `str` | Write output to this file path instead of stdout. |

---

## JSON Format

Output is a JSON array of objects, one per CVE. Array fields (`poc_urls`, `affected_categories`, `affected_assets`, `poc_source`) are native JSON arrays, not escaped strings. All 18 database columns are included verbatim (booleans stay as raw `0`/`1` ints, matching the DB representation — not coerced to `true`/`false`) plus a `generated_at` timestamp at the top level.

The `filter` object is a superset of the `{mode, hours, severity}` sketch originally drafted here: it was extended to also cover this repo's composable filter system (`--category`, `--asset`, `--exploits-only`, `--pocs-only`), which shipped in a separate feature after this doc was first written. `hours` is only meaningful for `new`/`updated` modes and is `null` otherwise; `severity` is `null`, a single-element list (`--critical`), or a multi-element list (`--severity HIGH,CRITICAL`).

```json
{
  "generated_at": "2026-06-30T09:15:00",
  "filter": {
    "mode": "new",
    "hours": 24,
    "severity": null,
    "category": null,
    "asset": null,
    "exploits_only": false,
    "pocs_only": false
  },
  "count": 47,
  "cves": [
    {
      "id": "CVE-2026-12345",
      "description": "...",
      "published_date": "2026-06-29",
      "last_updated_date": null,
      "base_score": 9.8,
      "base_severity": "CRITICAL",
      "affects_infrastructure": 1,
      "affected_categories": ["web_servers"],
      "affected_assets": ["nginx"],
      "relevance_score": 9.8,
      "has_known_exploit": 1,
      "exploit_added_date": null,
      "has_poc": 1,
      "poc_urls": ["https://..."],
      "poc_source": ["exploitdb"],
      "first_seen": "2026-06-29 08:03:11",
      "last_checked": "2026-06-30 06:00:58",
      "processed": 0
    }
  ]
}
```

`--cve <ID>` uses a different, pre-existing JSON shape (a single flat object with `generated_at` at the top level, not wrapped in `{filter, count, cves}`) — unchanged by this feature.

Special modes (`--dashboard`, `--trend`, `--cluster`) produce mode-specific JSON structures documented in their respective feature docs. As shipped, `--dashboard` supports `--format text` only; `--format json/csv/html` on `--dashboard` is rejected with an error pending that design. `--trend`/`--cluster` don't exist yet in this codebase.

---

## CSV Format

A flat CSV file with one row per CVE. Multi-value fields (JSON arrays) are serialized as pipe-delimited strings:

```
id,published_date,base_score,base_severity,has_known_exploit,has_poc,affects_infrastructure,relevance_score,affected_categories,affected_assets,poc_urls,description
CVE-2026-12345,2026-06-29,9.8,CRITICAL,1,1,1,9.8,web_servers,nginx,https://exploit-db.com/...,A heap-based buffer overflow...
```

The CSV header row always uses the database column names for predictability. The `description` field is quoted and escaped. `generated_at` is included as a comment on the first line:

```
# Generated: 2026-06-30 09:15:00  |  Filter: new (24h)  |  Count: 47
id,published_date,...
```

---

## HTML Format

A self-contained HTML file with embedded CSS — no external dependencies. The page renders a sortable, filterable table. All data is inlined in a `<script>` tag as a JSON blob; the table is built client-side.

### Features

- Sortable columns (click header)
- Text search box (filters rows in real time)
- Severity color coding: CRITICAL (red), HIGH (orange), MEDIUM (yellow), LOW (grey)
- Exploit and POC badges
- Expandable row for full description and POC links

### Header

```html
<h1>ThreatPulse CVE Report</h1>
<p>Generated: 2026-06-30 09:15:00 | Filter: new (24h) | 47 CVEs</p>
```

The HTML file is ~50 KB for a 100-CVE result set. No chart libraries are embedded in the base HTML format (charts belong to the Web UI feature).

---

## Implementation Notes

### Format dispatch

The existing `main()` in `cve_reporter.py` calls a format function after retrieving rows:

```python
rows = reporter.get_cves(args)  # Returns list regardless of mode

if args.format == 'json':
    output = format_json(rows, args, meta)
elif args.format == 'csv':
    output = format_csv(rows, args)
elif args.format == 'html':
    output = format_html(rows, args, meta)
else:
    output = format_text(rows, args)  # existing behavior

if args.output:
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(output)
else:
    print(output)
```

### `--output` with `--format text`

Writing text output to a file with `--output` strips ANSI color codes (if any are added in future) since the file will likely be read in a plain-text editor.

---

## Edge Cases

| Scenario | Behavior |
|---|---|
| `--output` path is not writable | Print error and exit 1 before generating output |
| Result set is empty | JSON outputs `{"count": 0, "cves": []}`, CSV outputs header only, HTML outputs table with "No results" row |
| `--format csv` with description containing commas | Properly quoted with `csv.writer` |
| `--format html` with very large result set (1000+ CVEs) | Warn that performance may be degraded; no hard limit in v1 |

---

## Testing Checklist

- [ ] `--format json` produces valid parseable JSON with all fields
- [ ] `--format csv` produces a valid CSV with correct quoting for description field
- [ ] `--format html` produces a self-contained HTML file that opens in a browser
- [ ] `--output /path/to/file` writes to file; no stdout output
- [ ] Empty result set produces valid (non-crashing) output in all formats
- [ ] JSON array fields are native arrays, not escaped strings

---

## Future Considerations

- **`--format markdown`:** A formatted Markdown table suitable for pasting into GitHub issues or Confluence — distinct from the full Markdown/HTML report brief.
- **`--format xlsx`:** Excel output with conditional formatting for severity. Requires `openpyxl`.
- **Streaming JSON:** For very large result sets, stream newline-delimited JSON (`--format ndjson`) to avoid building the full response in memory.
