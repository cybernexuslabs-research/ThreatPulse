# Feature Design: Collections / Watchlists

## Overview

Support named collections of CVEs that a researcher is tracking for a specific project or report. A collection (e.g., "Log4j variants", "Q3 Red Team", "Customer XYZ") lets analysts add CVEs to a named set and later query, export, or report on that set as a group — independent of the asset inventory, severity filters, or any other system-managed attribute.

---

## Scope

**In scope (v1):**
- Create, rename, and delete named collections
- Add and remove CVEs from a collection
- List all collections and their member counts
- `--collection <name>` filter to retrieve all CVEs in a named set
- Collections stored in a new `collections` table (many-to-many with `cves`)
- All existing reporter flags composable with `--collection`

**Out of scope (deferred):**
- Shared collections across users (see Multi-User Triage feature)
- Collection expiry or archiving
- Automatic collection population via saved search

---

## Schema Changes

### `collections` table

```sql
CREATE TABLE IF NOT EXISTS collections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
```

### `collection_members` join table

```sql
CREATE TABLE IF NOT EXISTS collection_members (
    collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    cve_id        TEXT    NOT NULL REFERENCES cves(id),
    added_at      TEXT    NOT NULL,
    PRIMARY KEY (collection_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_collection_members_cve ON collection_members(cve_id);
```

---

## CLI Design

### Collection management

```bash
# Create a new collection
./cve_reporter.py --create-collection "Log4j variants" --description "Tracking Log4Shell family"

# List all collections
./cve_reporter.py --list-collections

# Add a CVE to a collection
./cve_reporter.py --add-to-collection "Log4j variants" CVE-2021-44228

# Add multiple CVEs
./cve_reporter.py --add-to-collection "Log4j variants" CVE-2021-44228 CVE-2021-45046

# Remove a CVE from a collection
./cve_reporter.py --remove-from-collection "Log4j variants" CVE-2021-44228

# Delete a collection (does not delete CVEs from cves table)
./cve_reporter.py --delete-collection "Log4j variants"

# Rename a collection
./cve_reporter.py --rename-collection "Log4j variants" "Log4Shell Family"
```

### Querying

```bash
# Report on all CVEs in a collection
./cve_reporter.py --collection "Log4j variants"

# Composed with other filters
./cve_reporter.py --collection "Q3 Red Team" --exploits-only
./cve_reporter.py --collection "Customer XYZ" --format json --output customer_xyz.json

# Mark all CVEs in a collection as processed
./cve_reporter.py --collection "Log4j variants" --mark-processed
```

### Flag reference

| Flag | Type | Description |
|---|---|---|
| `--collection NAME` | `str` | Filter: show only CVEs in this named collection. |
| `--create-collection NAME` | `str` | Create a new collection. |
| `--description TEXT` | `str` | Optional description for `--create-collection`. |
| `--list-collections` | `bool` | List all collections with member counts and dates. |
| `--add-to-collection NAME CVE-ID...` | `str` + `str+` | Add CVE(s) to a collection. |
| `--remove-from-collection NAME CVE-ID` | `str str` | Remove a CVE from a collection. |
| `--delete-collection NAME` | `str` | Delete a collection (not its CVEs). |
| `--rename-collection OLD NEW` | `str str` | Rename a collection. |

---

## Display Changes

### `--list-collections` output

```
COLLECTIONS
======================================================================
  Log4j variants        12 CVEs   Created 2026-01-10   "Tracking Log4Shell family"
  Q3 Red Team            5 CVEs   Created 2026-05-15
  Customer XYZ           3 CVEs   Created 2026-06-01
======================================================================
Total: 3 collections
```

### `--collection` report header

Reports filtered by collection include the collection name and description in the header:

```
======================================================================
COLLECTION: Log4j variants
Description: Tracking Log4Shell family
Members: 12 CVEs  |  Filters: exploits-only
Generated: 2026-06-30 09:15:00
======================================================================
```

### Collection membership in detail view

In `format_cve_detail()`, list any collections the CVE belongs to:

```
Collections:   Log4j variants, Q3 Red Team
```

---

## Implementation Notes

### Collection lookup by name

Collection names are used as human-readable identifiers on the CLI. The reporter resolves a name to an ID at query time:

```python
def get_collection_id(conn, name: str) -> int | None:
    row = conn.execute("SELECT id FROM collections WHERE name = ?", (name,)).fetchone()
    return row[0] if row else None
```

### Adding CVEs from search results

A common workflow is to run a search, identify interesting CVEs, and add them all to a collection. This is supported by piping `--format json` output into a shell script that calls `--add-to-collection`, or in a future version via a `--save-to-collection` flag on any report command.

---

## Edge Cases

| Scenario | Behavior |
|---|---|
| `--add-to-collection` with a CVE not in database | Print warning: "CVE-XXXX not found in database — skipped"; continue with others |
| `--collection` with a name that doesn't exist | Print "Collection not found: X"; suggest `--list-collections` |
| `--create-collection` with a duplicate name | Print "Collection already exists: X" and exit 1 |
| `--delete-collection` removes the only collection | No problem — collection table becomes empty |
| CVE removed from `cves` table | `ON DELETE CASCADE` removes it from `collection_members` automatically |

---

## Testing Checklist

- [ ] `--create-collection` inserts a row in `collections`
- [ ] `--add-to-collection` inserts into `collection_members`; duplicate add is a no-op
- [ ] `--collection "X"` returns only CVEs in that collection
- [ ] `--collection "X" --exploits-only` returns the intersection
- [ ] `--list-collections` shows name, count, and description
- [ ] `--delete-collection` removes collection and its membership rows (cascade)
- [ ] CVE not in database produces a warning, not a crash, during `--add-to-collection`

---

## Future Considerations

- **Saved search as collection source:** `--save-to-collection "Q3 Red Team"` appended to any report command automatically adds matching CVEs.
- **Collection export:** `--collection "X" --format stix` to export a collection as a STIX bundle.
- **Shared collections:** In a multi-user context (see Multi-User Triage), collections could be shared between analysts.
- **Collection diff:** Show what CVEs were added to a collection since a given date.
