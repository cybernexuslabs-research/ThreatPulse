#!/usr/bin/env python3
"""
ThreatPulse - CVE Reporter Service
Continuous CVE threat monitoring and reporting tool.
Generates reports from CVE database on-demand.
Supports multiple output formats and filtering options.
"""

import sys
import os
import sqlite3
import json
import csv
import io
import re
import html as html_escape_module
import argparse
import textwrap
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import config
from events import record_event

def normalize_cve_id(raw: str) -> str:
    """Normalize CVE ID to uppercase canonical form (e.g. cve-2026-1234 → CVE-2026-1234)."""
    return raw.strip().upper()


def days_to_exploit(published_date: Optional[str], events: List[Dict]) -> Optional[timedelta]:
    """Time from NVD publication to the first sign of active exploitation.

    Anchored on `cves.published_date` (the actual NVD disclosure date) —
    not the `ingested` event's timestamp, which is what the design doc's
    original pseudocode used. `ingested` only records when *this collector*
    first observed the CVE, which lags real disclosure by however stale
    that particular collector run was, and doesn't exist at all for CVEs
    ingested before this feature shipped. published_date is present on
    every row regardless, so this covers those pre-feature CVEs too, the
    moment they earn a kev_added/poc_added event.

    "First sign of exploitation" is the earliest kev_added or poc_added
    event (exploit_confirmed was collapsed into kev_added in the collector —
    see cve_collector.py's _record_lifecycle_events — there's only one
    exploit-signal event type to look for here).

    Returns None if there's no published_date, no qualifying event, or
    either timestamp fails to parse (defensive against malformed/legacy data
    rather than raising out of a report-generation path).
    """
    if not published_date:
        return None
    exploit_events = [e for e in events if e['event_type'] in ('kev_added', 'poc_added')]
    if not exploit_events:
        return None
    first = min(exploit_events, key=lambda e: e['event_date'])
    try:
        pub = datetime.fromisoformat(published_date)
        first_dt = datetime.fromisoformat(first['event_date'])
    except (ValueError, TypeError):
        return None
    return first_dt - pub


def _format_duration(delta: timedelta) -> str:
    """Human-readable duration for display: '5 days', '3 hours', '2 days 4 hours'.

    Shared by format_cve_detail()'s LIFECYCLE TIMELINE section and the
    --velocity list-view line, so both surfaces render a days_to_exploit()
    result identically.
    """
    total_seconds = max(delta.total_seconds(), 0)
    days = int(total_seconds // 86400)
    hours = int((total_seconds % 86400) // 3600)
    if days > 0 and hours > 0:
        return f"{days} day{'s' if days != 1 else ''} {hours} hour{'s' if hours != 1 else ''}"
    elif days > 0:
        return f"{days} day{'s' if days != 1 else ''}"
    elif hours > 0:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return "less than an hour"


# All columns in the `cves` table, in schema.sql order. Drives full column
# parity across --format json/csv/html (the output-formats spec requires
# every DB column to be present in list-based exports).
CVE_COLUMNS = [
    'id', 'description', 'published_date', 'last_updated_date',
    'base_score', 'base_severity',
    'affects_infrastructure', 'affected_categories', 'affected_assets', 'relevance_score',
    'has_known_exploit', 'exploit_added_date',
    'has_poc', 'poc_urls', 'poc_source',
    'first_seen', 'last_checked', 'processed',
]

# Columns whose DB representation is a JSON-encoded array string.
JSON_ARRAY_COLUMNS = {'affected_categories', 'affected_assets', 'poc_urls', 'poc_source'}

# Collections / Watchlists schema (see docs/features/COLLECTIONS_WATCHLISTS_FEATURE.md).
# Inlined (rather than read from schema.sql at runtime) so the reporter keeps
# no dependency on schema.sql being present in the working directory. Kept in
# sync with the CREATE TABLE/INDEX statements appended to schema.sql — both
# use IF NOT EXISTS, so running either (or both) more than once is a no-op.
# Both FK columns on collection_members cascade on delete: collection_id so
# deleting a collection cleans up its membership rows, and cve_id so a CVE
# removed from `cves` doesn't leave orphaned membership rows behind. Cascades
# only fire when the connection has `PRAGMA foreign_keys = ON` (see
# CVEReporter.__enter__).
_COLLECTIONS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS collections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collection_members (
    collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    cve_id        TEXT    NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    added_at      TEXT    NOT NULL,
    PRIMARY KEY (collection_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_collection_members_cve ON collection_members(cve_id);
"""

# Lifecycle event log (see docs/features/TIMELINE_VIEW_FEATURE.md). Inlined
# for the same reason _COLLECTIONS_SCHEMA_SQL is: the reporter must not
# depend on schema.sql being present, or on cve_collector.py's
# migrate_database() having already run against this DB. Kept in sync with
# the CREATE TABLE/INDEX statements appended to schema.sql; both use IF NOT
# EXISTS. The FK cascades on delete for the same reason collection_members'
# does — a CVE removed from `cves` shouldn't leave orphaned event rows —
# and only fires with PRAGMA foreign_keys = ON (see CVEReporter.__enter__).
_CVE_EVENTS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cve_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    event_date  TEXT NOT NULL,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_events_cve_id ON cve_events(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_events_type   ON cve_events(event_type);
"""

# Matches the placeholder tokens in CVEReporter._HTML_TEMPLATE. Used with
# re.sub()'s callback form (see format_list_html) so token substitution is a
# single pass over the *original* template — chaining separate str.replace()
# calls would re-scan each already-substituted result for the next token,
# and a CVE description or --asset/--category value that happens to contain
# the literal text "___HEADER___" would get corrupted by a later replace().
_HTML_TOKEN_RE = re.compile(r'___(?:DATA_JSON|HEADER)___')

# Leading characters that spreadsheet applications (Excel, Sheets, LibreOffice)
# interpret as the start of a formula. A leading apostrophe neutralizes this
# without altering the visible cell value.
_CSV_FORMULA_TRIGGERS = ('=', '+', '-', '@', '\t', '\r')


def _csv_safe(value) -> str:
    """Stringify a CSV cell value, neutralizing formula-injection payloads.

    If the stringified value starts with a character a spreadsheet app would
    treat as a formula prefix, prepend a single quote so it's rendered as
    inert text instead of being evaluated.
    """
    s = '' if value is None else str(value)
    if s.startswith(_CSV_FORMULA_TRIGGERS):
        return "'" + s
    return s


def write_output(content: str, path: Optional[str] = None):
    """Write `content` to `path` if given, else print it to stdout.

    No confirmation message is printed on success — callers that write a
    report to a file must produce zero stdout output, so piping/redirecting
    stdout always yields exactly the requested format and nothing else.
    """
    if path:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    else:
        print(content)


def _check_output_writable(path: str):
    """Verify `path` is writable before any report generation begins.

    Deliberately avoids creating a file as a side effect of the check (an
    `open(path, 'a')` probe would silently leave a zero-byte file behind
    even if the run later aborts for an unrelated reason). If `path` exists,
    checks it directly; otherwise checks that its parent directory exists
    and is writable. Prints an error and exits 1 on failure.
    """
    if os.path.exists(path):
        writable = os.access(path, os.W_OK)
    else:
        directory = os.path.dirname(path) or '.'
        writable = os.path.isdir(directory) and os.access(directory, os.W_OK)

    if not writable:
        print(f"Error: cannot write to output path '{path}'", file=sys.stderr)
        sys.exit(1)


class CVEReporter:
    """Generate various reports from CVE database"""
    
    def __init__(self, db_path: str = config.DB_PATH):
        self.db_path = db_path
        self.conn = None
    
    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        # Required for collection_members' ON DELETE CASCADE to actually fire —
        # SQLite does not enforce FK constraints by default. Must be set before
        # any DDL/DML, which is guaranteed here (first statement post-connect).
        self.conn.execute("PRAGMA foreign_keys = ON")
        # cve_collector.py is a separate writer process with no lock
        # coordination (cron runs every 30 min per this file's own epilog);
        # retry briefly instead of immediately raising "database is locked"
        # if a report happens to race a collector write.
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self._ensure_table_schema('collections', _COLLECTIONS_SCHEMA_SQL)
        self._ensure_table_schema('cve_events', _CVE_EVENTS_SCHEMA_SQL)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()

    def _ensure_table_schema(self, table_name: str, schema_sql: str):
        """Create `table_name` (and whatever it's defined alongside — sibling
        tables/indexes in `schema_sql`, e.g. collections+collection_members)
        if `table_name` doesn't exist yet.

        Checks sqlite_master first (a plain indexed read, no write lock)
        rather than unconditionally running CREATE TABLE IF NOT EXISTS on
        every invocation — cve_reporter.py must stay read-only for read-only
        commands (--dashboard, --cve, a plain filtered query), and DDL takes
        a write lock even when it ends up being a no-op.
        """
        exists = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,)
        ).fetchone()
        if exists is None:
            self.conn.executescript(schema_sql)
            self.conn.commit()

    def get_new_cves(self, hours: int = 24) -> List[sqlite3.Row]:
        """Get CVEs added in the last N hours"""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM cves
            WHERE first_seen > ?
            ORDER BY base_score DESC, published_date DESC
        """, (cutoff,))
        return cursor.fetchall()
    
    def get_updated_cves(self, hours: int = 24) -> List[sqlite3.Row]:
        """Get CVEs that were updated in the last N hours"""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM cves
            WHERE last_updated_date > ?
            ORDER BY last_updated_date DESC
        """, (cutoff,))
        return cursor.fetchall()
    
    def get_unprocessed_cves(self) -> List[sqlite3.Row]:
        """Get CVEs that haven't been processed/reported yet"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM cves
            WHERE processed = 0
            ORDER BY base_score DESC, published_date DESC
        """)
        return cursor.fetchall()
    
    def get_cves_by_severity(self, severities: List[str]) -> List[sqlite3.Row]:
        """Get CVEs by severity level(s)"""
        placeholders = ','.join('?' * len(severities))
        cursor = self.conn.cursor()
        cursor.execute(f"""
            SELECT * FROM cves
            WHERE base_severity IN ({placeholders})
            ORDER BY base_score DESC, published_date DESC
        """, severities)
        return cursor.fetchall()
    
    def get_cves_by_asset(self, asset: str, with_exploits: bool = False) -> List[sqlite3.Row]:
        """Get CVEs affecting a specific asset.
        Preserved for backward compatibility; main() now uses build_filtered_query()."""
        cursor = self.conn.cursor()
        query = """
            SELECT * FROM cves
            WHERE affected_assets LIKE ?
        """
        params = [f'%"{asset}"%']
        
        if with_exploits:
            query += " AND has_known_exploit = 1"
        
        query += " ORDER BY relevance_score DESC, base_score DESC"
        
        cursor.execute(query, params)
        return cursor.fetchall()
    
    def get_cves_by_category(self, category: str, with_exploits: bool = False) -> List[sqlite3.Row]:
        """Get CVEs matching a specific asset category.
        Preserved for backward compatibility; main() now uses build_filtered_query()."""
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

    def get_exploit_cves(self) -> List[sqlite3.Row]:
        """Get all CVEs with known exploits"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM cves
            WHERE has_known_exploit = 1
            ORDER BY relevance_score DESC, base_score DESC
        """)
        return cursor.fetchall()
    
    def get_poc_cves(self) -> List[sqlite3.Row]:
        """Get all CVEs with known POC exploits"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM cves
            WHERE has_poc = 1
            ORDER BY relevance_score DESC, base_score DESC
        """)
        return cursor.fetchall()

    def get_relevant_cves(self) -> List[sqlite3.Row]:
        """Get CVEs relevant to our infrastructure"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM cves
            WHERE affects_infrastructure = 1
            ORDER BY relevance_score DESC
        """)
        return cursor.fetchall()
    
    def get_cves_since_date(self, since_date: str) -> List[sqlite3.Row]:
        """Get CVEs published since a specific date"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM cves
            WHERE published_date >= ?
            ORDER BY base_score DESC, published_date DESC
        """, (since_date,))
        return cursor.fetchall()
    
    def build_filtered_query(
        self,
        hours: int = 24,
        new: bool = False,
        updated: bool = False,
        unprocessed: bool = False,
        relevant: bool = False,
        since: str = None,
        critical: bool = False,
        severities: list = None,
        category: str = None,
        asset: str = None,
        exploits_only: bool = False,
        pocs_only: bool = False,
        collection_id: int = None,
    ) -> tuple:
        """Build a composable SELECT query from any combination of active flags.

        Phase 1 — primary mode sets the base WHERE condition and ORDER BY.
        Phase 2 — composable filters append AND conditions on top of any base.

        Returns (sql, params) ready for cursor.execute().
        """
        conditions = []
        params = []

        # --- Phase 1: Primary mode ---
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

        # --- Phase 2: Composable filters ---
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

        if collection_id is not None:
            # Subquery (not a JOIN) keeps SELECT * FROM cves semantics intact
            # and composes trivially with the condition-list/params-list
            # building above.
            conditions.append("id IN (SELECT cve_id FROM collection_members WHERE collection_id = ?)")
            params.append(collection_id)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # Per-mode ORDER BY — preserves semantics of all existing get_* methods
        if updated:
            order_by = "last_updated_date DESC"
        elif relevant or category or asset or exploits_only or pocs_only or collection_id:
            order_by = "relevance_score DESC, base_score DESC"
        else:
            order_by = "base_score DESC, published_date DESC"

        sql = f"SELECT * FROM cves {where} ORDER BY {order_by}"
        return sql, params

    # ------------------------------------------------------------------
    # Collections / Watchlists data-access layer
    # (see docs/features/COLLECTIONS_WATCHLISTS_FEATURE.md)
    # ------------------------------------------------------------------

    def get_collection_id(self, name: str) -> Optional[int]:
        """Resolve a collection name to its id, or None if it doesn't exist."""
        row = self.conn.execute(
            "SELECT id FROM collections WHERE name = ?", (name,)
        ).fetchone()
        return row[0] if row else None

    def create_collection(self, name: str, description: Optional[str] = None):
        """Insert a new collection row.

        Callers should pre-check get_collection_id(name) is None first (for
        a clean "already exists" message in the common case); this also
        catches sqlite3.IntegrityError as a race-condition backstop (two
        concurrent invocations creating the same name) and exits the same
        way the pre-check does, so behavior is identical either way.
        """
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            self.conn.execute(
                "INSERT INTO collections (name, description, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (name, description, now, now),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            print(f"Collection already exists: {name}", file=sys.stderr)
            sys.exit(1)

    def list_collections(self) -> List[sqlite3.Row]:
        """Return all collections with a computed member_count, oldest first.

        LEFT JOIN + COUNT(m.cve_id) (not COUNT(*)) so empty collections show
        0 members instead of 1 (a bare COUNT(*) would count the single NULL
        row a LEFT JOIN produces for a collection with no members).
        """
        return self.conn.execute("""
            SELECT c.*, COUNT(m.cve_id) AS member_count
            FROM collections c
            LEFT JOIN collection_members m ON m.collection_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at ASC
        """).fetchall()

    def get_collection_member_count(self, collection_id: int) -> int:
        """Total CVE count for a collection, independent of any other active filters.

        The single named source for the --collection text banner's "Members:
        N CVEs" figure — deliberately not len(cves), which is the *filtered*
        result count once other flags (e.g. --exploits-only) are combined
        with --collection.
        """
        row = self.conn.execute(
            "SELECT COUNT(*) FROM collection_members WHERE collection_id = ?",
            (collection_id,),
        ).fetchone()
        return row[0]

    def add_to_collection(self, collection_id: int, cve_ids: List[str]) -> tuple:
        """Add CVE IDs (already normalized) to a collection.

        Returns (added, skipped) — skipped holds any CVE ID not present in
        the cves table (doc's edge case: warn and continue, don't crash).
        INSERT OR IGNORE makes re-adding an existing member a no-op at the
        (collection_id, cve_id) primary key.
        """
        added, skipped = [], []
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        for cve_id in cve_ids:
            if self.get_cve_by_id(cve_id) is None:
                skipped.append(cve_id)
                continue
            self.conn.execute(
                "INSERT OR IGNORE INTO collection_members (collection_id, cve_id, added_at) "
                "VALUES (?, ?, ?)",
                (collection_id, cve_id, now),
            )
            added.append(cve_id)
        if added:
            self.conn.execute(
                "UPDATE collections SET updated_at = ? WHERE id = ?", (now, collection_id)
            )
        self.conn.commit()
        return added, skipped

    def remove_from_collection(self, collection_id: int, cve_id: str) -> bool:
        """Remove one CVE from a collection. Returns True if a row was actually deleted."""
        cursor = self.conn.execute(
            "DELETE FROM collection_members WHERE collection_id = ? AND cve_id = ?",
            (collection_id, cve_id),
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def delete_collection(self, collection_id: int):
        """Delete a collection; membership rows cascade via the FK (PRAGMA foreign_keys=ON)."""
        self.conn.execute("DELETE FROM collections WHERE id = ?", (collection_id,))
        self.conn.commit()

    def rename_collection(self, collection_id: int, new_name: str):
        """Rename a collection. See create_collection() for the IntegrityError handling."""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            self.conn.execute(
                "UPDATE collections SET name = ?, updated_at = ? WHERE id = ?",
                (new_name, now, collection_id),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            print(f"Collection already exists: {new_name}", file=sys.stderr)
            sys.exit(1)

    def get_collections_for_cve(self, cve_id: str) -> List[str]:
        """Names of every collection cve_id belongs to, alphabetically. Feeds format_cve_detail()."""
        rows = self.conn.execute("""
            SELECT c.name FROM collections c
            JOIN collection_members m ON m.collection_id = c.id
            WHERE m.cve_id = ?
            ORDER BY c.name
        """, (cve_id,)).fetchall()
        return [row[0] for row in rows]

    def get_events_for_cve(self, cve_id: str) -> List[Dict]:
        """Lifecycle events for one CVE, chronological order. Feeds --timeline
        and days_to_exploit(). Same plain SELECT shape as get_collections_for_cve().
        """
        rows = self.conn.execute("""
            SELECT event_type, event_date, detail FROM cve_events
            WHERE cve_id = ?
            ORDER BY event_date ASC, id ASC
        """, (cve_id,)).fetchall()
        return [
            {
                'event_type': row['event_type'],
                'event_date': row['event_date'],
                'detail': json.loads(row['detail']) if row['detail'] else {},
            }
            for row in rows
        ]

    def get_events_for_cves(self, cve_ids: List[str]) -> Dict[str, List[Dict]]:
        """Batched get_events_for_cve() for --velocity's candidate-row set —
        one query instead of one per CVE. Feeds days_to_exploit() per row.
        A CVE with no events is simply absent from the result, not mapped
        to an empty list.
        """
        if not cve_ids:
            return {}
        placeholders = ','.join('?' * len(cve_ids))
        rows = self.conn.execute(f"""
            SELECT cve_id, event_type, event_date, detail FROM cve_events
            WHERE cve_id IN ({placeholders})
            ORDER BY event_date ASC, id ASC
        """, cve_ids).fetchall()
        grouped: Dict[str, List[Dict]] = {}
        for row in rows:
            grouped.setdefault(row['cve_id'], []).append({
                'event_type': row['event_type'],
                'event_date': row['event_date'],
                'detail': json.loads(row['detail']) if row['detail'] else {},
            })
        return grouped

    def get_cve_by_id(self, cve_id: str):
        """Return the single cves row for cve_id, or None if not found."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cves WHERE id = ?", (cve_id,))
        return cursor.fetchone()

    def mark_as_processed(self, cve_ids: List[str]):
        """Mark CVEs as processed.

        Writes a `processed` cve_events row only for CVEs that weren't
        already processed — re-running --mark-processed on a CVE that's
        already marked is a no-op timeline-wise, matching the
        transition-only pattern the collector's own events follow (no
        duplicate kev_added/poc_added on repeat runs either).

        The SELECT (which CVEs are newly transitioning) and the UPDATE are
        wrapped in one BEGIN IMMEDIATE transaction rather than run as two
        separate statements. A plain SELECT-then-UPDATE takes SQLite's
        write lock only at the UPDATE, so two concurrent reporter
        invocations marking overlapping CVE sets could otherwise both read
        processed=0 for the same CVE before either writes, and both log a
        `processed` event for what's really one transition. BEGIN
        IMMEDIATE takes the write lock up front instead, so a second
        concurrent call blocks (via the busy_timeout set in __enter__)
        until this one commits and sees the now-updated row.
        """
        if not cve_ids:
            return
        cursor = self.conn.cursor()
        placeholders = ','.join('?' * len(cve_ids))

        cursor.execute("BEGIN IMMEDIATE")
        try:
            newly_processed = [
                row['id'] for row in cursor.execute(
                    f"SELECT id FROM cves WHERE id IN ({placeholders}) AND processed = 0",
                    cve_ids,
                ).fetchall()
            ]

            cursor.execute(f"""
                UPDATE cves
                SET processed = 1
                WHERE id IN ({placeholders})
            """, cve_ids)

            for cve_id in newly_processed:
                record_event(self.conn, cve_id, 'processed')

            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
    
    def get_dashboard_stats(self) -> Dict:
        """Get comprehensive statistics for dashboard"""
        cursor = self.conn.cursor()
        
        # Overall stats
        cursor.execute("SELECT * FROM cve_stats")
        stats = cursor.fetchone()
        
        # Recent activity (last 24 hours)
        cutoff_24h = (datetime.now() - timedelta(hours=24)).isoformat()
        cursor.execute("SELECT COUNT(*) FROM cves WHERE first_seen > ?", (cutoff_24h,))
        new_24h = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cves WHERE last_updated_date > ?", (cutoff_24h,))
        updated_24h = cursor.fetchone()[0]
        
        # Top affected assets
        cursor.execute("""
            SELECT affected_assets, COUNT(*) as count
            FROM cves
            WHERE affected_assets IS NOT NULL
            GROUP BY affected_assets
            ORDER BY count DESC
            LIMIT 10
        """)
        top_assets = cursor.fetchall()
        
        # Recent critical/high CVEs with exploits
        cursor.execute("""
            SELECT COUNT(*) FROM cves
            WHERE has_known_exploit = 1
            AND base_severity IN ('CRITICAL', 'HIGH')
            AND affects_infrastructure = 1
        """)
        critical_exploits = cursor.fetchone()[0]
        
        return {
            'total_cves': stats[0],
            'critical': stats[1],
            'high': stats[2],
            'medium': stats[3],
            'low': stats[4],
            'with_exploits': stats[5],
            'relevant': stats[6],
            'unprocessed': stats[7],
            'with_pocs': stats[8],
            'new_24h': new_24h,
            'updated_24h': updated_24h,
            'top_assets': top_assets,
            'critical_exploits': critical_exploits
        }
    
    def _parse_json_field(self, value) -> list:
        """Safely parse a JSON string field from the DB; returns [] on None or error.

        Note: format_cve_text() and format_cve_json() use equivalent inline guards.
        This helper is used by format_cve_detail() and format_cve_detail_json() only;
        the existing formatters are left unchanged to avoid scope creep.
        """
        if not value:
            return []
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []

    def _row_to_export_dict(self, cve: sqlite3.Row) -> Dict:
        """Convert a full DB row into an export-ready dict.

        All CVE_COLUMNS are included with their raw DB values (no bool()
        coercion — has_known_exploit etc. stay as 0/1 ints, matching the
        --format json contract) except for JSON_ARRAY_COLUMNS, which are
        parsed into native lists. This is the single source of truth behind
        --format json/csv/html so the three formats never drift from each
        other's idea of "the full record".
        """
        row = dict(cve)
        for col in JSON_ARRAY_COLUMNS:
            row[col] = self._parse_json_field(row.get(col))
        return row

    def format_list_text(self, cves: List[sqlite3.Row], title: str,
                          collection_info: Optional[Dict] = None,
                          velocity_map: Optional[Dict[str, timedelta]] = None) -> str:
        """Render a list of CVEs as a banner + per-CVE text report.

        When collection_info is given ({name, description, member_count,
        filters}), renders the specialized COLLECTION/Description/Members/
        Filters banner from the collections feature instead of the generic
        banner. `filters` is a pre-joined string of any *other* active
        filters (deliberately not derived from `title`, which — when a
        collection is active — already has "Collection: X |" prefixed onto
        it for the csv/html headers; reusing it here would duplicate the
        collection name in the Filters line). When collection_info is None
        (the default), behavior is unchanged from before that feature
        existed.

        velocity_map (cve_id -> timedelta) is None on an ordinary run;
        format_cve_text() then renders exactly as before this feature
        existed. When set (--velocity/--max-days-to-exploit), each CVE's
        entry gets an "Exploited: N days after disclosure" line for the
        rows present in the map.
        """
        if not cves and collection_info is None:
            return "No CVEs found matching the specified filters."

        output = []
        output.append("=" * 70)
        if collection_info:
            output.append(f"COLLECTION: {collection_info['name']}")
            if collection_info.get('description'):
                output.append(f"Description: {collection_info['description']}")
            filters_str = collection_info.get('filters') or "none"
            output.append(f"Members: {collection_info['member_count']} CVEs  |  Filters: {filters_str}")
            output.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            output.append(title)
            output.append("=" * 70)
            output.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            output.append(f"Total CVEs: {len(cves)}")
        output.append("=" * 70)
        output.append("")

        if not cves:
            output.append("No CVEs found matching the specified filters.")
        for cve in cves:
            time_to_exploit = velocity_map.get(cve['id']) if velocity_map else None
            output.append(self.format_cve_text(cve, time_to_exploit=time_to_exploit))
            output.append("-" * 70)

        return "\n".join(output)

    def format_list_json(self, cves: List[sqlite3.Row], filter_meta: Dict) -> str:
        """Render a list of CVEs as the structured JSON export.

        Shape: {generated_at, filter, count, cves: [...]} with every CVE
        expanded to its full column set via _row_to_export_dict(). Valid
        (non-crashing) on an empty result set: count=0, cves=[].
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'filter': filter_meta,
            'count': len(cves),
            'cves': [self._row_to_export_dict(cve) for cve in cves],
        }
        return json.dumps(report, indent=2, default=str)

    def format_list_csv(self, cves: List[sqlite3.Row], title: str) -> str:
        """Render a list of CVEs as a flat CSV with a leading comment line.

        Header row always uses the full CVE_COLUMNS set (DB column names) so
        the file has a predictable shape even on an empty result set.
        Multi-value (JSON array) fields are pipe-delimited. Every cell is
        passed through _csv_safe() to neutralize spreadsheet formula
        injection; csv.writer's default QUOTE_MINIMAL handles commas/quotes/
        newlines (e.g. in `description`).
        """
        generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        buf = io.StringIO()
        buf.write(f"# Generated: {generated}  |  Filter: {title}  |  Count: {len(cves)}\n")

        writer = csv.writer(buf)
        writer.writerow(CVE_COLUMNS)

        for cve in cves:
            row = self._row_to_export_dict(cve)
            values = []
            for col in CVE_COLUMNS:
                val = row.get(col)
                if col in JSON_ARRAY_COLUMNS:
                    val = '|'.join(val) if val else ''
                values.append(_csv_safe(val))
            writer.writerow(values)

        return buf.getvalue()

    _HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ThreatPulse CVE Report</title>
<style>
  :root {
    --bg: #0f1117; --panel: #1a1d29; --border: #2a2e3d; --text: #e5e7eb;
    --muted: #9aa1b1; --accent: #6ea8ff;
    --critical: #ff5c5c; --high: #ff9f43; --medium: #ffd93d; --low: #9aa1b1;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    margin: 0; padding: 24px;
  }
  h1 { margin: 0 0 4px 0; font-size: 22px; }
  .meta { color: var(--muted); margin: 0 0 20px 0; font-size: 13px; }
  #search {
    width: 100%; max-width: 420px; padding: 8px 12px; margin-bottom: 16px;
    background: var(--panel); border: 1px solid var(--border); border-radius: 6px;
    color: var(--text); font-size: 14px;
  }
  table { width: 100%; border-collapse: collapse; background: var(--panel);
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border);
    font-size: 13px; vertical-align: top; }
  th { cursor: pointer; user-select: none; color: var(--muted); font-weight: 600;
    white-space: nowrap; }
  th:hover { color: var(--text); }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: rgba(110,168,255,0.06); }
  tbody tr.empty:hover { background: none; cursor: default; }
  .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px;
    font-weight: 600; margin-right: 4px; }
  .badge.exploit { background: rgba(255,92,92,0.15); color: var(--critical); }
  .badge.poc { background: rgba(110,168,255,0.15); color: var(--accent); }
  .sev { font-weight: 700; }
  .sev.CRITICAL { color: var(--critical); }
  .sev.HIGH { color: var(--high); }
  .sev.MEDIUM { color: var(--medium); }
  .sev.LOW, .sev.NONE { color: var(--low); }
  .detail-row td { background: rgba(255,255,255,0.02); white-space: pre-wrap; }
  .detail-row a { color: var(--accent); }
  .detail-row .poc-link { display: block; margin-top: 4px; word-break: break-all; }
</style>
</head>
<body>
<h1>ThreatPulse CVE Report</h1>
<p class="meta">___HEADER___</p>
<input id="search" type="text" placeholder="Search CVEs...">
<table id="cve-table">
  <thead>
    <tr>
      <th data-key="id">ID</th>
      <th data-key="base_severity">Severity</th>
      <th data-key="base_score">Score</th>
      <th data-key="published_date">Published</th>
      <th data-key="relevance_score">Relevance</th>
      <th>Flags</th>
    </tr>
  </thead>
  <tbody id="cve-tbody"></tbody>
</table>
<script>
const DATA = ___DATA_JSON___;

function el(tag, opts) {
  const node = document.createElement(tag);
  if (opts) {
    if (opts.className) node.className = opts.className;
    if (opts.text !== undefined) node.textContent = opts.text;
  }
  return node;
}

function safeLink(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      const a = el('a', { text: url });
      a.href = url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.className = 'poc-link';
      return a;
    }
  } catch (e) { /* fall through to plain text */ }
  return el('span', { text: url + ' (blocked: unsupported URL scheme)', className: 'poc-link' });
}

function buildDetailContent(cve) {
  const wrap = el('div');
  wrap.appendChild(el('div', { text: cve.description || '(no description)' }));
  const urls = Array.isArray(cve.poc_urls) ? cve.poc_urls : [];
  urls.forEach(u => wrap.appendChild(safeLink(u)));
  return wrap;
}

function buildRow(cve) {
  const tr = el('tr');

  const idTd = el('td', { text: cve.id });
  const sevTd = el('td');
  const sevSpan = el('span', { text: cve.base_severity || 'N/A', className: 'sev ' + (cve.base_severity || 'NONE') });
  sevTd.appendChild(sevSpan);
  const scoreTd = el('td', { text: cve.base_score != null ? String(cve.base_score) : 'N/A' });
  const pubTd = el('td', { text: cve.published_date || '' });
  const relTd = el('td', { text: cve.relevance_score != null ? String(cve.relevance_score) : '' });

  const flagsTd = el('td');
  if (cve.has_known_exploit) flagsTd.appendChild(el('span', { text: 'EXPLOIT', className: 'badge exploit' }));
  if (cve.has_poc) flagsTd.appendChild(el('span', { text: 'POC', className: 'badge poc' }));

  tr.appendChild(idTd); tr.appendChild(sevTd); tr.appendChild(scoreTd);
  tr.appendChild(pubTd); tr.appendChild(relTd); tr.appendChild(flagsTd);

  const detailTr = el('tr', { className: 'detail-row' });
  detailTr.style.display = 'none';
  const detailTd = el('td');
  detailTd.colSpan = 6;
  detailTd.appendChild(buildDetailContent(cve));
  detailTr.appendChild(detailTd);

  tr.addEventListener('click', () => {
    detailTr.style.display = detailTr.style.display === 'none' ? '' : 'none';
  });

  return [tr, detailTr];
}

let sortKey = null;
let sortAsc = true;

function render(rows) {
  const tbody = document.getElementById('cve-tbody');
  tbody.textContent = '';
  if (rows.length === 0) {
    const tr = el('tr', { className: 'empty' });
    const td = el('td', { text: 'No results' });
    td.colSpan = 6;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  rows.forEach(cve => {
    const [tr, detailTr] = buildRow(cve);
    tbody.appendChild(tr);
    tbody.appendChild(detailTr);
  });
}

function applyFilterAndSort() {
  const q = document.getElementById('search').value.trim().toLowerCase();
  let rows = DATA.filter(cve => {
    if (!q) return true;
    return JSON.stringify(cve).toLowerCase().includes(q);
  });
  if (sortKey) {
    rows = rows.slice().sort((a, b) => {
      const av = a[sortKey], bv = b[sortKey];
      if (av == null) return 1;
      if (bv == null) return -1;
      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    });
  }
  render(rows);
}

document.getElementById('search').addEventListener('input', applyFilterAndSort);

document.querySelectorAll('th[data-key]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.getAttribute('data-key');
    if (sortKey === key) { sortAsc = !sortAsc; } else { sortKey = key; sortAsc = true; }
    applyFilterAndSort();
  });
});

applyFilterAndSort();
</script>
</body>
</html>
"""

    def format_list_html(self, cves: List[sqlite3.Row], title: str) -> str:
        """Render a list of CVEs as a self-contained, sortable/searchable HTML table.

        Security notes:
          - The embedded JSON blob has '</' escaped to '<\\/' before being
            written into the <script> tag, so a description containing a
            literal "</script>" sequence can't terminate the script early
            and inject live markup.
          - All per-row rendering in the client-side JS uses
            document.createElement()/.textContent — never innerHTML or
            string-built HTML — for any DB-derived value.
          - poc_urls entries are only rendered as clickable links after the
            JS validates the URL scheme is http/https; anything else
            (javascript:, data:, malformed) renders as inert text.
        """
        if len(cves) > 1000:
            print(
                f"Warning: --format html with {len(cves)} CVEs may render slowly in a browser.",
                file=sys.stderr,
            )

        rows_data = [self._row_to_export_dict(cve) for cve in cves]
        data_json = json.dumps(rows_data, default=str).replace('</', '<\\/')
        generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # title may embed free-form CLI input (e.g. --asset); escape before
        # inserting into the static HTML shell since ___HEADER___ lands
        # directly in markup, not in a JS/JSON context like DATA above.
        header = html_escape_module.escape(
            f"Generated: {generated} | Filter: {title} | {len(cves)} CVEs"
        )

        # Single pass over the pristine template via re.sub's callback form —
        # see _HTML_TOKEN_RE's comment for why chained str.replace() calls
        # are unsafe here (a data/header value containing a token's literal
        # text would get corrupted by a subsequent replace).
        replacements = {'___DATA_JSON___': data_json, '___HEADER___': header}
        return _HTML_TOKEN_RE.sub(lambda m: replacements[m.group(0)], self._HTML_TEMPLATE)

    def format_cve_text(self, cve: sqlite3.Row, time_to_exploit: Optional[timedelta] = None) -> str:
        """Format a single CVE as text.

        time_to_exploit is None on an ordinary run (default) and this
        renders exactly as it did before the timeline feature existed.
        Passed in (from --velocity/--max-days-to-exploit's velocity_map)
        it adds one extra line. Named to avoid shadowing the module-level
        days_to_exploit() function that computes it.
        """
        exploit_flag = "🚨 EXPLOIT AVAILABLE" if cve['has_known_exploit'] else ""

        output = []
        output.append(f"CVE: {cve['id']} {exploit_flag}")
        output.append(f"Severity: {cve['base_severity']} (Score: {cve['base_score']})")
        output.append(f"Published: {cve['published_date']}")

        if cve['affects_infrastructure']:
            assets = json.loads(cve['affected_assets']) if cve['affected_assets'] else []
            categories = json.loads(cve['affected_categories']) if cve['affected_categories'] else []
            output.append(f"Affects Assets: {', '.join(assets)}")
            output.append(f"Categories: {', '.join(categories)}")
            output.append(f"Relevance Score: {cve['relevance_score']:.1f}")

        if cve['has_known_exploit']:
            output.append("⚠️  KNOWN EXPLOIT - IMMEDIATE PATCHING REQUIRED")

        if time_to_exploit is not None:
            output.append(f"Exploited: {_format_duration(time_to_exploit)} after disclosure")

        if cve['has_poc']:
            poc_urls = json.loads(cve['poc_urls']) if cve['poc_urls'] else []
            poc_sources = json.loads(cve['poc_source']) if cve['poc_source'] else []
            output.append(f"POC Available: Yes (Sources: {', '.join(poc_sources)})")
            for url in poc_urls:
                output.append(f"  POC: {url}")

        if cve['last_updated_date']:
            output.append(f"Last Updated: {cve['last_updated_date']}")
        
        output.append(f"Description: {cve['description']}")
        output.append("")
        
        return "\n".join(output)
    
    def format_cve_json(self, cve: sqlite3.Row) -> Dict:
        """Format a single CVE as JSON"""
        return {
            'id': cve['id'],
            'description': cve['description'],
            'published_date': cve['published_date'],
            'base_score': cve['base_score'],
            'base_severity': cve['base_severity'],
            'affects_infrastructure': bool(cve['affects_infrastructure']),
            'affected_categories': json.loads(cve['affected_categories']) if cve['affected_categories'] else None,
            'affected_assets': json.loads(cve['affected_assets']) if cve['affected_assets'] else None,
            'relevance_score': cve['relevance_score'],
            'has_known_exploit': bool(cve['has_known_exploit']),
            'has_poc': bool(cve['has_poc']),
            'poc_urls': json.loads(cve['poc_urls']) if cve['poc_urls'] else None,
            'poc_source': json.loads(cve['poc_source']) if cve['poc_source'] else None,
            'first_seen': cve['first_seen'],
            'last_checked': cve['last_checked'],
            'last_updated_date': cve['last_updated_date']
        }
    
    def format_cve_detail(self, cve: sqlite3.Row, collections: Optional[List[str]] = None,
                           lifecycle_events: Optional[List[Dict]] = None) -> str:
        """Format a single CVE as a full detail view for terminal output: seven
        sections, plus an eighth LIFECYCLE TIMELINE section when --timeline
        was requested.

        collections is the list of collection names this CVE belongs to
        (from get_collections_for_cve()); shown in the IDENTITY section.

        lifecycle_events controls the optional TIMELINE section: None (the
        default) omits it entirely for the plain --cve view; a list (from
        get_events_for_cve() — empty or not) renders it, including the
        "no event history" case for CVEs ingested before this feature or
        with no events at all.
        """
        SEP  = "=" * 70
        DASH = "-" * 70
        generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        poc_urls      = self._parse_json_field(cve['poc_urls'])
        poc_sources   = self._parse_json_field(cve['poc_source'])
        categories    = self._parse_json_field(cve['affected_categories'])
        assets        = self._parse_json_field(cve['affected_assets'])

        out = []

        # ── 1. HEADER ──────────────────────────────────────────────────────────
        out.append(SEP)
        out.append(f"CVE DETAIL: {cve['id']}")
        out.append(f"Generated: {generated}")
        out.append(SEP)
        out.append("")

        # ── 2. IDENTITY ────────────────────────────────────────────────────────
        out.append("IDENTITY")
        out.append(DASH)
        out.append(f"CVE ID:          {cve['id']}")
        severity  = cve['base_severity'] or "N/A"
        score     = cve['base_score'] if cve['base_score'] is not None else "N/A"
        out.append(f"Severity:        {severity}  (CVSS Score: {score})")
        out.append(f"Published:       {cve['published_date']}")
        out.append(f"Last Updated:    {cve['last_updated_date'] or '(not populated)'}")
        out.append(f"Collections:     {', '.join(collections) if collections else '(none)'}")
        out.append("")

        # ── 3. DESCRIPTION ─────────────────────────────────────────────────────
        out.append("DESCRIPTION")
        out.append(DASH)
        description = cve['description'] or "(no description available)"
        out.append(textwrap.fill(description, width=70))
        out.append("")

        # ── 4. EXPLOIT STATUS ──────────────────────────────────────────────────
        out.append("EXPLOIT STATUS")
        out.append(DASH)
        if cve['has_known_exploit']:
            out.append("Known Exploit:   YES  ⚠️  KNOWN EXPLOIT — IMMEDIATE PATCHING REQUIRED")
        else:
            out.append("Known Exploit:   NO")
        exploit_date = cve['exploit_added_date'] or "(not populated)"
        out.append(f"CISA KEV:        {exploit_date}")
        if cve['has_poc']:
            sources_str = ', '.join(poc_sources) if poc_sources else "unknown"
            out.append(f"POC Available:   YES  (Sources: {sources_str})")
            for url in poc_urls:
                out.append(f"  → {url}")
        else:
            out.append("POC Available:   NO")
        out.append("")

        # ── 5. KEYWORD RELEVANCE ───────────────────────────────────────────────
        out.append("KEYWORD RELEVANCE")
        out.append(DASH)
        if cve['affects_infrastructure']:
            out.append("Matches Asset Inventory:  YES")
            out.append(f"Matched Categories:       {', '.join(categories) if categories else '(none)'}")
            out.append(f"Matched Keywords:         {', '.join(assets) if assets else '(none)'}")
            if cve['base_score'] is not None and cve['relevance_score'] is not None:
                weight = (cve['relevance_score'] / cve['base_score']
                          if cve['base_score'] else 0)
                out.append(
                    f"Relevance Score:          {cve['relevance_score']}"
                    f"  (CVSS {cve['base_score']} × category weight {weight:.1f})"
                )
            else:
                out.append(f"Relevance Score:          {cve['relevance_score']}")
        else:
            out.append("Matches Asset Inventory:  NO")
            out.append("(No configured keywords matched the CVE description)")
        out.append("")

        # ── 6. PROCESSING HISTORY ──────────────────────────────────────────────
        out.append("PROCESSING HISTORY")
        out.append(DASH)

        events = []
        if cve['first_seen']:
            events.append((cve['first_seen'], "First ingested by collector"))
        if cve['last_updated_date']:
            events.append((cve['last_updated_date'],
                           "Data updated  (score or exploit/POC status changed)"))
        if cve['last_checked']:
            events.append((cve['last_checked'],
                           "Last checked by collector  (no changes)"))

        events.sort(key=lambda e: e[0])
        for ts, label in events:
            out.append(f"  {ts}  {label}")

        if cve['processed']:
            out.append(f"  {cve['last_updated_date'] or 'unknown'}         Marked as processed")
        else:
            out.append("  [unreviewed]         Not yet marked as processed")
        out.append("")

        # ── 7. LIFECYCLE TIMELINE (only when --timeline was requested) ─────────
        if lifecycle_events is not None:
            out.append("LIFECYCLE TIMELINE")
            out.append(DASH)
            if not lifecycle_events:
                out.append("  No event history available "
                            "(this CVE predates the timeline feature, or has had "
                            "no lifecycle transitions recorded since).")
            else:
                event_labels = {
                    'ingested':     'First seen',
                    'cvss_changed': 'CVSS updated',
                    'kev_added':    'Added to CISA KEV list',
                    'poc_added':    'POC published',
                    'poc_updated':  'New POC URL added',
                    'processed':    'Marked as processed',
                }
                for ev in lifecycle_events:
                    detail = ev['detail'] or {}
                    etype = ev['event_type']
                    label = event_labels.get(etype, etype)
                    if etype == 'ingested':
                        extra = f" — CVSS {detail.get('cvss', 'N/A')} {detail.get('severity', '')}".rstrip()
                    elif etype == 'cvss_changed':
                        extra = f": {detail.get('from', '?')} → {detail.get('to', '?')}"
                    elif etype == 'kev_added':
                        extra = f" ({detail.get('source', 'cisa_kev')})"
                    elif etype == 'poc_added':
                        sources = detail.get('source') or []
                        extra = f" ({', '.join(sources)})" if sources else ""
                    elif etype == 'poc_updated':
                        extra = f": {detail.get('new_url', '')}"
                    else:
                        extra = ""
                    out.append(f"  {ev['event_date']}  [{etype:<13}] {label}{extra}")

                out.append("")
                kev_event = next((e for e in lifecycle_events if e['event_type'] == 'kev_added'), None)
                poc_event = next((e for e in lifecycle_events if e['event_type'] == 'poc_added'), None)
                if kev_event is not None:
                    d = days_to_exploit(cve['published_date'], [kev_event])
                    out.append(f"Time to KEV:        {_format_duration(d)} after disclosure"
                               if d is not None else "Time to KEV:        (could not compute)")
                if poc_event is not None:
                    d = days_to_exploit(cve['published_date'], [poc_event])
                    out.append(f"Time to POC:        {_format_duration(d)} after disclosure"
                               if d is not None else "Time to POC:        (could not compute)")
                if kev_event is None and poc_event is None:
                    out.append("Time to exploit:    not yet exploited")
            out.append("")

        # ── 8. ALL ENRICHMENT DATA ─────────────────────────────────────────────
        out.append("ALL ENRICHMENT DATA")
        out.append(DASH)

        row = dict(cve)
        json_fields = {'poc_urls', 'poc_source', 'affected_categories', 'affected_assets'}
        for col, val in row.items():
            if col in json_fields:
                parsed = self._parse_json_field(val)
                if len(parsed) > 1:
                    first, *rest = parsed
                    out.append(f"{col + ':':30} [\"{first}\",")
                    for item in rest[:-1]:
                        out.append(f"{'':31}  \"{item}\",")
                    out.append(f"{'':31}  \"{rest[-1]}\"]")
                else:
                    out.append(f"{col + ':':30} {json.dumps(parsed)}")
            elif col == 'processed':
                label = "(reviewed)" if val else "(unreviewed)"
                out.append(f"{col + ':':30} {val}  {label}")
            elif col == 'exploit_added_date' and val is None:
                out.append(f"{col + ':':30} (not populated)")
            else:
                out.append(f"{col + ':':30} {val}")

        out.append(SEP)
        return "\n".join(out)

    def format_cve_detail_json(self, cve: sqlite3.Row) -> str:
        """Return a JSON string of the full CVE record with all 18 columns plus generated_at.

        Returns a json.dumps() string, not a Dict — distinct from format_cve_json() which
        returns a Dict and omits several columns (exploit_added_date, processed, last_checked).
        """
        generated_at = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        record = dict(cve)  # sqlite3.Row → dict, captures all 18 columns
        for field in ('poc_urls', 'poc_source', 'affected_categories', 'affected_assets'):
            record[field] = self._parse_json_field(record.get(field))
        record['generated_at'] = generated_at
        return json.dumps(record, indent=2, default=str)

    def generate_report(self, cves: List[sqlite3.Row], title: str, filter_meta: Dict,
                       output_format: str = 'text', filename: Optional[str] = None,
                       collection_info: Optional[Dict] = None,
                       velocity_map: Optional[Dict[str, timedelta]] = None):
        """Dispatch to the appropriate format_list_* method and write the result.

        filter_meta is only consumed by the json format (it becomes the
        "filter" key); text/csv/html use the human-readable `title` string.
        collection_info is only consumed by the text format (see
        format_list_text) and is None outside the --collection + text case.
        velocity_map (cve_id -> timedelta, from --velocity/--max-days-to-exploit)
        is likewise text-only for v1 — json/csv/html output stay exactly as
        they were; --velocity/--max-days-to-exploit still correctly filter
        and sort `cves` for every format, just without a field explaining
        why for non-text output. See docs/features/TIMELINE_VIEW_FEATURE.md.
        """
        if output_format == 'json':
            output = self.format_list_json(cves, filter_meta)
        elif output_format == 'csv':
            output = self.format_list_csv(cves, title)
        elif output_format == 'html':
            output = self.format_list_html(cves, title)
        else:  # text
            output = self.format_list_text(cves, title, collection_info=collection_info,
                                            velocity_map=velocity_map)

        write_output(output, filename)

    def generate_dashboard(self) -> str:
        """Build the dashboard summary text and return it (does not print)."""
        stats = self.get_dashboard_stats()

        out = []
        out.append("=" * 70)
        out.append("THREATPULSE DASHBOARD")
        out.append("=" * 70)
        out.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        out.append("")

        out.append("OVERALL STATISTICS")
        out.append("-" * 70)
        out.append(f"Total CVEs in Database: {stats['total_cves']}")
        out.append(f"  ├─ Critical: {stats['critical']}")
        out.append(f"  ├─ High: {stats['high']}")
        out.append(f"  ├─ Medium: {stats['medium']}")
        out.append(f"  └─ Low: {stats['low']}")
        out.append("")
        out.append(f"CVEs with Known Exploits: {stats['with_exploits']}")
        out.append(f"CVEs with POC Exploits: {stats['with_pocs']}")
        out.append(f"Relevant to Infrastructure: {stats['relevant']}")
        out.append(f"Unprocessed CVEs: {stats['unprocessed']}")
        out.append("")

        out.append("RECENT ACTIVITY (24 HOURS)")
        out.append("-" * 70)
        out.append(f"New CVEs: {stats['new_24h']}")
        out.append(f"Updated CVEs: {stats['updated_24h']}")
        out.append("")

        out.append("⚠️  CRITICAL ALERTS")
        out.append("-" * 70)
        out.append(f"High/Critical CVEs with Exploits (Infrastructure): {stats['critical_exploits']}")
        if stats['critical_exploits'] > 0:
            out.append("   ⚠️  IMMEDIATE ACTION REQUIRED")
        out.append("")

        if stats['top_assets']:
            out.append("TOP AFFECTED ASSETS")
            out.append("-" * 70)
            for asset_data, count in stats['top_assets'][:5]:
                try:
                    assets = json.loads(asset_data)
                    out.append(f"  {', '.join(assets)}: {count} CVEs")
                except (json.JSONDecodeError, TypeError):
                    pass
            out.append("")

        out.append("=" * 70)
        return "\n".join(out)


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


def _resolve_collection_id(reporter: 'CVEReporter', name: str) -> int:
    """Resolve a collection name to its id, or print an error and exit 1.

    Shared by every name-based collection entry point (--collection,
    --add-to-collection, --remove-from-collection, --delete-collection,
    --rename-collection's OLD) so they all fail identically on an unknown name.
    """
    collection_id = reporter.get_collection_id(name)
    if collection_id is None:
        print(
            f"Collection not found: {name}\n"
            f"Run --list-collections to see available collections.",
            file=sys.stderr
        )
        sys.exit(1)
    return collection_id


def main():
    parser = argparse.ArgumentParser(
        description='ThreatPulse - Continuous CVE threat monitoring and reporting tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --new                          # Show new CVEs (last 24h)
  %(prog)s --new --hours 48              # Show new CVEs (last 48h)
  %(prog)s --updated                      # Show updated CVEs
  %(prog)s --unprocessed                  # Show unprocessed CVEs
  %(prog)s --critical                     # Show critical CVEs
  %(prog)s --severity HIGH,CRITICAL       # Show high and critical CVEs
  %(prog)s --asset nginx                  # Show CVEs affecting nginx
  %(prog)s --category web_servers         # All CVEs for a category
  %(prog)s --exploits-only                # All CVEs with known exploits
  %(prog)s --pocs-only                    # All CVEs with POC exploits
  %(prog)s --relevant                     # All relevant CVEs
  %(prog)s --since 2024-01-01            # CVEs since date

Composable examples (flags combine with AND logic):
  %(prog)s --new --critical                            # New critical CVEs
  %(prog)s --new --category databases --exploits-only  # New DB CVEs with exploits
  %(prog)s --unprocessed --severity CRITICAL,HIGH      # Unprocessed high-severity
  %(prog)s --since 2026-01-01 --category network_devices  # Network CVEs since date
  %(prog)s --relevant --exploits-only                  # Infra-relevant with exploits
  %(prog)s --new --pocs-only                           # New CVEs that have POCs

  Note: when multiple primary modes are supplied (e.g. --new --updated),
  the first one wins silently. Use one primary mode at a time.

Output options:
  %(prog)s --new --format json           # Output as JSON
  %(prog)s --new --format csv            # Output as CSV
  %(prog)s --new --format html --output report.html  # Self-contained HTML file
  %(prog)s --new --output report.txt     # Save to file
  %(prog)s --new --mark-processed        # Mark shown CVEs as processed
  %(prog)s --dashboard                    # Show dashboard summary (text only)
  %(prog)s --cve CVE-2026-12345 --format csv  # Single CVE detail as CSV/HTML too

Collections / Watchlists:
  %(prog)s --create-collection "Log4j variants" --description "Tracking Log4Shell family"
  %(prog)s --list-collections
  %(prog)s --add-to-collection "Log4j variants" CVE-2021-44228 CVE-2021-45046
  %(prog)s --remove-from-collection "Log4j variants" CVE-2021-44228
  %(prog)s --rename-collection "Log4j variants" "Log4Shell Family"
  %(prog)s --delete-collection "Log4j variants"
  %(prog)s --collection "Q3 Red Team" --exploits-only   # Composes with any filter
  %(prog)s --collection "Log4j variants" --mark-processed

Cron usage:
  */30 * * * * /usr/bin/python /opt/threatpulse/cve_reporter.py \\
      --new --format json \\
      --output /var/reports/cves.json >> /var/log/threatpulse.log 2>&1
        """
    )
    
    # Report type arguments
    parser.add_argument('--new', action='store_true', 
                       help='Show new CVEs')
    parser.add_argument('--updated', action='store_true',
                       help='Show recently updated CVEs')
    parser.add_argument('--unprocessed', action='store_true',
                       help='Show unprocessed CVEs')
    severity_group = parser.add_mutually_exclusive_group()
    severity_group.add_argument('--critical', action='store_true',
                       help='Show critical CVEs')
    severity_group.add_argument('--severity', type=str,
                       help='Severity levels (comma-separated: CRITICAL,HIGH,MEDIUM,LOW)')
    asset_group = parser.add_mutually_exclusive_group()
    asset_group.add_argument('--asset', type=str,
                       help='Filter by asset name')
    asset_group.add_argument('--category', type=str,
                       help='Filter by asset category (e.g. web_servers, databases)')
    parser.add_argument('--with-exploits', action='store_true',
                       help='Deprecated alias for --exploits-only; use --exploits-only instead')
    parser.add_argument('--exploits-only', action='store_true',
                       help='Show CVEs with known exploits (composable with any base mode)')
    parser.add_argument('--pocs-only', action='store_true',
                       help='Show CVEs with POC exploits (composable with any base mode)')
    parser.add_argument('--with-pocs', action='store_true',
                       help='Deprecated alias for --pocs-only; use --pocs-only instead')
    parser.add_argument('--relevant', action='store_true',
                       help='Show all CVEs relevant to infrastructure')
    parser.add_argument('--since', type=str,
                       help='Show CVEs since date (YYYY-MM-DD)')
    parser.add_argument('--dashboard', action='store_true',
                       help='Show dashboard summary')
    parser.add_argument('--cve', type=str, metavar='CVE-ID',
                       help='Display full detail for a specific CVE ID (e.g. CVE-2026-12345)')

    # Collections / Watchlists (see docs/features/COLLECTIONS_WATCHLISTS_FEATURE.md)
    parser.add_argument('--collection', type=str, metavar='NAME',
                       help='Filter: show only CVEs in this named collection (composable with any other filter)')
    parser.add_argument('--create-collection', type=str, metavar='NAME',
                       help='Create a new collection')
    parser.add_argument('--description', type=str,
                       help='Optional description for --create-collection')
    parser.add_argument('--list-collections', action='store_true',
                       help='List all collections with member counts')
    parser.add_argument('--add-to-collection', nargs='+', metavar=('NAME', 'CVE_ID'),
                       help='Add one or more CVEs to a collection')
    parser.add_argument('--remove-from-collection', nargs=2, metavar=('NAME', 'CVE_ID'),
                       help='Remove a CVE from a collection')
    parser.add_argument('--delete-collection', type=str, metavar='NAME',
                       help='Delete a collection (does not delete the CVEs themselves)')
    parser.add_argument('--rename-collection', nargs=2, metavar=('OLD', 'NEW'),
                       help='Rename a collection')

    # Timeline / velocity (see docs/features/TIMELINE_VIEW_FEATURE.md)
    parser.add_argument('--timeline', action='store_true',
                       help='Show the lifecycle event log for a specific CVE (requires --cve; --format text only)')
    parser.add_argument('--velocity', action='store_true',
                       help='Sort results by time from disclosure to first exploit event (fastest first)')
    parser.add_argument('--max-days-to-exploit', type=int, metavar='N',
                       help='Show only CVEs exploited within N days of NVD publication '
                            '(composable with any base mode; independent of --velocity)')

    # Options
    parser.add_argument('--hours', type=int, default=24,
                       help='Hours to look back (default: 24)')
    parser.add_argument('--format', choices=['text', 'json', 'csv', 'html'], default='text',
                       help='Output format: text, json, csv, or html (default: text). '
                            '--dashboard currently supports text only.')
    parser.add_argument('--output', type=str,
                       help='Output filename (default: stdout)')
    parser.add_argument('--mark-processed', action='store_true',
                       help='Mark displayed CVEs as processed')
    
    args = parser.parse_args()

    # --timeline only means anything alongside --cve (it extends the single-CVE
    # detail view); without --cve it would otherwise be silently ignored by
    # falling through to the filtered-list path below, which is worse than
    # failing loudly here.
    if args.timeline and not args.cve:
        print("Error: --timeline requires --cve <CVE-ID>.", file=sys.stderr)
        sys.exit(1)

    # The collection-management mutation actions never consume --output (per
    # the doc's CLI design, they print a plain confirmation/warning); route
    # around them so a stray/invalid --output value doesn't spuriously block
    # a command that would never have touched it.
    _uses_output = not any([
        args.create_collection, args.add_to_collection,
        args.remove_from_collection, args.delete_collection, args.rename_collection,
    ])

    # Fail fast on an unwritable --output path, before any report is generated,
    # for every mode below that actually writes to it (--cve, --dashboard,
    # --list-collections, filtered-query).
    if args.output and _uses_output:
        _check_output_writable(args.output)

    # --- Collection management actions ---
    # Priority-checked at the top of main(), same convention as --cve/--dashboard
    # below (no formal argparse mutex group — first recognized flag wins).

    if args.create_collection:
        with CVEReporter() as reporter:
            if reporter.get_collection_id(args.create_collection) is not None:
                print(f"Collection already exists: {args.create_collection}", file=sys.stderr)
                sys.exit(1)
            reporter.create_collection(args.create_collection, args.description)
            print(f"Created collection '{args.create_collection}'")
        sys.exit(0)

    if args.list_collections:
        if args.format != 'text':
            print(
                "Error: --list-collections currently only supports --format text "
                "(json/csv/html are not yet implemented for --list-collections).",
                file=sys.stderr,
            )
            sys.exit(1)
        with CVEReporter() as reporter:
            collections = reporter.list_collections()
            if not collections:
                write_output(
                    "No collections found. Create one with --create-collection <name>.",
                    args.output,
                )
                sys.exit(0)
            lines = ["COLLECTIONS", "=" * 70]
            name_width = max(len(c['name']) for c in collections)
            for c in collections:
                line = f"  {c['name'].ljust(name_width)}   {c['member_count']:>3} CVEs   Created {c['created_at']}"
                if c['description']:
                    line += f'   "{c["description"]}"'
                lines.append(line)
            lines.append("=" * 70)
            lines.append(f"Total: {len(collections)} collections")
            write_output("\n".join(lines), args.output)
        sys.exit(0)

    if args.add_to_collection:
        if len(args.add_to_collection) < 2:
            print(
                "Error: --add-to-collection requires a collection name and at least one CVE ID.",
                file=sys.stderr,
            )
            sys.exit(1)
        name, raw_ids = args.add_to_collection[0], args.add_to_collection[1:]
        with CVEReporter() as reporter:
            collection_id = _resolve_collection_id(reporter, name)
            cve_ids = [normalize_cve_id(c) for c in raw_ids]
            added, skipped = reporter.add_to_collection(collection_id, cve_ids)
            for cve_id in skipped:
                print(f"{cve_id} not found in database — skipped", file=sys.stderr)
            print(f"Added {len(added)} CVE(s) to '{name}'")
        sys.exit(0)

    if args.remove_from_collection:
        name, raw_id = args.remove_from_collection
        cve_id = normalize_cve_id(raw_id)
        with CVEReporter() as reporter:
            collection_id = _resolve_collection_id(reporter, name)
            removed = reporter.remove_from_collection(collection_id, cve_id)
            if removed:
                print(f"Removed {cve_id} from '{name}'")
            else:
                print(f"{cve_id} was not in '{name}'")
        sys.exit(0)

    if args.delete_collection:
        with CVEReporter() as reporter:
            collection_id = _resolve_collection_id(reporter, args.delete_collection)
            reporter.delete_collection(collection_id)
            print(f"Deleted collection '{args.delete_collection}'")
        sys.exit(0)

    if args.rename_collection:
        old_name, new_name = args.rename_collection
        with CVEReporter() as reporter:
            collection_id = _resolve_collection_id(reporter, old_name)
            if reporter.get_collection_id(new_name) is not None:
                print(f"Collection already exists: {new_name}", file=sys.stderr)
                sys.exit(1)
            reporter.rename_collection(collection_id, new_name)
            print(f"Renamed '{old_name}' to '{new_name}'")
        sys.exit(0)

    # CVE detail lookup
    if args.cve:
        cve_id = normalize_cve_id(args.cve)
        with CVEReporter() as reporter:
            cve = reporter.get_cve_by_id(cve_id)
            if cve is None:
                print(f"No data found for {cve_id}.")
                print("Run the collector to ingest new CVEs: python cve_collector.py")
                sys.exit(1)
            if args.timeline and args.format != 'text':
                print(
                    "Error: --timeline currently only supports --format text "
                    "(json/csv/html are not yet implemented for --timeline).",
                    file=sys.stderr,
                )
                sys.exit(1)

            if args.format == 'json':
                output = reporter.format_cve_detail_json(cve)
            elif args.format == 'csv':
                output = reporter.format_list_csv([cve], f"CVE Detail: {cve_id}")
            elif args.format == 'html':
                output = reporter.format_list_html([cve], f"CVE Detail: {cve_id}")
            else:
                collections = reporter.get_collections_for_cve(cve_id)
                lifecycle_events = reporter.get_events_for_cve(cve_id) if args.timeline else None
                output = reporter.format_cve_detail(cve, collections=collections,
                                                      lifecycle_events=lifecycle_events)
            write_output(output, args.output)
            if args.mark_processed:
                reporter.mark_as_processed([cve_id])
                print(f"\nMarked {cve_id} as processed", file=sys.stderr)
        sys.exit(0)

    # Show dashboard if requested
    if args.dashboard:
        if args.format != 'text':
            print(
                "Error: --dashboard currently only supports --format text "
                "(json/csv/html are not yet implemented for --dashboard).",
                file=sys.stderr,
            )
            sys.exit(1)
        with CVEReporter() as reporter:
            write_output(reporter.generate_dashboard(), args.output)
        return
    
    # Determine which report to generate
    with CVEReporter() as reporter:

        # Validate --category early so invalid names exit before any query
        category = _validate_category(args.category) if args.category else None

        # Resolve --collection name to id the same way --category is validated
        # above; not-found uses the shared error (also used by the collection
        # management actions higher up in main()).
        collection_id = _resolve_collection_id(reporter, args.collection) if args.collection else None

        # Resolve deprecated aliases — OR with modern equivalents so that
        # --with-exploits and --with-pocs still work and pass the no_flags check
        exploits_only  = bool(args.exploits_only) or bool(args.with_exploits)
        pocs_only_flag = bool(args.pocs_only) or bool(args.with_pocs)

        severities = ([s.strip().upper() for s in args.severity.split(',')]
                      if args.severity else None)

        # Detect whether any actionable flag was supplied
        no_flags = not any([args.new, args.updated, args.unprocessed, args.relevant,
                            args.since, args.critical, severities, category,
                            args.asset, exploits_only, pocs_only_flag, collection_id])
        if no_flags:
            parser.print_help()
            return

        sql, params = reporter.build_filtered_query(
            hours=args.hours,
            new=args.new,
            updated=args.updated,
            unprocessed=args.unprocessed,
            relevant=args.relevant,
            since=args.since,
            critical=args.critical,
            severities=severities,
            category=category,
            asset=args.asset,
            exploits_only=exploits_only,
            pocs_only=pocs_only_flag,
            collection_id=collection_id,
        )

        cursor = reporter.conn.cursor()
        cursor.execute(sql, params)
        cves = cursor.fetchall()

        # Note: no early-exit on an empty result set here — each
        # format_list_* method (text/json/csv/html) produces valid,
        # non-crashing output for cves=[] per the output-formats spec's
        # edge-case table, and that has to hold for --output too.

        # --velocity / --max-days-to-exploit: compute time-to-exploit per row
        # (one batched events query for the whole candidate set, not one per
        # row) and use it to filter and/or sort `cves` before any format_*
        # method sees it. velocity_map stays None when neither flag is set,
        # so an ordinary run pays no extra query and format_cve_text()
        # renders exactly as it did before this feature existed.
        velocity_map: Optional[Dict[str, timedelta]] = None
        if args.velocity or args.max_days_to_exploit is not None:
            events_by_cve = reporter.get_events_for_cves([cve['id'] for cve in cves])
            velocity_map = {}
            for cve in cves:
                d = days_to_exploit(cve['published_date'], events_by_cve.get(cve['id'], []))
                if d is not None:
                    velocity_map[cve['id']] = d

            if args.max_days_to_exploit is not None:
                # Compare full elapsed time, not timedelta.days (which
                # floors) -- a CVE exploited in 7 days 23 hours must fail
                # --max-days-to-exploit 7, not slip through because .days
                # truncated it down to 7. _format_duration() still *shows*
                # that same CVE as "7 days" elsewhere (rounded for
                # readability); the filter itself has to be exact.
                max_seconds = args.max_days_to_exploit * 86400
                cves = [cve for cve in cves
                        if cve['id'] in velocity_map
                        and velocity_map[cve['id']].total_seconds() <= max_seconds]

            if args.velocity:
                # CVEs with no computable time-to-exploit sort last, per the
                # design doc's edge-case table.
                cves = sorted(cves, key=lambda cve: velocity_map.get(cve['id'], timedelta.max))

        # Dynamic title reflecting all active flags
        title_parts = []
        if args.new:
            title_parts.append(f"New (Last {args.hours}h)")
        elif args.updated:
            title_parts.append(f"Updated (Last {args.hours}h)")
        elif args.unprocessed:
            title_parts.append("Unprocessed")
        elif args.relevant:
            title_parts.append("Relevant")
        elif args.since:
            title_parts.append(f"Since {args.since}")

        if args.critical:
            title_parts.append("Critical")
        elif severities:
            title_parts.append(f"Severity: {', '.join(severities)}")

        if category:
            title_parts.append(f"Category: {category}")
        if args.asset:
            title_parts.append(f"Asset: {args.asset}")
        if exploits_only:
            title_parts.append("Exploits Only")
        if pocs_only_flag:
            title_parts.append("POCs Only")
        if args.velocity:
            title_parts.append("Velocity Sorted")
        if args.max_days_to_exploit is not None:
            title_parts.append(f"Exploited Within {args.max_days_to_exploit}d")

        # Deliberately never append a "Collection: X" entry to title_parts —
        # title_parts is reused verbatim (unmodified) as the "Filters: ..."
        # line of the specialized --collection text banner below, and mixing
        # the collection name into it would both duplicate the banner's own
        # "COLLECTION: {name}" line and require fragile after-the-fact
        # removal for that banner's Filters line.
        title = "CVEs — " + " | ".join(title_parts) if title_parts else "All CVEs"
        if args.collection:
            title = f"Collection: {args.collection} | {title}"

        # Structured filter metadata for --format json's "filter" key. A
        # superset of the illustrative {mode, hours, severity} shape from
        # the output-formats spec, extended to cover this repo's composable
        # filters (category/asset/exploits_only/pocs_only) — see
        # docs/features/OUTPUT_FORMATS_FEATURE.md.
        if args.new:
            mode = "new"
        elif args.updated:
            mode = "updated"
        elif args.unprocessed:
            mode = "unprocessed"
        elif args.relevant:
            mode = "relevant"
        elif args.since:
            mode = f"since:{args.since}"
        else:
            mode = "all"

        filter_meta = {
            "mode": mode,
            "hours": args.hours if (args.new or args.updated) else None,
            "severity": (["CRITICAL"] if args.critical else severities),
            "category": category,
            "asset": args.asset,
            "exploits_only": exploits_only,
            "pocs_only": pocs_only_flag,
            "collection": args.collection,
        }

        # Specialized COLLECTION/Description/Members/Filters/Generated banner
        # for --collection in --format text only (see format_list_text());
        # every other mode/format keeps using the generic `title` above,
        # which already carries "Collection: X" when a collection is active.
        collection_info = None
        if args.collection and args.format == 'text':
            collection_row = reporter.conn.execute(
                "SELECT description FROM collections WHERE id = ?", (collection_id,)
            ).fetchone()
            collection_info = {
                'name': args.collection,
                'description': collection_row['description'] if collection_row else None,
                'member_count': reporter.get_collection_member_count(collection_id),
                'filters': " | ".join(title_parts) if title_parts else None,
            }

        reporter.generate_report(cves, title, filter_meta, args.format, args.output,
                                  collection_info=collection_info, velocity_map=velocity_map)

        # Mark as processed if requested
        if args.mark_processed and cves:
            cve_ids = [cve['id'] for cve in cves]
            reporter.mark_as_processed(cve_ids)
            print(f"\nMarked {len(cve_ids)} CVEs as processed", file=sys.stderr)


if __name__ == "__main__":
    main()
