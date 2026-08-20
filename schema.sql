-- CVE Tracking Database Schema
-- Single table design with proper indexing

CREATE TABLE IF NOT EXISTS cves (
    -- Identity
    id TEXT PRIMARY KEY,
    
    -- Core CVE data
    description TEXT NOT NULL,
    published_date TEXT NOT NULL,
    last_updated_date TEXT,  -- Tracks when CVE data changed (score, exploit status)
    
    -- Scoring
    base_score REAL,
    base_severity TEXT,  -- CRITICAL, HIGH, MEDIUM, LOW, NONE
    
    -- Relevance tracking
    affects_infrastructure BOOLEAN DEFAULT 0,
    affected_categories TEXT,  -- JSON array: ["web_servers", "databases"]
    affected_assets TEXT,      -- JSON array: ["nginx", "mysql"]
    relevance_score REAL DEFAULT 0,
    
    -- Exploit tracking
    has_known_exploit BOOLEAN DEFAULT 0,
    exploit_added_date TEXT,

    -- POC tracking
    has_poc BOOLEAN DEFAULT 0,
    poc_urls TEXT,       -- JSON array of POC URLs
    poc_source TEXT,     -- JSON array: ["github", "exploitdb", "cvedb"]
    
    -- Processing metadata
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed BOOLEAN DEFAULT 0,  -- For tracking what's been reported
    
    UNIQUE(id)
);

-- Essential indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_severity ON cves(base_severity);
CREATE INDEX IF NOT EXISTS idx_relevance ON cves(affects_infrastructure, relevance_score DESC);
CREATE INDEX IF NOT EXISTS idx_exploits ON cves(has_known_exploit, base_score DESC);
CREATE INDEX IF NOT EXISTS idx_published ON cves(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_processed ON cves(processed, published_date DESC);
CREATE INDEX IF NOT EXISTS idx_last_checked ON cves(last_checked);
CREATE INDEX IF NOT EXISTS idx_first_seen ON cves(first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_last_updated ON cves(last_updated_date DESC);
CREATE INDEX IF NOT EXISTS idx_poc ON cves(has_poc, base_score DESC);

-- View for quick stats
CREATE VIEW IF NOT EXISTS cve_stats AS
SELECT
    COUNT(*) as total_cves,
    SUM(CASE WHEN base_severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN base_severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN base_severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
    SUM(CASE WHEN base_severity = 'LOW' THEN 1 ELSE 0 END) as low_count,
    SUM(CASE WHEN has_known_exploit = 1 THEN 1 ELSE 0 END) as exploit_count,
    SUM(CASE WHEN affects_infrastructure = 1 THEN 1 ELSE 0 END) as relevant_count,
    SUM(CASE WHEN processed = 0 THEN 1 ELSE 0 END) as unprocessed_count,
    SUM(CASE WHEN has_poc = 1 THEN 1 ELSE 0 END) as poc_count
FROM cves;

-- Collections / Watchlists: named, ad-hoc sets of CVEs (see
-- docs/features/COLLECTIONS_WATCHLISTS_FEATURE.md). Both FK columns on
-- collection_members cascade on delete — collection_id so deleting a
-- collection cleans up its membership rows, and cve_id so a CVE removed
-- from `cves` (were that ever to happen) doesn't leave orphaned membership
-- rows behind. Enforced only when the connection has run
-- `PRAGMA foreign_keys = ON` (see CVEReporter.__enter__ in cve_reporter.py).
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

-- Lifecycle event log: append-only audit trail of per-CVE events (see
-- docs/features/TIMELINE_VIEW_FEATURE.md). Written by the collector on
-- ingest/score/exploit/POC transitions, and by the reporter when a CVE is
-- marked processed. event_date is local time (datetime.now().isoformat()),
-- matching every other timestamp column in this schema (first_seen,
-- last_checked, collections.created_at, etc.) — not UTC as the design doc's
-- pseudocode originally suggested, to keep duration math against
-- published_date/first_seen consistent within one timezone convention.
-- detail is a JSON blob with event-specific fields (see the design doc's
-- event type table for examples per event_type).
--
-- Unlike the doc's literal DDL, the FK cascades on delete (ON DELETE
-- CASCADE), for the same reason collection_members does: if a CVE row is
-- ever removed from `cves`, its event history shouldn't be left behind as
-- orphaned rows. Enforced only when the connection has run
-- `PRAGMA foreign_keys = ON` (see CVEReporter.__enter__ in cve_reporter.py) —
-- events are written from both cve_collector.py (which does not currently
-- set that pragma) and cve_reporter.py (which does), so treat the FK as
-- documentation of intent rather than a guarantee in all write paths.
CREATE TABLE IF NOT EXISTS cve_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,   -- ingested | cvss_changed | kev_added | poc_added | poc_updated | processed
    event_date  TEXT NOT NULL,   -- ISO 8601 datetime, local time
    detail      TEXT             -- JSON blob with event-specific data
);

CREATE INDEX IF NOT EXISTS idx_cve_events_cve_id ON cve_events(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_events_type   ON cve_events(event_type);
