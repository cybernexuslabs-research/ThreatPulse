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
