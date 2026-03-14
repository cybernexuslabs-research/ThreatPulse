# ThreatPulse - Continuous CVE Threat Monitoring and Reporting Tool

A modular threat monitoring tool that separates data collection from reporting, using a single normalized database with intelligent UPSERT logic.

## Architecture Overview

```
┌─────────────────────┐
│  cve_collector.py   │  ← Automated (cron every 30 min)
│  - Downloads feeds  │
│  - Updates database │
│  - No file output   │
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐
    │   cves.db    │  ← Single source of truth
    │ (SQLite DB)  │
    └──────┬───────┘
           │
           ▼
┌─────────────────────┐
│  cve_reporter.py    │  ← On-demand (manual/scheduled)
│  - Queries database │
│  - Generates reports│
│  - Multiple formats │
└─────────────────────┘
```

## Features

### ✅ Single Table Design
- No duplication (one CVE = one row)
- Efficient indexing for fast queries
- Tracks CVE lifecycle (new, updated, processed)

### ✅ UPSERT Logic (Option 3)
- Handles CVE updates intelligently
- Preserves `first_seen` timestamp
- Tracks when CVEs change (score upgrades, new exploits)
- Auto-resets `processed` flag on updates

### ✅ Relevance Scoring
- Matches CVEs against your asset inventory
- Weighted scoring by asset criticality
- Tracks affected categories and assets

### ✅ Exploit Tracking
- Integrates CISA KEV catalog
- Flags CVEs with known exploits
- Prioritizes actively exploited vulnerabilities

### ✅ POC Detection
- Checks nomi-sec/PoC-in-GitHub for public POC repositories
- Downloads and parses ExploitDB for known exploit code
- Queries CVEDB (Shodan) for POC references
- Stores POC URLs and sources per CVE

### ✅ Flexible Reporting
- CLI with multiple filtering options
- Text and JSON output formats
- Dashboard summary view
- Asset-specific reports

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x cve_collector.py cve_reporter.py

# Initialize database
python3 cve_collector.py
```

## Configuration

Edit `config.py` to customize your environment:

```python
MY_ASSETS = {
    'web_servers': ['apache', 'nginx', 'iis'],
    'databases': ['mysql', 'postgresql'],
    'cloud_services': ['aws', 'azure'],
    # ... add your assets
}

CATEGORY_WEIGHTS = {
    'web_servers': 1.0,      # High priority
    'databases': 0.9,        # High priority
    'applications': 0.6,     # Medium priority
    # ... adjust weights
}
```

## Usage

### Data Collection (Automated)

```bash
# Run collector manually
./cve_collector.py

# Or set up cron (every 30 minutes)
*/30 * * * * /path/to/cve_collector.py >> /var/log/cve_collector.log 2>&1
```

**What it does:**
- Downloads NVD recent CVEs feed
- Downloads CISA KEV catalog
- Checks for POC exploits (GitHub, ExploitDB, CVEDB)
- Parses and normalizes CVE data
- UPSERTs to database (insert or update)
- Tracks new/updated CVEs
- Logs statistics

### Reporting (On-Demand)

#### Quick Examples

```bash
# Show dashboard
./cve_reporter.py --dashboard

# New CVEs (last 24 hours)
./cve_reporter.py --new

# New CVEs (last 48 hours)
./cve_reporter.py --new --hours 48

# Recently updated CVEs
./cve_reporter.py --updated

# Unprocessed CVEs
./cve_reporter.py --unprocessed

# Critical CVEs only
./cve_reporter.py --critical

# High and critical CVEs
./cve_reporter.py --severity HIGH,CRITICAL

# All CVEs with known exploits
./cve_reporter.py --exploits-only

# All CVEs with POC exploits
./cve_reporter.py --pocs-only

# New CVEs that have POCs
./cve_reporter.py --new --with-pocs

# CVEs relevant to infrastructure
./cve_reporter.py --relevant

# CVEs since specific date
./cve_reporter.py --since 2024-01-01
```

#### Asset-Specific Reports

```bash
# All nginx CVEs
./cve_reporter.py --asset nginx

# MySQL CVEs with known exploits
./cve_reporter.py --asset mysql --with-exploits

# AWS CVEs
./cve_reporter.py --asset aws
```

#### Output Options

```bash
# JSON format
./cve_reporter.py --new --format json

# Save to file
./cve_reporter.py --new --output new_cves.txt

# JSON to file
./cve_reporter.py --exploits-only --format json --output exploits.json

# Mark as processed after viewing
./cve_reporter.py --unprocessed --mark-processed
```

## Database Schema

### Single Table: `cves`

```sql
CREATE TABLE cves (
    id TEXT PRIMARY KEY,                -- CVE-YYYY-NNNNN
    description TEXT NOT NULL,
    published_date TEXT NOT NULL,
    last_updated_date TEXT,             -- Tracks when CVE changed
    
    base_score REAL,                    -- CVSS score
    base_severity TEXT,                 -- CRITICAL/HIGH/MEDIUM/LOW
    
    affects_infrastructure BOOLEAN,     -- Matches our assets?
    affected_categories TEXT,           -- JSON: ["web_servers", ...]
    affected_assets TEXT,               -- JSON: ["nginx", "mysql"]
    relevance_score REAL,               -- Weighted score
    
    has_known_exploit BOOLEAN,          -- In CISA KEV?
    exploit_added_date TEXT,

    has_poc BOOLEAN,                    -- POC exploit available?
    poc_urls TEXT,                      -- JSON: ["https://github.com/..."]
    poc_source TEXT,                    -- JSON: ["github", "exploitdb", "cvedb"]

    first_seen TIMESTAMP,               -- When we first saw it
    last_checked TIMESTAMP,             -- Last collector run
    processed BOOLEAN                   -- Reported to user?
);
```

### Key Indexes

- `idx_severity` - Fast severity filtering
- `idx_relevance` - Relevant CVEs by score
- `idx_exploits` - CVEs with exploits
- `idx_processed` - Unprocessed CVEs
- `idx_last_updated` - Recently changed CVEs
- `idx_poc` - CVEs with POC exploits

## UPSERT Logic Explained

The collector uses SQLite's `ON CONFLICT` UPSERT to handle CVE updates:

```python
INSERT INTO cves (...) VALUES (...)
ON CONFLICT(id) DO UPDATE SET
    base_score = excluded.base_score,
    has_known_exploit = excluded.has_known_exploit,
    # ... update all fields except first_seen
    last_updated_date = CASE
        WHEN score/severity/exploit changed
        THEN now()
        ELSE keep old value
    END
```

**Benefits:**
1. **No duplicates** - CVE ID is primary key
2. **Tracks changes** - `last_updated_date` only updates when meaningful
3. **Preserves history** - `first_seen` never changes
4. **Auto re-alerts** - `processed` flag resets on updates

**Example Lifecycle:**

```
Day 1:  CVE-2024-1234 discovered
        - first_seen: 2024-02-15
        - base_score: 7.5 (HIGH)
        - has_exploit: False
        - processed: False

Day 2:  User views report
        - processed: True

Day 7:  NVD updates CVE
        - base_score: 9.8 (CRITICAL)  ← Changed!
        - has_exploit: True            ← Changed!
        - last_updated_date: 2024-02-22
        - processed: False             ← Reset!
        
        User gets alerted again!
```

## Workflow Examples

### Daily Morning Routine

```bash
# 1. Check dashboard
./cve_reporter.py --dashboard

# 2. Review new critical/high CVEs
./cve_reporter.py --severity CRITICAL,HIGH --new

# 3. Check for new exploits
./cve_reporter.py --exploits-only --new

# 4. Check for new POCs
./cve_reporter.py --pocs-only --new

# 5. Review infrastructure-relevant CVEs
./cve_reporter.py --relevant --unprocessed --mark-processed
```

### Targeted Asset Review

```bash
# Check specific asset
./cve_reporter.py --asset nginx --unprocessed

# Export for ticket creation
./cve_reporter.py --asset mysql --with-exploits --format json --output mysql_exploits.json
```

### Weekly Summary

```bash
# Get all unprocessed CVEs
./cve_reporter.py --unprocessed --output weekly_report.txt --mark-processed

# Or get last 7 days
./cve_reporter.py --new --hours 168 --output weekly_report.txt
```

## Customization

### Adding New Assets

Edit `config.py`:

```python
MY_ASSETS = {
    'containers': ['docker', 'kubernetes', 'containerd'],
    'monitoring': ['prometheus', 'grafana', 'elasticsearch'],
    # ...
}

CATEGORY_WEIGHTS = {
    'containers': 0.9,  # High priority
    'monitoring': 0.6,  # Medium priority
    # ...
}
```

### Custom Queries

You can also query the database directly:

```python
import sqlite3

conn = sqlite3.connect('cves.db')
cursor = conn.cursor()

# Custom query
cursor.execute("""
    SELECT id, base_score, description
    FROM cves
    WHERE base_severity = 'CRITICAL'
    AND affects_infrastructure = 1
    AND has_known_exploit = 1
    ORDER BY relevance_score DESC
""")

for row in cursor.fetchall():
    print(row)
```

## Cron Setup Examples

### Collector (Every 30 Minutes)

```bash
# Edit crontab
crontab -e

# Add line:
*/30 * * * * cd /path/to/ThreatPulse && ./cve_collector.py >> /var/log/cve_collector.log 2>&1
```

### Daily Morning Report (7 AM)

```bash
0 7 * * * cd /path/to/ThreatPulse && ./cve_reporter.py --unprocessed --output /tmp/daily_cves.txt --mark-processed && mail -s "Daily CVE Report" you@example.com < /tmp/daily_cves.txt
```

### Weekly Summary (Monday 9 AM)

```bash
0 9 * * 1 cd /path/to/ThreatPulse && ./cve_reporter.py --new --hours 168 --output /tmp/weekly_cves.txt && mail -s "Weekly CVE Summary" you@example.com < /tmp/weekly_cves.txt
```

## Logging

The collector logs to stdout/stderr. To keep logs:

```bash
# Manual run with logging
./cve_collector.py 2>&1 | tee -a cve_collector.log

# Or use systemd/cron redirection
./cve_collector.py >> /var/log/cve_collector.log 2>&1
```

## Troubleshooting

### Database locked error
```bash
# Check for running processes
ps aux | grep cve_collector

# Kill if stuck
pkill -f cve_collector
```

### Reset processed flags
```python
import sqlite3
conn = sqlite3.connect('cves.db')
conn.execute("UPDATE cves SET processed = 0")
conn.commit()
```

### View database stats
```bash
sqlite3 cves.db "SELECT * FROM cve_stats"
```

## File Structure

```
ThreatPulse/
├── config.py              # Configuration (assets, weights)
├── schema.sql             # Database schema
├── cve_collector.py       # Data collection service
├── cve_reporter.py        # Reporting service
├── requirements.txt       # Python dependencies
├── cves.db               # SQLite database (created on first run)
└── README.md             # This file
```

## Benefits Over Original Script

| Original | Lightweight Hybrid |
|----------|-------------------|
| 3 duplicate tables | 1 normalized table |
| No update tracking | Tracks CVE changes |
| File-based | Database-driven |
| All-in-one | Separation of concerns |
| Fixed output | Flexible querying |
| No state tracking | Processed flags |
| Manual filtering | Indexed searches |

## Next Steps

1. **Customize assets** in `config.py`
2. **Run collector** once to populate database
3. **Set up cron** for automated collection
4. **Test reports** with various filters
5. **Integrate** with ticketing/alerting systems

## License

MIT

## Contributing

Feel free to submit issues or pull requests!
