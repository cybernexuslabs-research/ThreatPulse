# ThreatPulse Architecture Diagram

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          THREATPULSE                                │
│         Continuous CVE Threat Monitoring and Reporting Tool         │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐
│   External Sources   │
├──────────────────────┤
│ • NVD CVE Feed       │────┐
│ • CISA KEV Catalog   │    │
└──────────────────────┘    │
                            │
                            ▼
           ┌────────────────────────────────┐
           │     cve_collector.py           │
           │  (Automated - Cron Every 30m)  │
           ├────────────────────────────────┤
           │ 1. Download NVD Feed           │
           │ 2. Download CISA KEV           │
           │ 3. Parse CVE Data              │
           │ 4. Check Relevance             │
           │ 5. Calculate Scores            │
           │ 6. UPSERT to Database          │
           └────────────┬───────────────────┘
                        │
                        │ INSERT/UPDATE
                        │
                        ▼
         ┌──────────────────────────────────────┐
         │          cves.db (SQLite)            │
         │        Single Normalized Table       │
         ├──────────────────────────────────────┤
         │ • CVE ID (Primary Key)               │
         │ • Description, Scores, Severity      │
         │ • Relevance Tracking                 │
         │ • Exploit Status                     │
         │ • Timestamps (first_seen, updated)   │
         │ • Processing State (processed flag)  │
         └──────────────┬───────────────────────┘
                        │
                        │ SELECT/QUERY
                        │
                        ▼
           ┌────────────────────────────────┐
           │      cve_reporter.py           │
           │    (On-Demand - Manual/CLI)    │
           ├────────────────────────────────┤
           │ • Query Database               │
           │ • Filter & Sort                │
           │ • Format Output                │
           │ • Mark as Processed            │
           └────────────┬───────────────────┘
                        │
                        │ Output
                        │
         ┌──────────────┴──────────────┐
         │                             │
         ▼                             ▼
   ┌──────────┐                  ┌──────────┐
   │   Text   │                  │   JSON   │
   │  Reports │                  │  Reports │
   └──────────┘                  └──────────┘
```

## UPSERT Flow Diagram

```
CVE Data Incoming
       │
       ▼
┌─────────────────┐
│ Check if exists │
│   in database   │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐ ┌─────────────────────────┐
│  NEW   │ │       EXISTS            │
│  CVE   │ │  Check for changes:     │
└───┬────┘ │  • Score different?     │
    │      │  • Severity different?  │
    │      │  • Exploit added?       │
    │      └────────┬────────────────┘
    │               │
    │          ┌────┴────┐
    │          │         │
    │          ▼         ▼
    │    ┌──────────┐ ┌──────────┐
    │    │ CHANGED  │ │ NO CHANGE│
    │    └────┬─────┘ └────┬─────┘
    │         │            │
    ▼         ▼            ▼
┌─────────────────────────────────────┐
│      UPSERT OPERATION               │
├─────────────────────────────────────┤
│ INSERT INTO cves (...)              │
│ ON CONFLICT(id) DO UPDATE SET       │
│   - Update all fields               │
│   - Preserve first_seen             │
│   - Set last_updated_date (if Δ)    │
│   - Reset processed flag (if Δ)     │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│ Database Updated│
│ • First Seen ✓  │
│ • Last Checked ✓│
│ • Changes ✓     │
└─────────────────┘
```

## CVE Lifecycle State Machine

```
       ┌──────────────────┐
       │ NVD Publishes    │
       │    CVE-2024-1234 │
       └────────┬─────────┘
                │
                ▼
    ┌───────────────────────┐
    │  COLLECTOR DISCOVERS  │
    │  • first_seen = NOW   │
    │  • processed = FALSE  │
    │  • Score = 7.5 (HIGH) │
    └────────┬──────────────┘
             │
             ▼
    ┌────────────────────────┐
    │ USER REVIEWS (REPORTER)│
    │  • Reads CVE           │
    │  • processed = TRUE    │
    └────────┬───────────────┘
             │
             ▼
    ┌────────────────────────┐
    │ NVD UPDATES CVE        │
    │  • Score: 7.5→9.8 (!)  │
    │  • Exploit: No→Yes (!) │
    └────────┬───────────────┘
             │
             ▼
    ┌────────────────────────────┐
    │ COLLECTOR RE-PROCESSES     │
    │  • last_updated = NOW      │
    │  • processed = FALSE (!)   │  ← RESET!
    │  • Score = 9.8 (CRITICAL)  │
    │  • has_exploit = TRUE      │
    └────────┬───────────────────┘
             │
             ▼
    ┌────────────────────────┐
    │ USER RE-ALERTED        │
    │  • Sees in --updated   │
    │  • Sees in --unproc    │
    └────────────────────────┘
```

## Reporter Query Paths

```
User CLI Command
       │
       ▼
┌──────────────────────┐
│  Parse Arguments     │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│  Determine Query Type                │
├──────────────────────────────────────┤
│ --new         → first_seen filter    │
│ --updated     → last_updated filter  │
│ --unprocessed → processed = 0        │
│ --critical    → severity = CRITICAL  │
│ --severity    → severity IN (...)    │
│ --asset       → assets LIKE %...%    │
│ --exploits    → has_exploit = 1      │
│ --relevant    → affects_infra = 1    │
│ --dashboard   → aggregate stats      │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────────────┐
│  Execute SQL Query   │
│  with Indexes        │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Format Results      │
│  • Text or JSON      │
│  • Sort by relevance │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Output              │
│  • stdout or file    │
│  • Mark processed    │
└──────────────────────┘
```

## Data Flow Example

```
Day 1: 09:00 AM
┌────────────────────────────────────────┐
│ Collector Run #1                       │
│ • Downloads 1,000 CVEs from NVD        │
│ • 50 are CRITICAL                      │
│ • 200 are HIGH                         │
│ • 100 affect infrastructure            │
│ • 15 have known exploits               │
│ • All inserted into database           │
└────────────────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────┐
│ Database State                         │
│ • Total CVEs: 1,000                    │
│ • Unprocessed: 1,000                   │
└────────────────────────────────────────┘
              │
              ▼
Day 1: 10:00 AM
┌────────────────────────────────────────┐
│ User: ./cve_reporter.py --dashboard    │
│ Output:                                │
│   Total: 1,000                         │
│   Critical: 50                         │
│   High: 200                            │
│   Exploits: 15                         │
│   Unprocessed: 1,000                   │
└────────────────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────┐
│ User: ./cve_reporter.py --critical     │
│       --mark-processed                 │
│ • Shows 50 critical CVEs               │
│ • Marks them as processed              │
└────────────────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────┐
│ Database State                         │
│ • Total CVEs: 1,000                    │
│ • Unprocessed: 950                     │
└────────────────────────────────────────┘
              │
              ▼
Day 1: 09:30 AM (Collector runs again)
┌────────────────────────────────────────┐
│ Collector Run #2                       │
│ • Downloads same 1,000 CVEs            │
│ • 1 CVE changed: CVE-2024-1234         │
│   - Score: 7.5 → 9.8                   │
│   - Severity: HIGH → CRITICAL          │
│   - Exploit: No → Yes                  │
│ • UPSERT updates the record            │
│ • Sets processed = 0 (reset!)          │
└────────────────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────┐
│ Database State                         │
│ • Total CVEs: 1,000 (same)             │
│ • Unprocessed: 951 (increased!)        │
│ • Updated in last 24h: 1               │
└────────────────────────────────────────┘
              │
              ▼
Day 1: 02:00 PM
┌────────────────────────────────────────┐
│ User: ./cve_reporter.py --updated      │
│ Shows:                                 │
│   CVE-2024-1234                        │
│   Was: 7.5 (HIGH), No exploit          │
│   Now: 9.8 (CRITICAL), Exploit! 🚨     │
└────────────────────────────────────────┘
```

## Database Schema Visual

```
┌─────────────────────────────────────────────────────────┐
│                     TABLE: cves                         │
├─────────────────────────────────────────────────────────┤
│ id                    TEXT PRIMARY KEY                  │  ← Unique CVE-YYYY-NNNNN
│ description           TEXT NOT NULL                     │
│ published_date        TEXT NOT NULL                     │
│ last_updated_date     TEXT                              │  ← When data changed
├─────────────────────────────────────────────────────────┤
│ base_score            REAL                              │  ← CVSS score (0-10)
│ base_severity         TEXT                              │  ← CRITICAL/HIGH/etc
├─────────────────────────────────────────────────────────┤
│ affects_infrastructure BOOLEAN                          │  ← Matches assets?
│ affected_categories   TEXT (JSON)                       │  ← ["web_servers", ...]
│ affected_assets       TEXT (JSON)                       │  ← ["nginx", "mysql"]
│ relevance_score       REAL                              │  ← Weighted score
├─────────────────────────────────────────────────────────┤
│ has_known_exploit     BOOLEAN                           │  ← In CISA KEV?
│ exploit_added_date    TEXT                              │
├─────────────────────────────────────────────────────────┤
│ first_seen            TIMESTAMP                         │  ← Never changes
│ last_checked          TIMESTAMP                         │  ← Every collector run
│ processed             BOOLEAN                           │  ← User reviewed?
└─────────────────────────────────────────────────────────┘

Indexes:
• idx_severity          → Fast severity filtering
• idx_relevance         → Relevant CVEs by score
• idx_exploits          → CVEs with exploits
• idx_processed         → Unprocessed CVEs
• idx_last_updated      → Recently changed
• idx_first_seen        → New CVEs
```

## Configuration Flow

```
┌─────────────────┐
│   config.py     │
│  • MY_ASSETS    │
│  • WEIGHTS      │
└────────┬────────┘
         │
         ├─────────────┐
         │             │
         ▼             ▼
┌─────────────┐   ┌─────────────┐
│ Collector   │   │  Reporter   │
│ Uses for:   │   │  Uses for:  │
│ • Relevance │   │  • Display  │
│ • Scoring   │   │  • Context  │
└─────────────┘   └─────────────┘
```
