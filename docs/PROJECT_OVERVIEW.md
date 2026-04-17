# ThreatPulse — Project Overview

**Version:** 1.0  
**Last reviewed:** 2026-04-16  
**License:** MIT

## What Is ThreatPulse?

ThreatPulse is a continuous CVE (Common Vulnerabilities and Exposures) threat monitoring and reporting tool built in Python. It automates the cycle of discovering new vulnerabilities, matching them against an organization's asset inventory, tracking exploit availability, and surfacing actionable intelligence through a flexible CLI reporter.

The tool is designed around a clean separation of concerns: a **collector** service handles all data ingestion and a **reporter** service handles all querying and output. Both share a single SQLite database as the source of truth.

## Architecture at a Glance

ThreatPulse follows a two-stage pipeline architecture:

1. **cve_collector.py** pulls data from external threat feeds on a scheduled basis (typically every 30 minutes via cron). It normalizes and deduplicates incoming CVE records using SQLite UPSERT logic, so the database always reflects the latest state of each vulnerability without creating duplicate rows.

2. **cves.db** (SQLite) serves as the single normalized data store. One table (`cves`) holds all CVE records with columns for scoring, relevance, exploit status, POC availability, and processing state. Nine indexes and a summary statistics view (`cve_stats`) keep queries fast.

3. **cve_reporter.py** is a CLI tool that queries the database on demand. It supports a wide range of filters (severity, asset, exploit status, time window, processing state) and can output as formatted text or JSON, to stdout or to a file.

4. **config.py** holds the shared configuration: the asset inventory, category criticality weights, feed URLs, and database path. Both the collector and reporter import from it.

## Data Sources

ThreatPulse ingests data from three external sources:

- **NVD (National Vulnerability Database)** — the primary CVE feed, providing vulnerability descriptions, CVSS scores (v2, v3.1, and v4.0), and severity ratings.
- **CISA KEV (Known Exploited Vulnerabilities)** catalog — flags CVEs that are actively exploited in the wild.
- **ExploitDB** — a CSV-based lookup that maps CVE IDs to published exploit code, providing proof-of-concept URLs.

A fourth source, **CVEDB (Shodan)**, is queried per-CVE for additional POC references but only for CVEs already deemed relevant or known-exploited, to avoid excessive API calls. GitHub-based POC lookups (nomi-sec/PoC-in-GitHub) are present in code but disabled by default due to rate-limiting constraints.

## Key Capabilities

### Intelligent UPSERT Logic

When the collector re-encounters a CVE it has already stored, it compares the incoming score, severity, and exploit status against the existing record. If any of these have changed, the record is updated, the `last_updated_date` is refreshed, and the `processed` flag is reset to zero — ensuring analysts are re-alerted to meaningful changes. The `first_seen` timestamp is never overwritten, preserving discovery history.

### Relevance Scoring

Each CVE description is matched against the asset inventory defined in `config.py` using word-boundary regex. Matching assets and their categories are recorded, and a weighted relevance score is computed by multiplying the CVSS base score by the highest criticality weight among matched categories. This lets analysts prioritize vulnerabilities that matter most to their specific environment.

### Asset Inventory

The default configuration tracks 11 asset categories covering web servers, operating systems, databases, network devices, cloud services, applications, PAM tools, security tools, vulnerability types, DevOps tooling, and AI services. Each category carries a criticality weight between 0.5 and 1.0 that feeds into relevance scoring.

### Flexible Reporting

The reporter supports filtering by: new CVEs (time window), updated CVEs, unprocessed CVEs, severity level(s), specific assets, exploit availability, POC availability, infrastructure relevance, and publication date. Filters can be combined (e.g., `--new --with-pocs`). A `--dashboard` mode provides an aggregate summary including severity breakdowns, recent activity counts, top affected assets, and critical alert counts.

### Processing Workflow

The `processed` boolean flag enables a triage workflow. Analysts review CVEs, optionally mark them as processed with `--mark-processed`, and the collector automatically resets the flag if a CVE's risk profile changes. This prevents both alert fatigue and missed escalations.

## Technology Stack

- **Language:** Python 3
- **Database:** SQLite (single-file, zero-config)
- **Dependencies:** `requests` (the only external package)
- **Scheduling:** Intended for cron-based automation; no built-in daemon

## File Structure

| File | Purpose |
|---|---|
| `config.py` | Shared configuration — assets, weights, URLs, DB path |
| `cve_collector.py` | Data ingestion service (CVECollector class) |
| `cve_reporter.py` | Reporting CLI (CVEReporter class with argparse interface) |
| `schema.sql` | Database schema — table, indexes, and stats view |
| `setup.py` | Interactive first-run setup script |
| `requirements.txt` | Python dependencies (requests) |
| `README.md` | Full usage documentation |
| `ARCHITECTURE.md` | Visual architecture and flow diagrams |
| `QUICKREF.md` | Quick-reference command card |

## Typical Workflows

**Daily morning check:** Run the dashboard for a summary, review new critical/high CVEs, check for fresh exploits and POCs, then mark infrastructure-relevant CVEs as processed.

**Targeted asset review:** Query CVEs for a specific technology (e.g., `--asset nginx`), optionally filtered to only those with known exploits, and export to JSON for ticket creation.

**Automated alerting:** Combine cron-scheduled collection with cron-scheduled reporting piped to email or a Slack/Teams webhook for hands-off monitoring.

## Strengths and Considerations

**Strengths:** Minimal dependencies, simple deployment (just Python + SQLite), clean separation between collection and reporting, intelligent change detection that avoids both duplicates and missed updates, and a well-indexed schema that keeps queries fast even as the database grows.

**Considerations:** The tool currently relies on NVD's bundled JSON feed format rather than the NVD 2.0 REST API, which may require updating if NVD deprecates the feed. GitHub POC lookups are disabled due to unauthenticated rate limits and would benefit from optional API token support. There is no built-in notification mechanism — alerting depends on external tooling (cron + mail/webhooks). The single `requests` dependency keeps things lean, but adding retry/backoff logic for feed downloads would improve resilience.
