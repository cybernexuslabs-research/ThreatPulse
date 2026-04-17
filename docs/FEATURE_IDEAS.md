# ThreatPulse — Feature Ideas

A consolidated list of proposed features organized by category. Each entry includes a name and full description to guide planning and implementation.

---

## Configuration & Flexibility

### External Asset Configuration File

Move `MY_ASSETS` and `CATEGORY_WEIGHTS` out of `config.py` and into an external file (e.g., `assets.yaml` or `assets.json`) loaded at runtime. This lets users update their asset watch list without editing Python source code, version-control asset lists independently, and swap profiles per environment. Include a CLI flag such as `--assets-file` to point to a custom file, with a fallback to built-in defaults if no file is provided.

### External Data Source URLs

The NVD, CISA KEV, and ExploitDB URLs are currently hard-coded in `config.py`. Externalizing them into the same settings file (or a dedicated `settings.yaml`) allows operators to swap feeds, point to internal mirrors, or add new sources without modifying code.

### Environment-Based Configuration

Support environment variables or a `.env` file for operational settings such as `DB_PATH`, `REQUEST_TIMEOUT`, `LOG_LEVEL`, and API keys (e.g., GitHub tokens, NVD API keys). This simplifies deployment across different environments (dev, staging, production) and keeps secrets out of source control.

### Asset Grouping / Profiles

Support multiple named asset profiles (e.g., "production", "development", "cloud-only") so users can run separate relevance scans per environment or business unit. Each profile would have its own asset list and category weights, selectable via a CLI flag.

---

## Data Sources & Coverage

### NVD API 2.0 Migration

The project currently uses the older JSON feed format (`nvdcve-2.0-recent.json.zip`). NIST has been migrating to a REST API at `api.nvd.nist.gov`. Switching to the new API provides real-time data access, pagination, keyword filtering at the source, and better rate-limit handling with an API key.

### Re-enable GitHub POC Lookups

The nomi-sec/PoC-in-GitHub integration is currently disabled due to rate limits. Adding support for a GitHub personal access token and implementing rate-limit-aware request handling (backoff, conditional requests via ETags) would restore this valuable exploit-intelligence source.

### EPSS Score Integration

Integrate the Exploit Prediction Scoring System (EPSS), which provides a daily probability score estimating the likelihood a CVE will be exploited in the wild within 30 days. For research and prioritization, EPSS complements CVSS by shifting focus from theoretical severity to real-world attacker interest. The EPSS data is available as a free daily CSV download.

### Additional Intel Feeds

Expand the data source pipeline to support additional feeds beyond the current three. Candidates include vendor-specific advisories (Microsoft, Cisco, Red Hat), the VulnCheck KEV list, and PacketStorm. A plugin-style feed architecture would make adding new sources straightforward.

### Historical Feed Ingestion

The collector currently pulls only the NVD "recent" feed. For research purposes, add the ability to backfill the full NVD history (or a specific date/year range) so users can perform longitudinal analysis, trend identification, and historical comparisons.

---

## Search & Discovery

### Full-Text / Keyword Search

Add a `--search` flag to the reporter that performs regex or keyword searches across CVE descriptions and references. Researchers need to search for arbitrary terms like "use-after-free", "authentication bypass", or a specific library name that may not be in the asset inventory.

### CVE Lookup by ID

Add a `--cve CVE-2026-XXXX` flag that pulls everything the database knows about a specific vulnerability in one view: CVSS score, description, exploit status, POC links, relevance matches, processing history, and all enrichment data.

### Vendor / Product Filtering

Allow filtering by CPE vendor or product name (e.g., "show me all Microsoft Exchange CVEs from the last 90 days") without requiring the product to be part of the configured asset inventory. This decouples research queries from organizational asset management.

### Related CVE Clustering

Group CVEs that share the same affected component, CWE weakness type, or were disclosed in the same advisory batch. Researchers often study vulnerability patterns rather than individual CVEs, and clustering surfaces those patterns automatically.

---

## Enrichment & Context

### MITRE ATT&CK Mapping

Automatically tag CVEs with likely MITRE ATT&CK techniques based on the vulnerability type and description. For example, an RCE vulnerability maps to T1203 (Exploitation for Client Execution). This connects individual CVEs to adversary behavior models, which is essential for threat research and red-team planning.

### Threat Actor Association

Cross-reference CVEs against known threat actor toolkits and campaigns. If a group like APT28, Lazarus, or Scattered Spider has been observed exploiting a vulnerability, surface that linkage alongside the CVE data. Sources could include MITRE's threat group database, Mandiant reports, or output from the ThreatPulse threat-actor-profiler skill.

### CWE Enrichment

Store and display the CWE (Common Weakness Enumeration) identifier for each CVE and support filtering by weakness type. Queries like "show me all CWE-787 (out-of-bounds write) vulnerabilities with public exploits" are common in vulnerability research workflows.

### Reference Link Extraction

NVD entries include reference URLs pointing to vendor advisories, patches, technical write-ups, and bug tracker entries. Store these references in the database and display them in reports so researchers have quick access to primary sources without needing to visit the NVD website.

### Timeline View

Display a chronological timeline for each CVE showing key lifecycle events: publication date, CISA KEV addition date, first POC appearance, CVSS score changes, and exploit status transitions. Understanding the lifecycle of a vulnerability is central to research and threat intelligence reporting.

---

## Analysis & Workflow

### Research Notes and Tags

Allow users to attach freeform notes and custom tags to any CVE (e.g., "interesting for red team", "potential supply chain vector", "needs deeper analysis"). The current binary `processed` flag is insufficient for research workflows where CVEs need to be annotated, categorized, and revisited.

### Collections / Watchlists

Support named collections of CVEs that a researcher is tracking for a specific project or report. For example, `--collection "Log4j variants"` would let users add CVEs to a named set and later query, export, or report on that set as a group.

### Multi-User Triage Workflow

Expand the single `processed` flag into a richer triage system with fields like `assigned_to`, `triage_status` (new / investigating / mitigated / risk-accepted), and `notes`. This supports team-based vulnerability management where multiple analysts collaborate on triage.

### Diff / Delta Reporting

Generate a "what changed since I last looked?" report that goes beyond listing new CVEs. Surface which existing CVEs received new exploit POCs, CVSS score changes, KEV additions, or status updates. The upsert logic already detects some of these changes internally; this feature would expose them as a first-class report view.

### Historical Trending

Track and visualize how a CVE's risk profile evolves over time — CVSS score adjustments, exploit availability changes, KEV additions — rather than only storing the latest snapshot. This enables trend analysis across the vulnerability landscape.

---

## Reporting & Output

### Multiple Output Formats

The reporter currently outputs to the terminal only. Add `--format json`, `--format csv`, and `--format html` flags so output can be piped into other tools, imported into spreadsheets, or viewed in a browser.

### Markdown / HTML Report Generation

Generate a formatted vulnerability intelligence brief suitable for sharing with a team or attaching to a threat report. Include executive summary, critical findings, trending CVEs, and enrichment highlights. This pairs naturally with the existing threat-analysis skill.

### Email / Slack Notifications

Send automated alerts when high-severity or high-relevance CVEs are discovered, when exploit status changes, or when a CVE hits the CISA KEV list. This removes the requirement for someone to manually run the reporter to discover new threats.

### Dashboard / Web UI

Provide a lightweight web interface (e.g., Flask or FastAPI) for browsing, filtering, searching, and triaging CVEs visually. A dashboard view with severity distribution charts, recent activity feeds, and one-click triage actions would make the tool accessible to team members who prefer a GUI.

### STIX / TAXII Export

Output enriched CVE data in STIX 2.1 format so it can be ingested by threat intelligence platforms such as MISP, OpenCTI, or ThreatConnect. TAXII server support would allow other systems to subscribe to the ThreatPulse feed directly.

### API Mode

Run the reporter as a lightweight REST API so external tools — Jupyter notebooks, dashboards, automation scripts, SOAR platforms — can query the enriched CVE database programmatically.

---

## Reliability & Operations

### Retry Logic with Exponential Backoff

HTTP requests currently use a flat 30-second timeout with no retry. Implement exponential backoff with configurable retry counts to make the collector resilient to transient network failures, API rate limits, and temporary service outages.

### Structured Logging

Move from basic string-format logging to structured JSON log output. This makes logs searchable and parseable by log management platforms like Splunk or Sentinel — tools already in the ThreatPulse asset watch list.

### Unit and Integration Tests

The `tests/` directory exists but is empty. Add unit tests covering the relevance scoring algorithm, CVE upsert/change-detection logic, feed parsing, and reporter filtering. Integration tests should verify the end-to-end pipeline from feed download through database insertion to report output.
