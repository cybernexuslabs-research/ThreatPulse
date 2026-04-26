#!/usr/bin/env python3
"""
ThreatPulse - CVE Reporter Service
Continuous CVE threat monitoring and reporting tool.
Generates reports from CVE database on-demand.
Supports multiple output formats and filtering options.
"""

import sys
import sqlite3
import json
import argparse
import textwrap
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import config

def normalize_cve_id(raw: str) -> str:
    """Normalize CVE ID to uppercase canonical form (e.g. cve-2026-1234 → CVE-2026-1234)."""
    return raw.strip().upper()


class CVEReporter:
    """Generate various reports from CVE database"""
    
    def __init__(self, db_path: str = config.DB_PATH):
        self.db_path = db_path
        self.conn = None
    
    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()
    
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

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # Per-mode ORDER BY — preserves semantics of all existing get_* methods
        if updated:
            order_by = "last_updated_date DESC"
        elif relevant or category or asset or exploits_only or pocs_only:
            order_by = "relevance_score DESC, base_score DESC"
        else:
            order_by = "base_score DESC, published_date DESC"

        sql = f"SELECT * FROM cves {where} ORDER BY {order_by}"
        return sql, params

    def get_cve_by_id(self, cve_id: str):
        """Return the single cves row for cve_id, or None if not found."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cves WHERE id = ?", (cve_id,))
        return cursor.fetchone()

    def mark_as_processed(self, cve_ids: List[str]):
        """Mark CVEs as processed"""
        cursor = self.conn.cursor()
        placeholders = ','.join('?' * len(cve_ids))
        cursor.execute(f"""
            UPDATE cves
            SET processed = 1
            WHERE id IN ({placeholders})
        """, cve_ids)
        self.conn.commit()
    
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

    def format_cve_text(self, cve: sqlite3.Row) -> str:
        """Format a single CVE as text"""
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
    
    def format_cve_detail(self, cve: sqlite3.Row) -> str:
        """Format a single CVE as a full seven-section detail view for terminal output."""
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

        # ── 7. ALL ENRICHMENT DATA ─────────────────────────────────────────────
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

    def generate_report(self, cves: List[sqlite3.Row], title: str, 
                       output_format: str = 'text', filename: Optional[str] = None):
        """Generate and output/save a report"""
        
        if output_format == 'json':
            report_data = {
                'title': title,
                'generated_at': datetime.now().isoformat(),
                'count': len(cves),
                'cves': [self.format_cve_json(cve) for cve in cves]
            }
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(report_data, f, indent=2)
                print(f"Report saved to: {filename}")
            else:
                print(json.dumps(report_data, indent=2))
        
        else:  # text format
            output = []
            output.append("=" * 70)
            output.append(title)
            output.append("=" * 70)
            output.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            output.append(f"Total CVEs: {len(cves)}")
            output.append("=" * 70)
            output.append("")
            
            for cve in cves:
                output.append(self.format_cve_text(cve))
                output.append("-" * 70)
            
            report_text = "\n".join(output)
            
            if filename:
                with open(filename, 'w') as f:
                    f.write(report_text)
                print(f"Report saved to: {filename}")
            else:
                print(report_text)
    
    def generate_dashboard(self):
        """Generate dashboard summary"""
        stats = self.get_dashboard_stats()
        
        print("=" * 70)
        print("THREATPULSE DASHBOARD")
        print("=" * 70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("")
        
        print("OVERALL STATISTICS")
        print("-" * 70)
        print(f"Total CVEs in Database: {stats['total_cves']}")
        print(f"  ├─ Critical: {stats['critical']}")
        print(f"  ├─ High: {stats['high']}")
        print(f"  ├─ Medium: {stats['medium']}")
        print(f"  └─ Low: {stats['low']}")
        print("")
        print(f"CVEs with Known Exploits: {stats['with_exploits']}")
        print(f"CVEs with POC Exploits: {stats['with_pocs']}")
        print(f"Relevant to Infrastructure: {stats['relevant']}")
        print(f"Unprocessed CVEs: {stats['unprocessed']}")
        print("")
        
        print("RECENT ACTIVITY (24 HOURS)")
        print("-" * 70)
        print(f"New CVEs: {stats['new_24h']}")
        print(f"Updated CVEs: {stats['updated_24h']}")
        print("")
        
        print("⚠️  CRITICAL ALERTS")
        print("-" * 70)
        print(f"High/Critical CVEs with Exploits (Infrastructure): {stats['critical_exploits']}")
        if stats['critical_exploits'] > 0:
            print("   ⚠️  IMMEDIATE ACTION REQUIRED")
        print("")
        
        if stats['top_assets']:
            print("TOP AFFECTED ASSETS")
            print("-" * 70)
            for asset_data, count in stats['top_assets'][:5]:
                try:
                    assets = json.loads(asset_data)
                    print(f"  {', '.join(assets)}: {count} CVEs")
                except:
                    pass
            print("")
        
        print("=" * 70)


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
  %(prog)s --new --output report.txt     # Save to file
  %(prog)s --new --mark-processed        # Mark shown CVEs as processed
  %(prog)s --dashboard                    # Show dashboard summary

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
    
    # Options
    parser.add_argument('--hours', type=int, default=24,
                       help='Hours to look back (default: 24)')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--output', type=str,
                       help='Output filename (default: stdout)')
    parser.add_argument('--mark-processed', action='store_true',
                       help='Mark displayed CVEs as processed')
    
    args = parser.parse_args()
    
    # CVE detail lookup
    if args.cve:
        cve_id = normalize_cve_id(args.cve)
        with CVEReporter() as reporter:
            cve = reporter.get_cve_by_id(cve_id)
            if cve is None:
                print(f"No data found for {cve_id}.")
                print("Run the collector to ingest new CVEs: python cve_collector.py")
                sys.exit(1)
            if args.format == 'json':
                output = reporter.format_cve_detail_json(cve)
            else:
                output = reporter.format_cve_detail(cve)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(output)
            else:
                print(output)
            if args.mark_processed:
                reporter.mark_as_processed([cve_id])
                print(f"\nMarked {cve_id} as processed")
        sys.exit(0)

    # Show dashboard if requested
    if args.dashboard:
        with CVEReporter() as reporter:
            reporter.generate_dashboard()
        return
    
    # Determine which report to generate
    with CVEReporter() as reporter:

        # Validate --category early so invalid names exit before any query
        category = _validate_category(args.category) if args.category else None

        # Resolve deprecated aliases — OR with modern equivalents so that
        # --with-exploits and --with-pocs still work and pass the no_flags check
        exploits_only  = bool(args.exploits_only) or bool(args.with_exploits)
        pocs_only_flag = bool(args.pocs_only) or bool(args.with_pocs)

        severities = ([s.strip().upper() for s in args.severity.split(',')]
                      if args.severity else None)

        # Detect whether any actionable flag was supplied
        no_flags = not any([args.new, args.updated, args.unprocessed, args.relevant,
                            args.since, args.critical, severities, category,
                            args.asset, exploits_only, pocs_only_flag])
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
        )

        cursor = reporter.conn.cursor()
        cursor.execute(sql, params)
        cves = cursor.fetchall()

        if not cves:
            print("No CVEs found matching the specified filters.")
            sys.exit(0)

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

        title = "CVEs — " + " | ".join(title_parts) if title_parts else "All CVEs"

        reporter.generate_report(cves, title, args.format, args.output)

        # Mark as processed if requested
        if args.mark_processed and cves:
            cve_ids = [cve['id'] for cve in cves]
            reporter.mark_as_processed(cve_ids)
            print(f"\nMarked {len(cve_ids)} CVEs as processed")


if __name__ == "__main__":
    main()
