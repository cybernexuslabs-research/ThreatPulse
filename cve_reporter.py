#!/usr/bin/env python3
"""
ThreatPulse - CVE Reporter Service
Continuous CVE threat monitoring and reporting tool.
Generates reports from CVE database on-demand.
Supports multiple output formats and filtering options.
"""

import sqlite3
import json
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import config

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
        """Get CVEs affecting a specific asset"""
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
  %(prog)s --asset mysql --with-exploits  # MySQL CVEs with exploits
  %(prog)s --exploits-only                # All CVEs with known exploits
  %(prog)s --pocs-only                    # All CVEs with POC exploits
  %(prog)s --new --with-pocs             # New CVEs that have POCs
  %(prog)s --relevant                     # All relevant CVEs
  %(prog)s --since 2024-01-01            # CVEs since date
  %(prog)s --dashboard                    # Show dashboard summary
  %(prog)s --new --format json           # Output as JSON
  %(prog)s --new --output report.txt     # Save to file
  %(prog)s --new --mark-processed        # Mark shown CVEs as processed

Asset configuration flags (processed by config.py before argparse runs):
  --assets-file <path>   Load asset inventory and weights from a JSON file.
                         Falls back to 'assets.json' in the current directory,
                         then to assets.default.json alongside config.py.
  --init-assets          Copy assets.default.json to 'assets.json', then exit.
                         Prompts before overwriting an existing file.

  These flags are consumed by config.py at import time and will NOT appear
  in --help output, but are fully functional alongside any reporter flag.

Cron usage with a custom assets file:
  */30 * * * * /usr/bin/python /opt/threatpulse/cve_reporter.py \\
      --assets-file /etc/threatpulse/assets.json --new --format json \\
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
    parser.add_argument('--critical', action='store_true',
                       help='Show critical CVEs')
    parser.add_argument('--severity', type=str,
                       help='Severity levels (comma-separated: CRITICAL,HIGH,MEDIUM,LOW)')
    parser.add_argument('--asset', type=str,
                       help='Filter by asset name')
    parser.add_argument('--with-exploits', action='store_true',
                       help='Only show CVEs with known exploits (use with --asset)')
    parser.add_argument('--exploits-only', action='store_true',
                       help='Show all CVEs with known exploits')
    parser.add_argument('--pocs-only', action='store_true',
                       help='Show all CVEs with POC exploits')
    parser.add_argument('--with-pocs', action='store_true',
                       help='Filter results to only show CVEs with POCs')
    parser.add_argument('--relevant', action='store_true',
                       help='Show all CVEs relevant to infrastructure')
    parser.add_argument('--since', type=str,
                       help='Show CVEs since date (YYYY-MM-DD)')
    parser.add_argument('--dashboard', action='store_true',
                       help='Show dashboard summary')
    
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
    
    # Show dashboard if requested
    if args.dashboard:
        with CVEReporter() as reporter:
            reporter.generate_dashboard()
        return
    
    # Determine which report to generate
    with CVEReporter() as reporter:
        cves = []
        title = ""
        
        if args.new:
            cves = reporter.get_new_cves(args.hours)
            title = f"New CVEs (Last {args.hours} Hours)"
        
        elif args.updated:
            cves = reporter.get_updated_cves(args.hours)
            title = f"Updated CVEs (Last {args.hours} Hours)"
        
        elif args.unprocessed:
            cves = reporter.get_unprocessed_cves()
            title = "Unprocessed CVEs"
        
        elif args.critical:
            cves = reporter.get_cves_by_severity(['CRITICAL'])
            title = "Critical CVEs"
        
        elif args.severity:
            severities = [s.strip().upper() for s in args.severity.split(',')]
            cves = reporter.get_cves_by_severity(severities)
            title = f"CVEs - Severity: {', '.join(severities)}"
        
        elif args.asset:
            cves = reporter.get_cves_by_asset(args.asset, args.with_exploits)
            title = f"CVEs Affecting: {args.asset}"
            if args.with_exploits:
                title += " (With Known Exploits)"
        
        elif args.exploits_only:
            cves = reporter.get_exploit_cves()
            title = "CVEs with Known Exploits"

        elif args.pocs_only:
            cves = reporter.get_poc_cves()
            title = "CVEs with POC Exploits"

        elif args.relevant:
            cves = reporter.get_relevant_cves()
            title = "Relevant CVEs (Infrastructure)"
        
        elif args.since:
            cves = reporter.get_cves_since_date(args.since)
            title = f"CVEs Since {args.since}"
        
        else:
            parser.print_help()
            return
        
        # Apply --with-pocs filter if specified
        if args.with_pocs and cves:
            cves = [cve for cve in cves if cve['has_poc']]
            title += " (With POCs)"

        # Generate report
        if args.output:
            filename = args.output
        else:
            filename = None
        
        reporter.generate_report(cves, title, args.format, filename)
        
        # Mark as processed if requested
        if args.mark_processed and cves:
            cve_ids = [cve['id'] for cve in cves]
            reporter.mark_as_processed(cve_ids)
            print(f"\nMarked {len(cve_ids)} CVEs as processed")


if __name__ == "__main__":
    main()
