#!/usr/bin/env python3
"""
ThreatPulse - CVE Collector Service
Continuous CVE threat monitoring and reporting tool.
Downloads and processes CVE data, updates database only.
Run via cron every 30 minutes or as needed.
"""

import csv
import io
import json
import re
import requests
import zipfile
import os
import sqlite3
import logging
from datetime import datetime
from typing import Dict, Set, Tuple, Optional, List
import config

# Setup logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT
)
logger = logging.getLogger(__name__)


class CVECollector:
    """Collects and processes CVE data from NVD and CISA KEV"""
    
    def __init__(self, db_path: str = config.DB_PATH):
        self.db_path = db_path
        self.json_filename = "nvdcve-2.0-recent.json"
        self.zip_filename = "nvdcve-2.0-recent.json.zip"
        
    def initialize_database(self):
        """Initialize database with schema"""
        logger.info("Initializing database...")
        conn = sqlite3.connect(self.db_path)

        # Read and execute schema
        with open('schema.sql', 'r') as f:
            schema = f.read()
            conn.executescript(schema)

        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")

    def migrate_database(self):
        """Add POC columns to existing database if missing"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(cves)")
        columns = {row[1] for row in cursor.fetchall()}

        new_columns = [
            ("has_poc", "BOOLEAN DEFAULT 0"),
            ("poc_urls", "TEXT"),
            ("poc_source", "TEXT"),
        ]
        for col_name, col_type in new_columns:
            if col_name not in columns:
                logger.info(f"Adding column {col_name} to cves table")
                cursor.execute(f"ALTER TABLE cves ADD COLUMN {col_name} {col_type}")

        # Recreate view and index from schema
        cursor.execute("DROP VIEW IF EXISTS cve_stats")
        cursor.execute("DROP INDEX IF EXISTS idx_poc")
        with open('schema.sql', 'r') as f:
            schema = f.read()
        for statement in schema.split(';'):
            stmt = statement.strip()
            if 'CREATE VIEW' in stmt or 'CREATE INDEX IF NOT EXISTS idx_poc' in stmt:
                cursor.execute(stmt)

        conn.commit()
        conn.close()
    
    def download_nvd_feed(self) -> bool:
        """Download NVD recent CVE feed"""
        try:
            logger.info("Downloading NVD CVE feed...")
            response = requests.get(config.NVD_RECENT_URL, timeout=config.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            with open(self.zip_filename, "wb") as f:
                f.write(response.content)
            
            logger.info("Unzipping CVE feed...")
            with zipfile.ZipFile(self.zip_filename, "r") as zip_ref:
                zip_ref.extractall()
            
            logger.info("NVD feed downloaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download NVD feed: {e}")
            return False
    
    def download_cisa_kev(self) -> Set[str]:
        """Download CISA Known Exploited Vulnerabilities catalog"""
        try:
            logger.info("Downloading CISA KEV catalog...")
            response = requests.get(config.CISA_KEV_URL, timeout=config.REQUEST_TIMEOUT)
            response.raise_for_status()
            kev_data = response.json()
            
            exploited_cves = set()
            for vuln in kev_data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                if cve_id:
                    exploited_cves.add(cve_id)
            
            logger.info(f"Found {len(exploited_cves)} CVEs in CISA KEV catalog")
            return exploited_cves
            
        except Exception as e:
            logger.error(f"Failed to download CISA KEV catalog: {e}")
            return set()
    
    def download_exploitdb_csv(self) -> Dict[str, List[str]]:
        """Download ExploitDB CSV and build CVE-to-URL mapping"""
        exploitdb_map = {}
        try:
            logger.info("Downloading ExploitDB CSV...")
            response = requests.get(config.EXPLOITDB_CSV_URL, timeout=60)
            response.raise_for_status()

            reader = csv.DictReader(io.StringIO(response.text))
            for row in reader:
                codes = row.get('codes', '')
                edb_id = row.get('id', '')
                if not codes or not edb_id:
                    continue
                for code in codes.split(';'):
                    code = code.strip()
                    if code.startswith('CVE-'):
                        url = f"https://www.exploit-db.com/exploits/{edb_id}"
                        if code not in exploitdb_map:
                            exploitdb_map[code] = []
                        exploitdb_map[code].append(url)

            logger.info(f"ExploitDB: mapped {len(exploitdb_map)} CVEs to exploits")
        except Exception as e:
            logger.error(f"Failed to download ExploitDB CSV: {e}")
        return exploitdb_map

    def check_poc_github(self, cve_id: str) -> List[str]:
        """Check nomi-sec/PoC-in-GitHub for POC repos"""
        try:
            year = cve_id.split('-')[1]
            url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                pocs = response.json()
                if isinstance(pocs, list) and pocs:
                    return [p['html_url'] for p in pocs if p.get('html_url')]
        except Exception as e:
            logger.debug(f"GitHub POC check failed for {cve_id}: {e}")
        return []

    def check_poc_cvedb(self, cve_id: str) -> List[str]:
        """Check CVEDB (Shodan) for POC references"""
        poc_indicators = ['exploit', 'poc', 'proof-of-concept', 'github.com']
        try:
            url = f"https://cvedb.shodan.io/cve/{cve_id}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                refs = data.get('references', [])
                return [r for r in refs if any(ind in r.lower() for ind in poc_indicators)]
        except Exception as e:
            logger.debug(f"CVEDB check failed for {cve_id}: {e}")
        return []

    def check_poc(self, cve_id: str, exploitdb_map: Dict[str, List[str]]) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check multiple sources for POC exploits.
        Returns: (has_poc, poc_urls_json, poc_source_json)
        """
        all_urls = []
        sources = []

        # 1. ExploitDB (from pre-downloaded CSV, no network call)
        edb_urls = exploitdb_map.get(cve_id, [])
        if edb_urls:
            all_urls.extend(edb_urls)
            sources.append('exploitdb')

        # 2. GitHub PoC-in-GitHub (disabled: rate limited to 60 req/hr unauthenticated)
        # github_urls = self.check_poc_github(cve_id)
        # if github_urls:
        #     all_urls.extend(github_urls)
        #     sources.append('github')

        # 3. CVEDB (Shodan)
        cvedb_urls = self.check_poc_cvedb(cve_id)
        if cvedb_urls:
            all_urls.extend(cvedb_urls)
            if 'cvedb' not in sources:
                sources.append('cvedb')

        if all_urls:
            # Deduplicate URLs
            unique_urls = list(dict.fromkeys(all_urls))
            return True, json.dumps(unique_urls), json.dumps(sources)

        return False, None, None

    def check_relevance(self, description: str) -> Tuple[bool, Optional[List[str]], Optional[List[str]]]:
        """
        Check if CVE affects our infrastructure
        Returns: (is_relevant, categories, assets)
        """
        if not description:
            return False, None, None
        
        desc_lower = description.lower()
        found_categories = []
        found_assets = []

        for category, assets in config.MY_ASSETS.items():
            for asset in assets:
                if re.search(r'\b' + re.escape(asset.lower()) + r'\b', desc_lower):
                    if category not in found_categories:
                        found_categories.append(category)
                    if asset not in found_assets:
                        found_assets.append(asset)
        
        is_relevant = len(found_categories) > 0
        return is_relevant, found_categories if is_relevant else None, found_assets if is_relevant else None
    
    def calculate_relevance_score(self, categories: Optional[List[str]], base_score: Optional[float]) -> float:
        """Calculate relevance score based on asset criticality and CVSS score"""
        if not base_score or not categories:
            return 0.0
        
        # Use the highest weight from all matching categories
        max_weight = max([config.CATEGORY_WEIGHTS.get(cat, 0.5) for cat in categories])
        return base_score * max_weight
    
    def parse_cve_data(self, cve_item: dict, known_exploits: Set[str], exploitdb_map: Dict[str, List[str]] = None) -> Optional[dict]:
        """Parse a single CVE item from NVD feed"""
        try:
            cve = cve_item.get('cve', {})
            cve_id = cve.get('id')
            if not cve_id:
                return None
            
            published_date = cve.get('published')
            
            # Get English description
            description = next(
                (desc['value'] for desc in cve.get('descriptions', []) if desc['lang'] == 'en'),
                None
            )
            
            # Extract CVSS metrics (prefer NVD v3.1, fallback to v4.0, then v2)
            base_score = None
            base_severity = None
            metrics = cve.get('metrics', {})
            
            # Try CVSS v3.1 (NVD preferred)
            v31_metrics = metrics.get('cvssMetricV31', [])
            nvd_v31 = [m for m in v31_metrics if m.get('source') == 'nvd@nist.gov']
            use_metric = None
            
            if nvd_v31:
                use_metric = max(nvd_v31, key=lambda m: m['cvssData'].get('baseScore', 0))
            elif v31_metrics:
                use_metric = max(v31_metrics, key=lambda m: m['cvssData'].get('baseScore', 0))
            
            if use_metric:
                base_score = use_metric['cvssData'].get('baseScore')
                base_severity = use_metric['cvssData'].get('baseSeverity')
            
            # Fallback to v4.0
            if base_score is None:
                v40_metrics = metrics.get('cvssMetricV40', [])
                if v40_metrics:
                    use_metric = max(v40_metrics, key=lambda m: m['cvssData'].get('baseScore', 0))
                    base_score = use_metric['cvssData'].get('baseScore')
                    base_severity = use_metric['cvssData'].get('baseSeverity')
            
            # Fallback to v2
            if base_score is None:
                v2_metrics = metrics.get('cvssMetricV2', [])
                if v2_metrics:
                    use_metric = max(v2_metrics, key=lambda m: m['cvssData'].get('baseScore', 0))
                    base_score = use_metric['cvssData'].get('baseScore')
                    base_severity = use_metric.get('baseSeverity') or use_metric['cvssData'].get('baseSeverity')
            
            # Check relevance to our infrastructure
            is_relevant, categories, assets = self.check_relevance(description)
            relevance_score = self.calculate_relevance_score(categories, base_score) if is_relevant else 0.0
            
            # Check for known exploits
            has_exploit = cve_id in known_exploits

            # Check for POCs (only for relevant CVEs to avoid thousands of API calls)
            has_poc = False
            poc_urls = None
            poc_source = None
            if exploitdb_map is not None and (is_relevant or has_exploit):
                has_poc, poc_urls, poc_source = self.check_poc(cve_id, exploitdb_map)

            return {
                'id': cve_id,
                'description': description,
                'published_date': published_date,
                'base_score': base_score,
                'base_severity': base_severity or 'NONE',
                'affects_infrastructure': is_relevant,
                'affected_categories': json.dumps(categories) if categories else None,
                'affected_assets': json.dumps(assets) if assets else None,
                'relevance_score': relevance_score,
                'has_known_exploit': has_exploit,
                'has_poc': has_poc,
                'poc_urls': poc_urls,
                'poc_source': poc_source
            }
            
        except Exception as e:
            logger.error(f"Error parsing CVE: {e}")
            return None
    
    def upsert_cve(self, conn: sqlite3.Connection, cve_data: dict):
        """
        Insert or update CVE using UPSERT logic (Option 3)
        Preserves first_seen, updates everything else
        """
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            INSERT INTO cves (
                id, description, base_score, base_severity,
                published_date, has_known_exploit,
                affected_categories, affected_assets, relevance_score,
                affects_infrastructure,
                has_poc, poc_urls, poc_source,
                first_seen, last_checked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                description = excluded.description,
                base_score = excluded.base_score,
                base_severity = excluded.base_severity,
                has_known_exploit = excluded.has_known_exploit,
                affected_categories = excluded.affected_categories,
                affected_assets = excluded.affected_assets,
                relevance_score = excluded.relevance_score,
                affects_infrastructure = excluded.affects_infrastructure,
                has_poc = excluded.has_poc,
                poc_urls = excluded.poc_urls,
                poc_source = excluded.poc_source,
                last_checked = excluded.last_checked,
                last_updated_date = CASE
                    WHEN cves.base_score != excluded.base_score
                         OR cves.base_severity != excluded.base_severity
                         OR cves.has_known_exploit != excluded.has_known_exploit
                         OR cves.has_poc != excluded.has_poc
                    THEN excluded.last_checked
                    ELSE cves.last_updated_date
                END,
                processed = CASE
                    WHEN cves.base_score != excluded.base_score
                         OR cves.base_severity != excluded.base_severity
                         OR cves.has_known_exploit != excluded.has_known_exploit
                         OR cves.has_poc != excluded.has_poc
                    THEN 0
                    ELSE cves.processed
                END
        """, (
            cve_data['id'],
            cve_data['description'],
            cve_data['base_score'],
            cve_data['base_severity'],
            cve_data['published_date'],
            cve_data['has_known_exploit'],
            cve_data['affected_categories'],
            cve_data['affected_assets'],
            cve_data['relevance_score'],
            cve_data['affects_infrastructure'],
            cve_data['has_poc'],
            cve_data['poc_urls'],
            cve_data['poc_source'],
            now,  # first_seen
            now   # last_checked
        ))
    
    def collect(self):
        """Main collection process"""
        logger.info("=" * 60)
        logger.info("CVE Collection Started")
        logger.info(f"Timestamp: {datetime.now().isoformat()}")
        logger.info("=" * 60)
        
        # Initialize database if needed
        if not os.path.exists(self.db_path):
            self.initialize_database()
        else:
            self.migrate_database()

        # Download feeds
        if not self.download_nvd_feed():
            logger.error("Failed to download NVD feed, aborting")
            return

        known_exploits = self.download_cisa_kev()
        exploitdb_map = self.download_exploitdb_csv()
        
        # Load and parse CVE data
        logger.info("Parsing CVE data...")
        try:
            with open(self.json_filename, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load CVE JSON: {e}")
            return
        
        # Process CVEs and update database
        conn = sqlite3.connect(self.db_path)
        stats = {
            'total': 0,
            'new': 0,
            'updated': 0,
            'critical': 0,
            'high': 0,
            'relevant': 0,
            'exploited': 0,
            'with_poc': 0
        }
        vulnerabilities = data.get('vulnerabilities', [])
        logger.info(f"Processing {len(vulnerabilities)} CVEs...")

        for item in vulnerabilities:
            cve_data = self.parse_cve_data(item, known_exploits, exploitdb_map)
            if not cve_data:
                continue

            # Check if this is a new or updated CVE
            cursor = conn.cursor()
            cursor.execute("SELECT base_score, base_severity, has_known_exploit FROM cves WHERE id = ?",
                          (cve_data['id'],))
            existing = cursor.fetchone()

            if existing:
                # Check if anything changed
                old_score, old_severity, old_exploit = existing
                if (old_score != cve_data['base_score'] or
                    old_severity != cve_data['base_severity'] or
                    old_exploit != cve_data['has_known_exploit']):
                    stats['updated'] += 1
                    logger.info(f"Updated: {cve_data['id']} - Score: {old_score}->{cve_data['base_score']}, "
                               f"Severity: {old_severity}->{cve_data['base_severity']}, "
                               f"Exploit: {old_exploit}->{cve_data['has_known_exploit']}")
            else:
                stats['new'] += 1
                logger.debug(f"New: {cve_data['id']} - {cve_data['base_severity']} ({cve_data['base_score']})")

            # UPSERT the CVE
            self.upsert_cve(conn, cve_data)

            # Update statistics
            stats['total'] += 1
            if cve_data['base_severity'] == 'CRITICAL':
                stats['critical'] += 1
            elif cve_data['base_severity'] == 'HIGH':
                stats['high'] += 1

            if cve_data['affects_infrastructure']:
                stats['relevant'] += 1

            if cve_data['has_known_exploit']:
                stats['exploited'] += 1

            if cve_data['has_poc']:
                stats['with_poc'] += 1
        
        conn.commit()
        
        # Get overall database stats
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cve_stats")
        db_stats = cursor.fetchone()
        
        conn.close()
        
        # Log summary
        logger.info("=" * 60)
        logger.info("Collection Summary")
        logger.info("=" * 60)
        logger.info(f"CVEs Processed: {stats['total']}")
        logger.info(f"New CVEs: {stats['new']}")
        logger.info(f"Updated CVEs: {stats['updated']}")
        logger.info(f"Critical: {stats['critical']}")
        logger.info(f"High: {stats['high']}")
        logger.info(f"Relevant to Infrastructure: {stats['relevant']}")
        logger.info(f"With Known Exploits: {stats['exploited']}")
        logger.info(f"With POCs: {stats['with_poc']}")
        logger.info("")
        logger.info("Database Totals:")
        logger.info(f"Total CVEs in DB: {db_stats[0]}")
        logger.info(f"Critical: {db_stats[1]} | High: {db_stats[2]} | Medium: {db_stats[3]} | Low: {db_stats[4]}")
        logger.info(f"Known Exploits: {db_stats[5]}")
        logger.info(f"Relevant to Infrastructure: {db_stats[6]}")
        logger.info(f"Unprocessed: {db_stats[7]}")
        logger.info(f"With POCs: {db_stats[8]}")
        logger.info("=" * 60)
        
        # Cleanup
        try:
            os.remove(self.zip_filename)
            os.remove(self.json_filename)
        except:
            pass


def main():
    collector = CVECollector()
    collector.collect()


if __name__ == "__main__":
    main()
