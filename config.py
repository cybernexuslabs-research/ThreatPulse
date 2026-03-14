"""
ThreatPulse - Shared configuration
Continuous CVE threat monitoring and reporting tool.
"""

# Asset inventory - customize this for your environment
MY_ASSETS = {
    'web_servers': ['apache', 'nginx', 'iis', 'httpd', 'tomcat'],
    'operating_systems': ['windows', 'ubuntu', 'centos', 'rhel', 'linux', 'macos'],
    'databases': ['mysql', 'postgresql', 'sql server', 'oracle', 'mongodb', 'mssql'],
    'network_devices': ['cisco', 'palo alto', 'fortinet', 'juniper', 'f5'],
    'cloud_services': ['aws', 'azure', 'google cloud', 'office 365', 'oci'],
    'applications': ['wordpress', 'drupal', 'joomla', 'exchange', 'sharepoint'],
    'pam_tools': ['delinea', 'cyberark', 'thycotic', 'one identity', 'okta', 'beyond trust', 'strongdm', 'duo'],
    'security_tools': ['splunk', 'sentinel', 'crowdstrike', 'defender', 'firewall'],
    'types': ['buffer overflow', 'xss', 'csrf', 'xsrf', 'sql injection', 'rce', 'directory traversal'],
    'devops': ['ansible', 'terraform', 'jenkins', 'git', 'github', 'gitlab', 'docker', 'kubernetes', 'openshift'],
    'ai': ['chatgpt', 'gpt-4', 'bard', 'claude', 'dall-e', 'midjourney', 'openclaw']
}

# Asset criticality weights for relevance scoring
CATEGORY_WEIGHTS = {
    'web_servers': 1.0,        # High - internet facing
    'databases': 0.9,          # High - sensitive data
    'operating_systems': 0.8,  # Medium-High - widespread
    'security_tools': 1.0,     # High - security impact
    'pam_tools': 1.0,          # High - privileged access
    'network_devices': 0.7,    # Medium - infrastructure
    'cloud_services': 0.9,     # High - business critical
    'applications': 0.6,       # Medium - depends on app
    'devops': 0.7,             # Medium - CI/CD impact
    'ai': 0.5,                 # Medium-Low - emerging
    'types': 0.8               # Medium-High - attack vectors
}

# Database configuration
DB_PATH = 'cves.db'

# NVD Feed URLs
NVD_RECENT_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip"

# CISA KEV Catalog URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ExploitDB CSV URL
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# Request timeout (seconds)
REQUEST_TIMEOUT = 30

# Logging configuration
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'INFO'
