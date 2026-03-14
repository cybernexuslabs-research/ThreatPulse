# ThreatPulse - Quick Reference Card

## Setup (One Time)
```bash
pip install -r requirements.txt
python3 setup.py
```

## Data Collection (Automated)
```bash
# Manual run
./cve_collector.py

# Cron (every 30 min)
*/30 * * * * cd /path/to/ThreatPulse && ./cve_collector.py >> /var/log/cve.log 2>&1
```

## Common Reports

### Dashboard
```bash
./cve_reporter.py --dashboard
```

### New CVEs
```bash
./cve_reporter.py --new                    # Last 24 hours
./cve_reporter.py --new --hours 48         # Last 48 hours
```

### By Severity
```bash
./cve_reporter.py --critical               # Critical only
./cve_reporter.py --severity HIGH          # High only
./cve_reporter.py --severity HIGH,CRITICAL # High + Critical
```

### Exploits
```bash
./cve_reporter.py --exploits-only          # All with exploits
./cve_reporter.py --updated                # Recently updated (new exploits)
```

### POC Exploits
```bash
./cve_reporter.py --pocs-only             # All CVEs with POC exploits
./cve_reporter.py --new --with-pocs       # New CVEs that have POCs
./cve_reporter.py --critical --with-pocs  # Critical CVEs with POCs
```

### By Asset
```bash
./cve_reporter.py --asset nginx            # All nginx CVEs
./cve_reporter.py --asset mysql --with-exploits  # MySQL + exploits
./cve_reporter.py --relevant               # All relevant to infrastructure
```

### Unprocessed
```bash
./cve_reporter.py --unprocessed            # Not yet reviewed
./cve_reporter.py --unprocessed --mark-processed  # Review and mark
```

### Time-Based
```bash
./cve_reporter.py --since 2024-01-01       # Since specific date
./cve_reporter.py --new --hours 168        # Last 7 days
```

## Output Options

### Formats
```bash
./cve_reporter.py --new --format text      # Text (default)
./cve_reporter.py --new --format json      # JSON
```

### Save to File
```bash
./cve_reporter.py --critical --output critical.txt
./cve_reporter.py --exploits-only --format json --output exploits.json
```

## Database Queries (Direct)
```bash
# View stats
sqlite3 cves.db "SELECT * FROM cve_stats"

# Count by severity
sqlite3 cves.db "SELECT base_severity, COUNT(*) FROM cves GROUP BY base_severity"

# Recent exploits
sqlite3 cves.db "SELECT id, base_score FROM cves WHERE has_known_exploit=1 ORDER BY base_score DESC LIMIT 10"
```

## Configuration
```bash
# Edit assets and weights
nano config.py

# After editing, re-run collector
./cve_collector.py
```

## Daily Workflow Example
```bash
# Morning check
./cve_reporter.py --dashboard

# Review new high/critical
./cve_reporter.py --severity CRITICAL,HIGH --new

# Check new exploits
./cve_reporter.py --exploits-only --updated

# Check for POCs
./cve_reporter.py --pocs-only --new

# Review unprocessed relevant CVEs
./cve_reporter.py --relevant --unprocessed --mark-processed
```

## Automation Examples

### Daily Email Report
```bash
# Cron: 7 AM daily
0 7 * * * cd /path/to/ThreatPulse && ./cve_reporter.py --unprocessed --output /tmp/daily.txt --mark-processed && mail -s "Daily CVE Report" you@example.com < /tmp/daily.txt
```

### Weekly Summary
```bash
# Cron: Monday 9 AM
0 9 * * 1 cd /path/to/ThreatPulse && ./cve_reporter.py --new --hours 168 --output /tmp/weekly.txt && mail -s "Weekly CVE Summary" you@example.com < /tmp/weekly.txt
```

### Slack/Teams Webhook
```bash
# Generate JSON and POST to webhook
./cve_reporter.py --exploits-only --format json | curl -X POST -H 'Content-Type: application/json' -d @- YOUR_WEBHOOK_URL
```

## Troubleshooting

### Database locked
```bash
ps aux | grep cve_collector
pkill -f cve_collector
```

### Reset processed flags
```bash
sqlite3 cves.db "UPDATE cves SET processed = 0"
```

### Re-initialize database
```bash
rm cves.db
python3 setup.py
```

## File Structure
```
ThreatPulse/
├── config.py              # Edit this for your assets
├── cve_collector.py       # Run via cron
├── cve_reporter.py        # Run manually
├── schema.sql             # Database schema
├── setup.py              # Initial setup
├── cves.db               # Your database
├── README.md             # Full docs
└── MIGRATION.md          # Migration guide
```

## Quick Tips

✅ **DO:**
- Run collector regularly (cron every 30 min)
- Customize config.py for your environment
- Use --mark-processed to track reviews
- Check dashboard daily
- Focus on --relevant and --exploits-only

❌ **DON'T:**
- Edit database directly (use reporter)
- Run collector and reporter simultaneously
- Forget to mark CVEs as processed
- Ignore updated CVEs (--updated flag)

## Help
```bash
./cve_reporter.py --help    # See all options
cat README.md               # Full documentation
cat MIGRATION.md            # Migration from old script
```
