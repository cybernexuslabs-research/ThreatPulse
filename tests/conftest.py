"""
Shared pytest fixtures for the timeline-view test suite (see
docs/features/TIMELINE_VIEW_FEATURE.md). ThreatPulse is a flat script
layout, not an installable package, so this file's first job is making
cve_collector.py / cve_reporter.py / events.py / config.py importable
regardless of where pytest is invoked from.

Tests must still be run with the repo root as the working directory
(`pytest` from the top level), same as cve_collector.py/cve_reporter.py
themselves require -- both read schema.sql via a bare relative path, with
no override for that.
"""

import os
import sqlite3
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(REPO_ROOT, "schema.sql")

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


@pytest.fixture
def db_path(tmp_path):
    """Path to a throwaway sqlite DB with the full current schema.sql applied.

    tmp_path is a pytest built-in fixture (a fresh directory per test,
    cleaned up automatically) -- nothing here ever touches the real
    cves.db in the repo root.
    """
    path = str(tmp_path / "test.db")
    conn = sqlite3.connect(path)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def bare_cves_db(tmp_path):
    """Path to a DB with ONLY a pre-collections, pre-timeline `cves` table --
    no has_poc/poc_urls/poc_source columns, no collections/collection_members,
    no cve_events. Simulates a database that predates every feature that
    migrate_database()/CVEReporter's self-healing schema checks are
    responsible for backfilling (see M2/M5). Deliberately NOT built from
    schema.sql, which is the thing being tested against it.
    """
    path = str(tmp_path / "bare.db")
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE cves (
            id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            published_date TEXT NOT NULL,
            last_updated_date TEXT,
            base_score REAL,
            base_severity TEXT,
            affects_infrastructure BOOLEAN DEFAULT 0,
            affected_categories TEXT,
            affected_assets TEXT,
            relevance_score REAL DEFAULT 0,
            has_known_exploit BOOLEAN DEFAULT 0,
            exploit_added_date TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed BOOLEAN DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()
    return path
