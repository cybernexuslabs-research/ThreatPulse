"""
Tests for the cve_events schema, migration, and collector-side event
writing (docs/features/TIMELINE_VIEW_FEATURE.md, modules M1/M2/M3/M4).

See tests/test_timeline.py for the reporter-side (M5/M6/M7) tests.
"""

import json
import sqlite3

from cve_collector import CVECollector
from events import record_event


# ---------------------------------------------------------------------------
# M1: schema.sql
# ---------------------------------------------------------------------------

class TestSchema:
    def test_cve_events_table_and_indexes_exist(self, db_path):
        conn = sqlite3.connect(db_path)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "cve_events" in tables

        indexes = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"idx_cve_events_cve_id", "idx_cve_events_type"} <= indexes

    def test_fk_cascades_on_cve_delete(self, db_path):
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            "INSERT INTO cves (id, description, published_date) "
            "VALUES ('CVE-2026-1', 'x', '2026-01-01')")
        conn.execute(
            "INSERT INTO cve_events (cve_id, event_type, event_date, detail) "
            "VALUES ('CVE-2026-1', 'ingested', '2026-01-01T00:00:00', '{}')")
        conn.commit()

        conn.execute("DELETE FROM cves WHERE id = 'CVE-2026-1'")
        conn.commit()

        count = conn.execute("SELECT COUNT(*) FROM cve_events").fetchone()[0]
        assert count == 0, "cve_events rows should cascade-delete with their CVE"


# ---------------------------------------------------------------------------
# M2: migrate_database()
# ---------------------------------------------------------------------------

class TestMigrateDatabase:
    def test_backfills_poc_columns_and_new_tables_on_old_db(self, bare_cves_db):
        conn = sqlite3.connect(bare_cves_db)
        conn.execute(
            "INSERT INTO cves (id, description, published_date) "
            "VALUES ('CVE-2020-1', 'old row', '2020-01-01')")
        conn.commit()
        conn.close()

        CVECollector(db_path=bare_cves_db).migrate_database()

        conn = sqlite3.connect(bare_cves_db)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(cves)")}
        assert {"has_poc", "poc_urls", "poc_source"} <= cols

        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"collections", "collection_members", "cve_events"} <= tables

        views = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='view'")}
        assert "cve_stats" in views

        # the pre-existing row must survive migration untouched
        row = conn.execute(
            "SELECT id, description FROM cves").fetchone()
        assert row == ("CVE-2020-1", "old row")

    def test_idempotent(self, bare_cves_db):
        collector = CVECollector(db_path=bare_cves_db)
        collector.migrate_database()
        collector.migrate_database()  # must not raise or duplicate anything

        conn = sqlite3.connect(bare_cves_db)
        assert conn.execute("SELECT COUNT(*) FROM sqlite_master "
                             "WHERE type='table' AND name='cve_events'").fetchone()[0] == 1


# ---------------------------------------------------------------------------
# M3: events.record_event()
# ---------------------------------------------------------------------------

class TestRecordEvent:
    def test_serializes_detail_and_defaults_to_empty_dict(self, db_path):
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO cves (id, description, published_date) "
            "VALUES ('CVE-2026-1', 'x', '2026-01-01')")

        record_event(conn, "CVE-2026-1", "cvss_changed", {"from": 7.5, "to": 9.8})
        record_event(conn, "CVE-2026-1", "ingested")  # detail=None
        conn.commit()

        rows = conn.execute(
            "SELECT event_type, detail FROM cve_events ORDER BY id").fetchall()
        assert json.loads(rows[0][1]) == {"from": 7.5, "to": 9.8}
        assert json.loads(rows[1][1]) == {}

    def test_event_date_override_for_deterministic_tests(self, db_path):
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO cves (id, description, published_date) "
            "VALUES ('CVE-2026-1', 'x', '2026-01-01')")
        record_event(conn, "CVE-2026-1", "kev_added", {"source": "cisa_kev"},
                      event_date="2026-01-05T00:00:00")
        conn.commit()
        row = conn.execute(
            "SELECT event_date FROM cve_events").fetchone()
        assert row[0] == "2026-01-05T00:00:00"

    def test_does_not_auto_commit(self, db_path):
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO cves (id, description, published_date) "
            "VALUES ('CVE-2026-1', 'x', '2026-01-01')")
        conn.commit()

        record_event(conn, "CVE-2026-1", "poc_added")
        conn.rollback()

        count = conn.execute("SELECT COUNT(*) FROM cve_events").fetchone()[0]
        assert count == 0


# ---------------------------------------------------------------------------
# M4: CVECollector._record_lifecycle_events()
# ---------------------------------------------------------------------------

class TestRecordLifecycleEvents:
    """`old` mirrors the pre-upsert SELECT's shape:
    (base_score, base_severity, has_known_exploit, has_poc, poc_urls).
    """

    def _events(self, conn, cve_id):
        return conn.execute(
            "SELECT event_type, detail FROM cve_events WHERE cve_id = ? ORDER BY id",
            (cve_id,)
        ).fetchall()

    def test_new_cve_writes_only_ingested(self, db_path):
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        cve_data = {"id": "CVE-1", "base_score": 7.5, "base_severity": "HIGH",
                    "has_known_exploit": False, "has_poc": False,
                    "poc_urls": None, "poc_source": None}

        collector._record_lifecycle_events(conn, "CVE-1", None, cve_data)

        ev = self._events(conn, "CVE-1")
        assert [e[0] for e in ev] == ["ingested"]
        assert json.loads(ev[0][1]) == {"cvss": 7.5, "severity": "HIGH"}

    def test_new_cve_already_kev_listed_fires_kev_added(self, db_path):
        """Regression: first-time ingest of a CVE that's already KEV-listed
        must still fire kev_added, not just ingested -- a bare early-return
        on old is None used to skip this entirely.
        """
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        cve_data = {"id": "CVE-1", "base_score": 9.8, "base_severity": "CRITICAL",
                    "has_known_exploit": True, "has_poc": False,
                    "poc_urls": None, "poc_source": None}

        collector._record_lifecycle_events(conn, "CVE-1", None, cve_data)

        types = [e[0] for e in self._events(conn, "CVE-1")]
        assert types == ["ingested", "kev_added"]

    def test_new_cve_already_has_poc_fires_poc_added(self, db_path):
        """Same regression as above, for POCs: a CVE ingested for the first
        time already carrying a POC must fire poc_added, not just ingested.
        """
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        cve_data = {
            "id": "CVE-1", "base_score": 7.5, "base_severity": "HIGH",
            "has_known_exploit": False, "has_poc": True,
            "poc_urls": json.dumps(["https://exploit-db.com/1"]),
            "poc_source": json.dumps(["exploitdb"]),
        }

        collector._record_lifecycle_events(conn, "CVE-1", None, cve_data)

        ev = self._events(conn, "CVE-1")
        assert [e[0] for e in ev] == ["ingested", "poc_added"]
        assert json.loads(ev[1][1]) == {
            "source": ["exploitdb"], "urls": ["https://exploit-db.com/1"],
        }

    def test_new_cve_already_kev_and_poc_fires_both(self, db_path):
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        cve_data = {
            "id": "CVE-1", "base_score": 9.8, "base_severity": "CRITICAL",
            "has_known_exploit": True, "has_poc": True,
            "poc_urls": json.dumps(["https://x/1"]),
            "poc_source": json.dumps(["exploitdb"]),
        }

        collector._record_lifecycle_events(conn, "CVE-1", None, cve_data)

        types = [e[0] for e in self._events(conn, "CVE-1")]
        assert types == ["ingested", "kev_added", "poc_added"]

    def test_new_cve_never_fires_cvss_changed(self, db_path):
        """"Changed" isn't meaningful without a prior score -- unlike
        kev_added/poc_added, cvss_changed must stay new-CVE-exempt.
        """
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        cve_data = {"id": "CVE-1", "base_score": 9.8, "base_severity": "CRITICAL",
                    "has_known_exploit": False, "has_poc": False,
                    "poc_urls": None, "poc_source": None}

        collector._record_lifecycle_events(conn, "CVE-1", None, cve_data)

        assert "cvss_changed" not in [e[0] for e in self._events(conn, "CVE-1")]

    def test_no_changes_writes_nothing(self, db_path):
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        cve_data = {"id": "CVE-1", "base_score": 7.5, "base_severity": "HIGH",
                    "has_known_exploit": False, "has_poc": False,
                    "poc_urls": None, "poc_source": None}
        old = (7.5, "HIGH", False, False, None)

        collector._record_lifecycle_events(conn, "CVE-1", old, cve_data)

        assert self._events(conn, "CVE-1") == []

    def test_cvss_changed(self, db_path):
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        old = (7.5, "HIGH", False, False, None)
        cve_data = {"id": "CVE-1", "base_score": 9.8, "base_severity": "CRITICAL",
                    "has_known_exploit": False, "has_poc": False,
                    "poc_urls": None, "poc_source": None}

        collector._record_lifecycle_events(conn, "CVE-1", old, cve_data)

        ev = self._events(conn, "CVE-1")
        assert ev[-1][0] == "cvss_changed"
        assert json.loads(ev[-1][1]) == {"from": 7.5, "to": 9.8}

    def test_kev_added_collapsed_not_duplicated_with_exploit_confirmed(self, db_path):
        """has_known_exploit is exclusively CISA-KEV-sourced in this collector
        (see download_cisa_kev()/parse_cve_data()), so the doc's separate
        exploit_confirmed event was collapsed into kev_added -- there is no
        second exploit source to make the two meaningfully different.
        """
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        old = (9.8, "CRITICAL", False, False, None)
        cve_data = {"id": "CVE-1", "base_score": 9.8, "base_severity": "CRITICAL",
                    "has_known_exploit": True, "has_poc": False,
                    "poc_urls": None, "poc_source": None}

        collector._record_lifecycle_events(conn, "CVE-1", old, cve_data)

        ev = self._events(conn, "CVE-1")
        assert ev[-1] == ("kev_added", json.dumps({"source": "cisa_kev"}))
        assert "exploit_confirmed" not in [e[0] for e in ev]

    def test_kev_added_does_not_refire_on_1_to_1(self, db_path):
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        old = (9.8, "CRITICAL", True, False, None)
        cve_data = {"id": "CVE-1", "base_score": 9.8, "base_severity": "CRITICAL",
                    "has_known_exploit": True, "has_poc": False,
                    "poc_urls": None, "poc_source": None}

        collector._record_lifecycle_events(conn, "CVE-1", old, cve_data)

        assert self._events(conn, "CVE-1") == []

    def test_poc_added(self, db_path):
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        old = (9.8, "CRITICAL", True, False, None)
        cve_data = {
            "id": "CVE-1", "base_score": 9.8, "base_severity": "CRITICAL",
            "has_known_exploit": True, "has_poc": True,
            "poc_urls": json.dumps(["https://exploit-db.com/1"]),
            "poc_source": json.dumps(["exploitdb"]),
        }

        collector._record_lifecycle_events(conn, "CVE-1", old, cve_data)

        ev = self._events(conn, "CVE-1")
        assert ev[-1][0] == "poc_added"
        assert json.loads(ev[-1][1]) == {
            "source": ["exploitdb"], "urls": ["https://exploit-db.com/1"],
        }

    def test_poc_updated_fires_once_per_new_url_only(self, db_path):
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        old = (9.8, "CRITICAL", True, True, json.dumps(["https://exploit-db.com/1"]))
        cve_data = {
            "id": "CVE-1", "base_score": 9.8, "base_severity": "CRITICAL",
            "has_known_exploit": True, "has_poc": True,
            "poc_urls": json.dumps(["https://exploit-db.com/1", "https://cvedb.example/2"]),
            "poc_source": json.dumps(["exploitdb", "cvedb"]),
        }

        collector._record_lifecycle_events(conn, "CVE-1", old, cve_data)

        ev = self._events(conn, "CVE-1")
        assert ev == [("poc_updated", json.dumps({"new_url": "https://cvedb.example/2"}))]

    def test_poc_updated_does_not_refire_on_identical_url_set(self, db_path):
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        urls = json.dumps(["https://exploit-db.com/1", "https://cvedb.example/2"])
        old = (9.8, "CRITICAL", True, True, urls)
        cve_data = {
            "id": "CVE-1", "base_score": 9.8, "base_severity": "CRITICAL",
            "has_known_exploit": True, "has_poc": True,
            "poc_urls": urls, "poc_source": json.dumps(["exploitdb", "cvedb"]),
        }

        collector._record_lifecycle_events(conn, "CVE-1", old, cve_data)

        assert self._events(conn, "CVE-1") == []

    def test_simultaneous_multi_field_transition_fires_all_events(self, db_path):
        conn = sqlite3.connect(db_path)
        collector = CVECollector(db_path=db_path)
        old = (5.0, "MEDIUM", False, False, None)
        cve_data = {
            "id": "CVE-2", "base_score": 9.8, "base_severity": "CRITICAL",
            "has_known_exploit": True, "has_poc": True,
            "poc_urls": json.dumps(["https://x/1"]),
            "poc_source": json.dumps(["exploitdb"]),
        }

        collector._record_lifecycle_events(conn, "CVE-2", old, cve_data)

        types = [e[0] for e in self._events(conn, "CVE-2")]
        assert types == ["cvss_changed", "kev_added", "poc_added"]


# ---------------------------------------------------------------------------
# CVECollector._cve_row_changed() -- drives collect()'s stats['updated']
# counter and "Updated:" log line. Extracted specifically so this is
# testable without going through collect()'s network I/O.
# ---------------------------------------------------------------------------

class TestCveRowChanged:
    BASE = {"id": "CVE-1", "base_score": 7.5, "base_severity": "HIGH",
            "has_known_exploit": False, "has_poc": False,
            "poc_urls": None, "poc_source": None}
    UNCHANGED_OLD = (7.5, "HIGH", False, False, None)

    def test_no_change_is_false(self):
        assert CVECollector._cve_row_changed(self.UNCHANGED_OLD, self.BASE) is False

    def test_score_change_is_true(self):
        cve_data = dict(self.BASE, base_score=9.8)
        assert CVECollector._cve_row_changed(self.UNCHANGED_OLD, cve_data) is True

    def test_severity_change_is_true(self):
        cve_data = dict(self.BASE, base_severity="CRITICAL")
        assert CVECollector._cve_row_changed(self.UNCHANGED_OLD, cve_data) is True

    def test_exploit_change_is_true(self):
        cve_data = dict(self.BASE, has_known_exploit=True)
        assert CVECollector._cve_row_changed(self.UNCHANGED_OLD, cve_data) is True

    def test_poc_only_change_is_true(self):
        """Regression: has_poc wasn't compared here at all, so a POC-only
        change (has_poc 0->1, nothing else different) fell through
        uncounted in collect()'s stats['updated'] even though
        _record_lifecycle_events() correctly wrote a poc_added event for
        the exact same transition.
        """
        cve_data = dict(self.BASE, has_poc=True,
                        poc_urls=json.dumps(["https://x/1"]),
                        poc_source=json.dumps(["exploitdb"]))
        assert CVECollector._cve_row_changed(self.UNCHANGED_OLD, cve_data) is True

    def test_poc_url_only_change_with_has_poc_already_true_is_false(self):
        """A new POC URL added to an already-true has_poc fires poc_updated
        as a lifecycle event, but deliberately does not count as "updated"
        for stats purposes -- matches how poc_updated was never folded into
        the "updated" bucket either.
        """
        old = (7.5, "HIGH", False, True, json.dumps(["https://x/1"]))
        cve_data = dict(self.BASE, has_poc=True,
                        poc_urls=json.dumps(["https://x/1", "https://y/2"]),
                        poc_source=json.dumps(["exploitdb", "cvedb"]))
        assert CVECollector._cve_row_changed(old, cve_data) is False
