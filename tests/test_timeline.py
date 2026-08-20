"""
Tests for the reporter-side of the timeline feature: get_events_for_cve(s),
days_to_exploit(), the LIFECYCLE TIMELINE detail section, mark_as_processed's
`processed` event, and the --timeline/--velocity/--max-days-to-exploit CLI
flags (docs/features/TIMELINE_VIEW_FEATURE.md, modules M5/M6/M7).

See tests/test_events.py for the collector/schema-side (M1-M4) tests.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
from datetime import timedelta

import pytest

from cve_reporter import CVEReporter, days_to_exploit, _format_duration
from events import record_event

# Recomputed rather than imported from tests.conftest: this repo's tests/
# has no __init__.py (plain script layout, not a package), so `import
# tests.conftest` is fragile across pytest's different import-mode/rootdir
# combinations. conftest.py's own sys.path insertion already made the
# top-level modules (cve_reporter, events, ...) importable above.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# M5: self-healing schema, get_events_for_cve(s), days_to_exploit, mark_as_processed
# ---------------------------------------------------------------------------

class TestSelfHealingSchema:
    def test_enter_creates_cve_events_on_a_db_that_never_had_it(self, bare_cves_db):
        with CVEReporter(db_path=bare_cves_db) as reporter:
            tables = {r[0] for r in reporter.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            assert {"cve_events", "collections", "collection_members"} <= tables


class TestGetEventsForCve:
    def test_chronological_order_and_parsed_detail(self, db_path):
        with CVEReporter(db_path=db_path) as reporter:
            reporter.conn.execute(
                "INSERT INTO cves (id, description, published_date) "
                "VALUES ('CVE-2026-1', 'x', '2026-01-15T08:00:00')")
            record_event(reporter.conn, "CVE-2026-1", "ingested", {"cvss": 9.8},
                         event_date="2026-01-20T00:00:00")
            record_event(reporter.conn, "CVE-2026-1", "poc_added", {"urls": ["x"]},
                         event_date="2026-01-22T00:00:00")
            reporter.conn.commit()

            events = reporter.get_events_for_cve("CVE-2026-1")
            assert [e["event_type"] for e in events] == ["ingested", "poc_added"]
            assert events[0]["detail"] == {"cvss": 9.8}

    def test_no_events_and_unknown_cve_both_return_empty_list(self, db_path):
        with CVEReporter(db_path=db_path) as reporter:
            reporter.conn.execute(
                "INSERT INTO cves (id, description, published_date) "
                "VALUES ('CVE-2026-2', 'x', '2026-01-01')")
            reporter.conn.commit()
            assert reporter.get_events_for_cve("CVE-2026-2") == []
            assert reporter.get_events_for_cve("CVE-NOPE") == []


class TestGetEventsForCves:
    def test_batched_grouping_and_missing_cve_absent(self, db_path):
        with CVEReporter(db_path=db_path) as reporter:
            reporter.conn.execute(
                "INSERT INTO cves (id, description, published_date) VALUES "
                "('CVE-1', 'x', '2026-01-01'), ('CVE-2', 'y', '2026-01-01')")
            record_event(reporter.conn, "CVE-1", "ingested")
            record_event(reporter.conn, "CVE-1", "kev_added")
            reporter.conn.commit()

            batched = reporter.get_events_for_cves(["CVE-1", "CVE-2", "CVE-NOPE"])
            assert set(batched.keys()) == {"CVE-1"}
            assert len(batched["CVE-1"]) == 2

    def test_empty_input_returns_empty_dict(self, db_path):
        with CVEReporter(db_path=db_path) as reporter:
            assert reporter.get_events_for_cves([]) == {}


class TestDaysToExploit:
    """Anchored on cves.published_date, not the `ingested` event -- see
    days_to_exploit()'s docstring for why. This also means a CVE with no
    `ingested` event at all (e.g. ingested before this feature shipped)
    still gets a correct result once it earns a kev_added/poc_added event.
    """

    def _ev(self, event_type, event_date, detail=None):
        return {"event_type": event_type, "event_date": event_date, "detail": detail or {}}

    def test_earliest_of_kev_and_poc_wins(self):
        events = [
            self._ev("kev_added", "2026-01-25T00:00:00"),
            self._ev("poc_added", "2026-01-22T00:00:00"),
        ]
        d = days_to_exploit("2026-01-15T08:00:00", events)
        assert d == timedelta(days=6, hours=16)

    def test_works_with_no_ingested_event_present(self):
        """The pre-feature-CVE coverage gap the doc's own anchor didn't cover."""
        events = [self._ev("kev_added", "2026-01-20T08:00:00")]
        d = days_to_exploit("2026-01-15T08:00:00", events)
        assert d == timedelta(days=5)

    def test_no_qualifying_event_returns_none(self):
        events = [self._ev("ingested", "2026-01-16T00:00:00"),
                  self._ev("cvss_changed", "2026-01-17T00:00:00")]
        assert days_to_exploit("2026-01-15T08:00:00", events) is None

    def test_no_published_date_returns_none(self):
        events = [self._ev("kev_added", "2026-01-20T00:00:00")]
        assert days_to_exploit(None, events) is None
        assert days_to_exploit("", events) is None

    def test_malformed_dates_return_none_not_raise(self):
        events = [self._ev("kev_added", "not-a-date")]
        assert days_to_exploit("2026-01-15T08:00:00", events) is None
        assert days_to_exploit("not-a-date", [self._ev("kev_added", "2026-01-20")]) is None


class TestFormatDuration:
    def test_days_and_hours(self):
        assert _format_duration(timedelta(days=5)) == "5 days"
        assert _format_duration(timedelta(days=1)) == "1 day"
        assert _format_duration(timedelta(hours=3)) == "3 hours"
        assert _format_duration(timedelta(hours=1)) == "1 hour"
        assert _format_duration(timedelta(days=4, hours=16)) == "4 days 16 hours"
        assert _format_duration(timedelta(minutes=30)) == "less than an hour"


class TestMarkAsProcessed:
    def test_writes_processed_event_only_on_real_transition(self, db_path):
        with CVEReporter(db_path=db_path) as reporter:
            reporter.conn.execute(
                "INSERT INTO cves (id, description, published_date) VALUES "
                "('CVE-1', 'x', '2026-01-01'), ('CVE-2', 'y', '2026-01-01')")
            reporter.conn.commit()

            reporter.mark_as_processed(["CVE-1", "CVE-2"])
            ev1 = reporter.get_events_for_cve("CVE-1")
            ev2 = reporter.get_events_for_cve("CVE-2")
            assert ev1[-1]["event_type"] == "processed"
            assert ev2[-1]["event_type"] == "processed"

            # re-marking already-processed CVEs must not duplicate the event
            reporter.mark_as_processed(["CVE-1", "CVE-2"])
            assert len(reporter.get_events_for_cve("CVE-1")) == len(ev1)
            assert len(reporter.get_events_for_cve("CVE-2")) == len(ev2)

    def test_empty_list_is_a_noop(self, db_path):
        with CVEReporter(db_path=db_path) as reporter:
            reporter.mark_as_processed([])  # must not raise

    def test_concurrent_calls_do_not_duplicate_processed_event(self, db_path):
        """Regression: a plain SELECT-then-UPDATE (write lock taken only at
        the UPDATE) let two concurrent mark_as_processed() calls both read
        processed=0 for the same CVE before either had written, each then
        logging its own `processed` event for what's really one transition.
        BEGIN IMMEDIATE now takes the write lock up front, so the second
        call blocks (via the busy_timeout set in __enter__) until the first
        commits, then correctly sees processed=1 and skips it.
        """
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO cves (id, description, published_date) "
                     "VALUES ('CVE-1', 'x', '2026-01-01')")
        conn.commit()
        conn.close()

        barrier = threading.Barrier(2)
        errors = []

        def worker():
            try:
                with CVEReporter(db_path=db_path) as reporter:
                    # Both threads' connections are already open and
                    # pragma'd before either calls mark_as_processed, to
                    # maximize the race window right at the SELECT/UPDATE.
                    barrier.wait(timeout=5)
                    reporter.mark_as_processed(["CVE-1"])
            except Exception as e:  # pragma: no cover - surfaced via `errors`
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, errors

        with CVEReporter(db_path=db_path) as reporter:
            events = reporter.get_events_for_cve("CVE-1")
        processed_events = [e for e in events if e["event_type"] == "processed"]
        assert len(processed_events) == 1, (
            f"expected exactly one processed event from two concurrent "
            f"calls, got {len(processed_events)}"
        )


# ---------------------------------------------------------------------------
# M6: LIFECYCLE TIMELINE section in format_cve_detail(), format_cve_text() gating
# ---------------------------------------------------------------------------

@pytest.fixture
def cve_row(db_path):
    with CVEReporter(db_path=db_path) as reporter:
        reporter.conn.execute(
            "INSERT INTO cves (id, description, published_date, base_score, "
            "base_severity, has_known_exploit, has_poc, processed) VALUES "
            "('CVE-2026-1', 'desc', '2026-01-15T08:00:00', 9.8, 'CRITICAL', 1, 1, 0)")
        reporter.conn.commit()
        yield db_path, reporter.get_cve_by_id("CVE-2026-1")


class TestFormatCveDetailTimeline:
    def test_section_absent_by_default(self, cve_row):
        db, cve = cve_row
        with CVEReporter(db_path=db) as reporter:
            out = reporter.format_cve_detail(cve)
        assert "LIFECYCLE TIMELINE" not in out
        assert "ALL ENRICHMENT DATA" in out  # rest of the detail view unaffected

    def test_empty_history_message(self, cve_row):
        db, cve = cve_row
        with CVEReporter(db_path=db) as reporter:
            out = reporter.format_cve_detail(cve, lifecycle_events=[])
        assert "No event history available" in out
        assert "Time to KEV" not in out and "Time to POC" not in out

    def test_full_render_with_time_to_kev_and_poc(self, cve_row):
        db, cve = cve_row
        with CVEReporter(db_path=db) as reporter:
            record_event(reporter.conn, "CVE-2026-1", "ingested",
                         {"cvss": 7.5, "severity": "HIGH"}, event_date="2026-01-15T09:00:00")
            record_event(reporter.conn, "CVE-2026-1", "cvss_changed",
                         {"from": 7.5, "to": 9.8}, event_date="2026-02-01T00:00:00")
            record_event(reporter.conn, "CVE-2026-1", "kev_added",
                         {"source": "cisa_kev"}, event_date="2026-01-20T08:00:00")  # +5d
            record_event(reporter.conn, "CVE-2026-1", "poc_added",
                         {"source": ["exploitdb"]}, event_date="2026-01-22T08:00:00")  # +7d
            reporter.conn.commit()

            events = reporter.get_events_for_cve("CVE-2026-1")
            out = reporter.format_cve_detail(cve, lifecycle_events=events)

        assert "First seen — CVSS 7.5 HIGH" in out
        assert "CVSS updated: 7.5 → 9.8" in out
        assert "Added to CISA KEV list (cisa_kev)" in out
        assert "POC published (exploitdb)" in out
        assert "Time to KEV:        5 days after disclosure" in out
        assert "Time to POC:        7 days after disclosure" in out

    def test_only_poc_event_shows_only_time_to_poc(self, cve_row):
        db, cve = cve_row
        with CVEReporter(db_path=db) as reporter:
            record_event(reporter.conn, "CVE-2026-1", "poc_added",
                         event_date="2026-01-22T08:00:00")
            reporter.conn.commit()
            events = reporter.get_events_for_cve("CVE-2026-1")
            out = reporter.format_cve_detail(cve, lifecycle_events=events)
        assert "Time to POC:" in out
        assert "Time to KEV:" not in out

    def test_no_exploit_events_shows_not_yet_exploited(self, cve_row):
        db, cve = cve_row
        with CVEReporter(db_path=db) as reporter:
            record_event(reporter.conn, "CVE-2026-1", "ingested")
            reporter.conn.commit()
            events = reporter.get_events_for_cve("CVE-2026-1")
            out = reporter.format_cve_detail(cve, lifecycle_events=events)
        assert "Time to exploit:    not yet exploited" in out


class TestFormatCveTextVelocityLine:
    def test_absent_by_default(self, cve_row):
        db, cve = cve_row
        with CVEReporter(db_path=db) as reporter:
            out = reporter.format_cve_text(cve)
        assert "Exploited:" not in out

    def test_present_when_passed(self, cve_row):
        db, cve = cve_row
        with CVEReporter(db_path=db) as reporter:
            out = reporter.format_cve_text(cve, time_to_exploit=timedelta(days=7))
        assert "Exploited: 7 days after disclosure" in out


# ---------------------------------------------------------------------------
# CLI integration (M6 --timeline validation/dispatch, M7 --velocity /
# --max-days-to-exploit). Exercises main() end-to-end via subprocess against
# an isolated temp working directory -- this is the only layer that actually
# proves argparse wiring + main()'s dispatch logic, not just the underlying
# methods.
# ---------------------------------------------------------------------------

def _run_cli(cwd, args):
    return subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "cve_reporter.py")] + args,
        cwd=cwd, capture_output=True, text=True,
    )


@pytest.fixture
def cli_db(tmp_path):
    """A CLI working directory with cves.db pre-built from schema.sql."""
    conn = sqlite3.connect(str(tmp_path / "cves.db"))
    with open(os.path.join(REPO_ROOT, "schema.sql")) as f:
        conn.executescript(f.read())
    conn.close()
    return tmp_path


class TestTimelineCli:
    def test_timeline_without_cve_errors(self, cli_db):
        r = _run_cli(cli_db, ["--timeline"])
        assert r.returncode == 1
        assert "--timeline requires --cve" in r.stderr

    def test_timeline_with_non_text_format_errors(self, cli_db):
        conn = sqlite3.connect(str(cli_db / "cves.db"))
        conn.execute("INSERT INTO cves (id, description, published_date, base_score, base_severity) "
                     "VALUES ('CVE-2026-9', 'x', '2026-01-01', 5.0, 'MEDIUM')")
        conn.commit()
        conn.close()

        r = _run_cli(cli_db, ["--cve", "CVE-2026-9", "--timeline", "--format", "json"])
        assert r.returncode == 1
        assert "--timeline currently only supports --format text" in r.stderr

    def test_timeline_renders_empty_history_for_a_cve_with_no_events(self, cli_db):
        conn = sqlite3.connect(str(cli_db / "cves.db"))
        conn.execute("INSERT INTO cves (id, description, published_date, base_score, base_severity) "
                     "VALUES ('CVE-2026-9', 'x', '2026-01-01', 5.0, 'MEDIUM')")
        conn.commit()
        conn.close()

        r = _run_cli(cli_db, ["--cve", "CVE-2026-9", "--timeline"])
        assert r.returncode == 0
        assert "LIFECYCLE TIMELINE" in r.stdout
        assert "No event history available" in r.stdout

    def test_plain_cve_unaffected(self, cli_db):
        conn = sqlite3.connect(str(cli_db / "cves.db"))
        conn.execute("INSERT INTO cves (id, description, published_date, base_score, base_severity) "
                     "VALUES ('CVE-2026-9', 'x', '2026-01-01', 5.0, 'MEDIUM')")
        conn.commit()
        conn.close()

        r = _run_cli(cli_db, ["--cve", "CVE-2026-9"])
        assert r.returncode == 0
        assert "LIFECYCLE TIMELINE" not in r.stdout


class TestVelocityCli:
    @pytest.fixture
    def velocity_db(self, cli_db):
        conn = sqlite3.connect(str(cli_db / "cves.db"))
        rows = [
            ("CVE-2026-FAST", "fast", "2026-01-01T00:00:00", 9.8, "CRITICAL", 1),
            ("CVE-2026-MED",  "med",  "2026-01-01T00:00:00", 9.8, "CRITICAL", 1),
            ("CVE-2026-SLOW", "slow", "2026-01-01T00:00:00", 9.8, "CRITICAL", 1),
            ("CVE-2026-NONE", "none", "2026-01-01T00:00:00", 9.8, "CRITICAL", 0),
        ]
        for cve_id, desc, pub, score, sev, exploit in rows:
            conn.execute(
                "INSERT INTO cves (id, description, published_date, base_score, "
                "base_severity, has_known_exploit) VALUES (?, ?, ?, ?, ?, ?)",
                (cve_id, desc, pub, score, sev, exploit))
        events = [
            ("CVE-2026-FAST", "kev_added", "2026-01-03T00:00:00"),   # +2d
            ("CVE-2026-MED",  "kev_added", "2026-01-11T00:00:00"),   # +10d
            ("CVE-2026-SLOW", "kev_added", "2026-02-01T00:00:00"),   # +31d
            ("CVE-2026-NONE", "ingested",  "2026-01-01T00:00:00"),   # no exploit event
        ]
        for cve_id, etype, edate in events:
            conn.execute(
                "INSERT INTO cve_events (cve_id, event_type, event_date, detail) "
                "VALUES (?, ?, ?, '{}')", (cve_id, etype, edate))
        conn.commit()
        conn.close()
        return cli_db

    def test_velocity_sorts_fastest_first(self, velocity_db):
        r = _run_cli(velocity_db, ["--exploits-only", "--velocity"])
        assert r.returncode == 0
        order = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("CVE:")]
        assert order == ["CVE-2026-FAST", "CVE-2026-MED", "CVE-2026-SLOW"]
        assert "Exploited: 2 days after disclosure" in r.stdout
        assert "Exploited: 31 days after disclosure" in r.stdout

    def test_unexploited_cve_sorts_last_not_filtered_out(self, velocity_db):
        """Uses --critical (matches all 4 rows) rather than --exploits-only,
        which would filter CVE-2026-NONE out at the SQL level before
        --velocity's sort ever saw it.
        """
        r = _run_cli(velocity_db, ["--critical", "--velocity"])
        assert r.returncode == 0
        order = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("CVE:")]
        assert order[-1] == "CVE-2026-NONE"
        none_block = r.stdout.split("CVE: CVE-2026-NONE")[1].split("-" * 70)[0]
        assert "Exploited:" not in none_block

    def test_max_days_to_exploit_filters(self, velocity_db):
        r = _run_cli(velocity_db, ["--exploits-only", "--max-days-to-exploit", "7"])
        assert r.returncode == 0
        order = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("CVE:")]
        assert order == ["CVE-2026-FAST"]

    def test_max_days_to_exploit_excludes_almost_a_day_over(self, cli_db):
        """Regression: comparing timedelta.days (which floors) let a CVE
        exploited in 7 days 1 hour slip through --max-days-to-exploit 7,
        since .days truncated 7d1h down to 7. The filter must compare full
        elapsed time instead.
        """
        conn = sqlite3.connect(str(cli_db / "cves.db"))
        conn.execute(
            "INSERT INTO cves (id, description, published_date, base_score, "
            "base_severity, has_known_exploit) VALUES "
            "('CVE-2026-EXACT', 'exact', '2026-01-01T00:00:00', 9.8, 'CRITICAL', 1), "
            "('CVE-2026-OVER',  'over',  '2026-01-01T00:00:00', 9.8, 'CRITICAL', 1)")
        conn.execute(
            "INSERT INTO cve_events (cve_id, event_type, event_date, detail) VALUES "
            "('CVE-2026-EXACT', 'kev_added', '2026-01-08T00:00:00', '{}'), "  # exactly 7d
            "('CVE-2026-OVER',  'kev_added', '2026-01-08T01:00:00', '{}')")   # 7d 1h
        conn.commit()
        conn.close()

        r = _run_cli(cli_db, ["--exploits-only", "--max-days-to-exploit", "7"])
        assert r.returncode == 0
        order = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("CVE:")]
        assert order == ["CVE-2026-EXACT"], order

    def test_ordinary_run_unaffected(self, velocity_db):
        r = _run_cli(velocity_db, ["--exploits-only"])
        assert r.returncode == 0
        assert "Exploited:" not in r.stdout
        order = {l.split()[1] for l in r.stdout.splitlines() if l.startswith("CVE:")}
        assert order == {"CVE-2026-FAST", "CVE-2026-MED", "CVE-2026-SLOW"}

    def test_json_output_stays_filtered_sorted_but_field_free(self, velocity_db):
        r = _run_cli(velocity_db, ["--exploits-only", "--velocity", "--format", "json"])
        assert r.returncode == 0
        data = json.loads(r.stdout)
        ids = [c["id"] for c in data["cves"]]
        assert ids == ["CVE-2026-FAST", "CVE-2026-MED", "CVE-2026-SLOW"]
        assert all("time_to_exploit" not in c and "days_to_exploit" not in c
                   for c in data["cves"])

    def test_velocity_alone_still_hits_no_flags(self, velocity_db):
        r = _run_cli(velocity_db, ["--velocity"])
        assert r.returncode == 0
        assert "usage:" in r.stdout.lower()
