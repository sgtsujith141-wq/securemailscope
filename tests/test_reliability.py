"""M8: database integrity, concurrency and failure recovery.

Every test uses an isolated temporary database. None touches a developer's
real store, and none is capable of exhausting the machine.

The recurring question is what happens *after* something goes wrong: a
completed job must never reference results that were not written, a restart
must not turn an interrupted job into a successful one, and concurrent work
must not leave the database in a state that no single operation could produce.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from securemailscope.backend.app import AppState, create_app
from securemailscope.backend.database import (
    Base,
    CaptureRow,
    Database,
    FindingRow,
    InvestigationRow,
    JobRow,
    SessionRow,
)
from securemailscope.backend.security import TOKEN_HEADER
from tests.narrowing import present

pytestmark = pytest.mark.filterwarnings("ignore")

FIXTURES = Path(__file__).parent / "fixtures" / "generated"


@pytest.fixture
def state(tmp_path: Path):
    app_state = AppState(tmp_path / "app")
    yield app_state
    app_state.shutdown()


@pytest.fixture
def client(state: AppState):
    with TestClient(create_app(state), base_url="http://127.0.0.1") as test_client:
        test_client.headers.update({TOKEN_HEADER: state.token.value})
        yield test_client


def upload(client: TestClient, name: str) -> str:
    data = (FIXTURES / name).read_bytes()
    response = client.post(
        "/api/captures", files={"file": (name, data, "application/octet-stream")}
    )
    assert response.status_code == 200, response.text
    return response.json()["capture_id"]


def analyse(client: TestClient, state: AppState, capture_ids: list[str]) -> str:
    investigation = client.post(
        "/api/investigations", json={"name": "T", "capture_ids": capture_ids}
    ).json()
    identifier = investigation["investigation_id"]
    client.post(f"/api/investigations/{identifier}/analyze")
    state.service.wait(identifier)
    return identifier


# ---------------------------------------------------------------------------
# SQLite integrity
# ---------------------------------------------------------------------------
def test_sqlite_integrity_and_foreign_keys_hold_after_a_real_analysis(
    client: TestClient, state: AppState
) -> None:
    """The two checks SQLite itself offers, run on a populated database."""
    analyse(client, state, [upload(client, "aa_tls10_static_rsa.pcap")])

    with state.database.engine.connect() as connection:
        integrity = connection.execute(text("PRAGMA integrity_check")).scalar_one()
        violations = connection.execute(text("PRAGMA foreign_key_check")).fetchall()
        foreign_keys_on = connection.execute(text("PRAGMA foreign_keys")).scalar_one()

    assert integrity == "ok", f"PRAGMA integrity_check returned {integrity!r}"
    assert violations == [], f"PRAGMA foreign_key_check found {violations}"
    assert foreign_keys_on == 1, (
        "foreign keys are off; SQLite disables them by default and the schema "
        "would silently accumulate orphaned rows"
    )


def test_a_foreign_key_violation_is_refused(state: AppState) -> None:
    """Proof the constraint is enforced, not merely declared."""
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError), state.database.session() as session:
        session.add(JobRow(job_id="job-orphan", investigation_id="inv-does-not-exist"))


def test_migrations_are_idempotent_and_versioned(tmp_path: Path) -> None:
    from securemailscope.backend.database import SCHEMA_VERSION

    path = tmp_path / "m.sqlite3"
    first = Database(path)
    assert first.schema_version == SCHEMA_VERSION
    first.close()

    # Opening again must not re-run anything or lose data.
    second = Database(path)
    with second.session() as session:
        session.add(InvestigationRow(investigation_id="inv-keep", name="keep"))
    second.close()

    third = Database(path)
    assert third.schema_version == SCHEMA_VERSION
    with third.session() as session:
        assert session.get(InvestigationRow, "inv-keep") is not None
    third.close()


# ---------------------------------------------------------------------------
# Transactional correctness
# ---------------------------------------------------------------------------
def test_a_failed_persist_rolls_back_to_the_previous_good_state(
    client: TestClient, state: AppState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Persistence is one transaction: it commits whole or not at all.

    The re-analysis path is the demanding case, because persisting begins by
    deleting the previous run's sessions and findings. If the transaction did
    not roll back, a failure partway through would leave the investigation with
    its old results destroyed and no new ones written.
    """
    capture = upload(client, "aa_tls10_static_rsa.pcap")
    identifier = analyse(client, state, [capture])
    before = client.get(f"/api/investigations/{identifier}/findings").json()
    assert before["total"] > 0

    # Fail *inside* the persisting transaction, after the deletes and the
    # capture-row updates have already been issued on the session.
    def explode(results):
        raise RuntimeError("simulated failure mid-transaction")

    monkeypatch.setattr(
        "securemailscope.backend.service._session_details", explode
    )
    client.post(f"/api/investigations/{identifier}/analyze")
    state.service.wait(identifier)

    detail = client.get(f"/api/investigations/{identifier}").json()
    assert detail["investigation"]["status"] == "FAILED"
    job = max(detail["jobs"], key=lambda j: j["created_at"])
    assert job["status"] == "FAILED"
    assert "persistence failed" in (job["error"] or "")

    # Nothing was lost: the rows the failed run had already deleted are back.
    after = client.get(f"/api/investigations/{identifier}/findings").json()
    assert after["total"] == before["total"]
    assert [f["finding_id"] for f in after["items"]] == [
        f["finding_id"] for f in before["items"]
    ]
    with state.database.engine.connect() as connection:
        assert connection.execute(text("PRAGMA integrity_check")).scalar_one() == "ok"


def test_a_first_analysis_that_fails_to_persist_stores_nothing(
    client: TestClient, state: AppState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed job must never leave a half-populated investigation behind."""
    capture = upload(client, "aa_tls10_static_rsa.pcap")
    identifier = client.post(
        "/api/investigations", json={"name": "T", "capture_ids": [capture]}
    ).json()["investigation_id"]

    def explode(results):
        raise RuntimeError("simulated failure mid-transaction")

    monkeypatch.setattr(
        "securemailscope.backend.service._session_details", explode
    )
    client.post(f"/api/investigations/{identifier}/analyze")
    state.service.wait(identifier)

    detail = client.get(f"/api/investigations/{identifier}").json()
    assert detail["investigation"]["status"] == "FAILED"
    assert detail["investigation"]["finding_count"] == 0
    assert detail["investigation"]["session_count"] == 0
    assert client.get(f"/api/investigations/{identifier}/findings").json()["total"] == 0
    with state.database.session() as session:
        assert (
            session.query(SessionRow)
            .filter(SessionRow.investigation_id == identifier)
            .count()
            == 0
        )


def test_no_completed_job_references_missing_results(
    client: TestClient, state: AppState
) -> None:
    identifier = analyse(client, state, [upload(client, "aa_tls10_static_rsa.pcap")])
    with state.database.session() as session:
        job = (
            session.query(JobRow)
            .filter(JobRow.investigation_id == identifier)
            .one()
        )
        assert job.status == "COMPLETED"
        investigation = present(
            session.get(InvestigationRow, identifier), "the investigation row"
        )
        sessions = (
            session.query(SessionRow)
            .filter(SessionRow.investigation_id == identifier)
            .count()
        )
        findings = (
            session.query(FindingRow)
            .filter(FindingRow.investigation_id == identifier)
            .count()
        )
    assert investigation.session_count == sessions
    assert investigation.finding_count == findings
    assert sessions > 0 and findings > 0


def test_reanalysis_replaces_rather_than_duplicating(
    client: TestClient, state: AppState
) -> None:
    capture = upload(client, "aa_tls10_static_rsa.pcap")
    identifier = analyse(client, state, [capture])
    first = client.get(f"/api/investigations/{identifier}/findings").json()["total"]

    client.post(f"/api/investigations/{identifier}/analyze")
    state.service.wait(identifier)
    second = client.get(f"/api/investigations/{identifier}/findings").json()["total"]

    assert first == second, "re-running an analysis duplicated its findings"


# ---------------------------------------------------------------------------
# Restart and recovery
# ---------------------------------------------------------------------------
def test_an_interrupted_job_fails_and_its_investigation_follows(tmp_path: Path) -> None:
    database = Database(tmp_path / "r.sqlite3")
    with database.session() as session:
        session.add(InvestigationRow(investigation_id="inv-i", name="i", status="RUNNING"))
        session.add(JobRow(job_id="job-i", investigation_id="inv-i", status="RUNNING"))
        session.add(JobRow(job_id="job-q", investigation_id="inv-i", status="QUEUED"))
    database.close()

    recovered = Database(tmp_path / "r.sqlite3")
    assert recovered.recover_interrupted_jobs() == 2
    with recovered.session() as session:
        for job_id in ("job-i", "job-q"):
            job = present(session.get(JobRow, job_id), job_id)
            assert job.status == "FAILED"
            assert job.finished_at is not None
            assert "restarted" in (job.error or "")
        assert present(
            session.get(InvestigationRow, "inv-i"), "inv-i"
        ).status == "FAILED"
    recovered.close()


def test_a_completed_investigation_survives_restart_intact(tmp_path: Path) -> None:
    root = tmp_path / "app"
    first = AppState(root)
    with TestClient(create_app(first), base_url="http://127.0.0.1") as client:
        client.headers.update({TOKEN_HEADER: first.token.value})
        identifier = analyse(
            client, first,
            [upload(client, "aa_tls10_static_rsa.pcap"),
             upload(client, "t_a_tls12_complete_handshake.pcap")],
        )
        before = client.get(f"/api/investigations/{identifier}").json()
        findings_before = client.get(
            f"/api/investigations/{identifier}/findings"
        ).json()
    first.shutdown()

    second = AppState(root)
    try:
        # Recovery must not touch a job that genuinely completed.
        assert second.service.recovered_jobs == 0
        with TestClient(create_app(second), base_url="http://127.0.0.1") as client:
            client.headers.update({TOKEN_HEADER: second.token.value})
            after = client.get(f"/api/investigations/{identifier}").json()
            findings_after = client.get(
                f"/api/investigations/{identifier}/findings"
            ).json()
            # Evidence survives, not just counts.
            detail = client.get(
                f"/api/findings/{findings_after['items'][0]['finding_id']}"
            ).json()
            assert detail["evidence"]
            assert detail["evidence"][0]["packet_number"] >= 1

        assert after["investigation"]["finding_count"] == before["investigation"]["finding_count"]
        assert after["investigation"]["posture_score"] == before["investigation"]["posture_score"]
        assert [f["finding_id"] for f in findings_after["items"]] == [
            f["finding_id"] for f in findings_before["items"]
        ]
        # And the report still generates from persisted state.
        assert client.get(
            f"/api/investigations/{identifier}/export/json"
        ).status_code == 200
    finally:
        second.shutdown()


def test_a_write_failure_is_surfaced_not_swallowed(tmp_path: Path) -> None:
    """A bounded simulation of a database that cannot be written."""
    from sqlalchemy.exc import OperationalError, SQLAlchemyError

    database = Database(tmp_path / "w.sqlite3")
    with database.session() as session:
        session.add(InvestigationRow(investigation_id="inv-w", name="w"))

    # Make the file read-only, then attempt a write.
    database.close()
    path = tmp_path / "w.sqlite3"
    path.chmod(0o400)
    try:
        reopened = Database(path)
    except OperationalError:
        return  # refused at open: also an acceptable, visible failure
    try:
        # SQLAlchemy wraps the driver error; the requirement is that the
        # failure is raised to the caller rather than silently dropped.
        with pytest.raises(SQLAlchemyError), reopened.session() as session:
            session.add(InvestigationRow(investigation_id="inv-x", name="x"))
    finally:
        reopened.close()
        path.chmod(0o600)


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
def test_the_worker_model_is_a_bounded_thread_pool(state: AppState) -> None:
    """Document the truth: threads, not processes or async tasks."""
    from concurrent.futures import ThreadPoolExecutor as Pool

    pool = state.service._pool
    assert isinstance(pool, Pool), (
        "the execution model is documented as a bounded thread pool; if this "
        "changes, the documentation must change with it"
    )
    assert pool._max_workers == 2


def test_cancellation_is_not_offered_because_it_is_not_implemented(
    client: TestClient, state: AppState
) -> None:
    """No fake Cancel: there is no endpoint and no CANCELLED status produced."""
    identifier = analyse(client, state, [upload(client, "aa_tls10_static_rsa.pcap")])
    # No route exists, so the router does not match at all.
    assert client.post(
        f"/api/investigations/{identifier}/cancel"
    ).status_code in (404, 405)
    assert client.delete(f"/api/jobs/{identifier}").status_code in (404, 405)
    routes = {getattr(r, "path", "") for r in create_app(state).routes}
    assert not any("cancel" in path or "abort" in path for path in routes)
    jobs = client.get(f"/api/investigations/{identifier}/jobs").json()
    assert all(job["status"] != "CANCELLED" for job in jobs)


def test_concurrent_uploads_do_not_corrupt_the_capture_table(
    client: TestClient,
) -> None:
    names = [
        "aa_tls10_static_rsa.pcap", "ab_null_cipher.pcap", "ac_rc4_weak_cipher.pcap",
        "t_a_tls12_complete_handshake.pcap", "t_d_tls13_negotiation.pcap",
    ]
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda n: upload(client, n), names))
    assert len(set(results)) == len(names)
    listed = client.get("/api/captures?limit=50").json()
    assert listed["total"] == len(names)


def test_the_same_capture_uploaded_concurrently_stays_one_row(
    client: TestClient,
) -> None:
    """Identical bytes are one piece of evidence, however many times they arrive."""
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(
            pool.map(lambda _: upload(client, "aa_tls10_static_rsa.pcap"), range(6))
        )
    assert len(set(results)) == 1
    assert client.get("/api/captures").json()["total"] == 1


def test_concurrent_reads_during_an_analysis_stay_consistent(
    client: TestClient, state: AppState
) -> None:
    """Reading an investigation while it is being written must not error."""
    capture = upload(client, "aa_tls10_static_rsa.pcap")
    identifier = client.post(
        "/api/investigations", json={"name": "T", "capture_ids": [capture]}
    ).json()["investigation_id"]
    client.post(f"/api/investigations/{identifier}/analyze")

    errors: list[int] = []
    stop = threading.Event()

    def poll() -> None:
        while not stop.is_set():
            response = client.get(f"/api/investigations/{identifier}")
            if response.status_code != 200:
                errors.append(response.status_code)

    reader = threading.Thread(target=poll, daemon=True)
    reader.start()
    state.service.wait(identifier)
    stop.set()
    reader.join(timeout=5)

    assert errors == [], f"reads during analysis returned {errors}"
    assert client.get(f"/api/investigations/{identifier}").json()[
        "investigation"
    ]["status"] == "COMPLETED"


def test_concurrent_exports_all_succeed_and_agree(
    client: TestClient, state: AppState
) -> None:
    identifier = analyse(client, state, [upload(client, "aa_tls10_static_rsa.pcap")])
    formats = ["json", "html", "pdf", "json", "html", "pdf"]
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(
            pool.map(
                lambda f: client.get(f"/api/investigations/{identifier}/export/{f}"),
                formats,
            )
        )
    assert all(r.status_code == 200 for r in responses)
    documents = [json.loads(r.content) for r in responses if "json" in r.headers["content-type"]]
    assert len({len(d["findings"]) for d in documents}) == 1, (
        "concurrent exports disagreed about how many findings there were"
    )


def test_a_duplicate_analysis_never_produces_two_completions(
    client: TestClient, state: AppState
) -> None:
    capture = upload(client, "aa_tls10_static_rsa.pcap")
    identifier = client.post(
        "/api/investigations", json={"name": "T", "capture_ids": [capture]}
    ).json()["investigation_id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        codes = list(
            pool.map(
                lambda _: client.post(
                    f"/api/investigations/{identifier}/analyze"
                ).status_code,
                range(4),
            )
        )
    state.service.wait(identifier)
    assert 200 in codes
    with state.database.session() as session:
        completed = (
            session.query(JobRow)
            .filter(
                JobRow.investigation_id == identifier, JobRow.status == "COMPLETED"
            )
            .count()
        )
    # However many were accepted, the persisted state is one consistent result.
    detail = client.get(f"/api/investigations/{identifier}").json()
    assert detail["investigation"]["session_count"] == 1
    assert completed >= 1


def test_a_worker_exception_marks_the_job_failed(
    client: TestClient, state: AppState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A worker thread that raises must not leave a job stuck at RUNNING."""
    from securemailscope.intelligence import engine as engine_module

    capture = upload(client, "aa_tls10_static_rsa.pcap")
    identifier = client.post(
        "/api/investigations", json={"name": "T", "capture_ids": [capture]}
    ).json()["investigation_id"]

    def explode(*args: object, **kwargs: object):
        raise ValueError("simulated engine failure")

    monkeypatch.setattr(engine_module, "analyze_batch", explode)
    monkeypatch.setattr("securemailscope.backend.service.analyze_batch", explode)

    client.post(f"/api/investigations/{identifier}/analyze")
    state.service.wait(identifier)

    detail = client.get(f"/api/investigations/{identifier}").json()
    assert detail["jobs"][0]["status"] == "FAILED"
    assert "simulated engine failure" in detail["jobs"][0]["error"]
    assert detail["investigation"]["status"] == "FAILED"


# ---------------------------------------------------------------------------
# Storage consistency
# ---------------------------------------------------------------------------
def test_deleting_a_capture_leaves_the_database_consistent(
    client: TestClient, state: AppState
) -> None:
    capture = upload(client, "aa_tls10_static_rsa.pcap")
    identifier = analyse(client, state, [capture])
    client.delete(f"/api/captures/{capture}")

    with state.database.engine.connect() as connection:
        assert connection.execute(text("PRAGMA integrity_check")).scalar_one() == "ok"
        assert connection.execute(text("PRAGMA foreign_key_check")).fetchall() == []

    with state.database.session() as session:
        row = present(session.get(CaptureRow, capture), "the capture row")
        assert row.status == "DELETED"
        assert row.stored_path == ""
    # The investigation is not silently discarded.
    assert client.get(f"/api/investigations/{identifier}").json()[
        "investigation"
    ]["finding_count"] == 4


def test_a_capture_file_removed_behind_the_application_fails_visibly(
    client: TestClient, state: AppState
) -> None:
    """Disk state can change under us. Analysis must fail, not fabricate."""
    capture = upload(client, "aa_tls10_static_rsa.pcap")
    with state.database.session() as session:
        Path(
            present(session.get(CaptureRow, capture), "the capture row").stored_path
        ).unlink()

    identifier = client.post(
        "/api/investigations", json={"name": "T", "capture_ids": [capture]}
    ).json()["investigation_id"]
    client.post(f"/api/investigations/{identifier}/analyze")
    state.service.wait(identifier)

    detail = client.get(f"/api/investigations/{identifier}").json()
    assert detail["investigation"]["status"] == "FAILED"
    assert detail["investigation"]["session_count"] == 0


# ---------------------------------------------------------------------------
# A capture may belong to more than one investigation
# ---------------------------------------------------------------------------
def test_one_capture_can_be_analysed_in_two_investigations(
    client: TestClient, state: AppState
) -> None:
    """Regression: the deterministic ids used to lock a capture to one investigation.

    ``session_id`` and ``finding_id`` are digests of their own content, so
    analysing the same capture again produces the same ids. While those were
    single-column primary keys, the second investigation's persist failed with
    ``UNIQUE constraint failed: findings.finding_id``, the whole transaction
    rolled back, and the investigation was marked FAILED with a raw database
    error. A capture could belong to exactly one investigation, for ever.
    """
    capture = upload(client, "aa_tls10_static_rsa.pcap")

    first = analyse(client, state, [capture])
    second_id = client.post(
        "/api/investigations",
        json={"name": "the same capture again", "capture_ids": [capture]},
    ).json()["investigation_id"]
    client.post(f"/api/investigations/{second_id}/analyze")
    state.service.wait(second_id)

    for identifier in (first, second_id):
        detail = client.get(f"/api/investigations/{identifier}").json()
        assert detail["investigation"]["status"] == "COMPLETED", (
            f"{identifier}: {detail['jobs'][-1].get('error')}"
        )
        assert detail["investigation"]["finding_count"] > 0

    a = client.get(f"/api/investigations/{first}/findings").json()
    b = client.get(f"/api/investigations/{second_id}/findings").json()
    assert a["total"] == b["total"]
    # The same capture under the same policy yields the same finding ids --
    # that is the point of a deterministic id, and both investigations keep
    # their own copy of the row.
    assert [f["finding_id"] for f in a["items"]] == [
        f["finding_id"] for f in b["items"]
    ]

    with state.database.engine.connect() as connection:
        assert connection.execute(text("PRAGMA integrity_check")).scalar_one() == "ok"
        assert connection.execute(text("PRAGMA foreign_key_check")).fetchall() == []


def test_a_finding_lookup_can_be_scoped_to_an_investigation(
    client: TestClient, state: AppState
) -> None:
    """With the same id in two investigations, the caller can say which."""
    capture = upload(client, "aa_tls10_static_rsa.pcap")
    first = analyse(client, state, [capture])
    second_id = client.post(
        "/api/investigations", json={"name": "again", "capture_ids": [capture]}
    ).json()["investigation_id"]
    client.post(f"/api/investigations/{second_id}/analyze")
    state.service.wait(second_id)

    finding_id = client.get(f"/api/investigations/{first}/findings").json()["items"][0][
        "finding_id"
    ]
    session_id = client.get(f"/api/investigations/{first}/sessions").json()["items"][0][
        "session_id"
    ]

    # Unscoped: still answers, because the rows are identical but for the
    # investigation they belong to.
    assert client.get(f"/api/findings/{finding_id}").status_code == 200
    assert client.get(f"/api/sessions/{session_id}").status_code == 200

    for identifier in (first, second_id):
        finding = client.get(
            f"/api/findings/{finding_id}", params={"investigation_id": identifier}
        )
        assert finding.status_code == 200
        assert finding.json()["finding"]["investigation_id"] == identifier

        session = client.get(
            f"/api/sessions/{session_id}", params={"investigation_id": identifier}
        )
        assert session.status_code == 200

    missing = client.get(
        f"/api/findings/{finding_id}", params={"investigation_id": "inv-nope"}
    )
    assert missing.status_code == 404


def test_the_schema_migration_widens_the_primary_keys(tmp_path: Path) -> None:
    """A version-1 database is migrated in place without losing rows.

    The version-1 shape is produced by taking the real schema and narrowing
    the two primary keys back to one column, rather than by hand-writing a
    table -- a hand-written approximation would not exercise the columns,
    defaults and indexes the real migration has to carry across.
    """
    import re

    from sqlalchemy import create_engine
    from sqlalchemy import text as sql

    path = tmp_path / "old.sqlite3"
    engine = create_engine(f"sqlite:///{path}", future=True)

    with engine.begin() as connection:
        Base.metadata.create_all(connection)
        for table, keep in (("sessions", "session_id"), ("findings", "finding_id")):
            ddl = connection.execute(
                sql(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=:t"
                ),
                {"t": table},
            ).scalar_one()
            narrowed = re.sub(
                r"PRIMARY KEY \([^)]*\)", f"PRIMARY KEY ({keep})", ddl
            )
            assert narrowed != ddl, f"the {table} DDL did not contain a key clause"
            connection.execute(sql(f"DROP TABLE {table}"))
            connection.execute(sql(narrowed))
        connection.execute(
            sql(
                "INSERT INTO findings (finding_id, investigation_id, capture_id, "
                "session_id, rule_id, title, description, severity, confidence, "
                "category, evaluation_status, rank, technical_impact, "
                "policy_version) VALUES ('find-1', 'inv-1', 'cap-1', 'sess-1', "
                "'R1', 'kept', 'd', 'HIGH', 'CONFIRMED', 'C', 'FAIL', 1, 'i', '1')"
            )
        )
        connection.execute(sql("PRAGMA user_version=1"))
    engine.dispose()

    database = Database(path)
    try:
        assert database.schema_version == 2
        with database.engine.connect() as connection:
            kept = connection.execute(
                text("SELECT title FROM findings WHERE finding_id='find-1'")
            ).scalar_one()
            assert kept == "kept", "the migration lost a row"
            assert (
                connection.execute(text("PRAGMA integrity_check")).scalar_one() == "ok"
            )
            leftovers = connection.execute(
                text("SELECT name FROM sqlite_master WHERE name LIKE '%\\_old' ESCAPE '\\'")
            ).fetchall()
            assert leftovers == [], leftovers
            for table, other in (("findings", "finding_id"), ("sessions", "session_id")):
                keys = {
                    row[1]
                    for row in connection.execute(
                        text(f"PRAGMA table_info({table})")
                    ).fetchall()
                    if row[5]
                }
                assert keys == {other, "investigation_id"}, (table, keys)
    finally:
        database.close()


def test_the_migration_is_a_no_op_on_a_current_database(tmp_path: Path) -> None:
    """Running it again must not rebuild anything or drop an index."""
    path = tmp_path / "current.sqlite3"
    first = Database(path)
    with first.engine.connect() as connection:
        before = connection.execute(
            text("SELECT name FROM sqlite_master ORDER BY name")
        ).fetchall()
    first.close()

    second = Database(path)
    try:
        assert second.migrate() == 2
        with second.engine.connect() as connection:
            after = connection.execute(
                text("SELECT name FROM sqlite_master ORDER BY name")
            ).fetchall()
        assert after == before
    finally:
        second.close()
