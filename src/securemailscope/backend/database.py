"""SQLite persistence (M7).

Design choices worth stating, because each has an obvious alternative:

**Normalised where it is queried, JSON where it is read whole.** Captures,
investigations, jobs, sessions and findings get real columns because the UI
filters, sorts and paginates on them. Cryptographic intelligence and ML results
are stored as JSON documents because they are always read in full and
normalising them would produce a dozen tables nothing ever joins against.

**Canonical identifiers, not surrogate keys.** ``capture_id`` is the SHA-256 of
the capture bytes, ``session_id`` and ``finding_id`` come from the engine. The
database stores the identity the evidence already has, so a packet reference
persisted here still means what it meant in the analysis.

**No payload, ever.** Nothing in this schema holds reconstructed application
data, a credential, an email body or a private key. The engine never produces
them for a report, and this layer stores only what a report may contain.

**Migrations via ``PRAGMA user_version``.** SQLite's own version counter, with
an ordered list of migration steps. Alembic would be the usual answer, and it
would be a lot of machinery for a single-file local database that one process
opens.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

__all__ = [
    "SCHEMA_VERSION",
    "Base",
    "CaptureRow",
    "InvestigationRow",
    "JobRow",
    "SessionRow",
    "FindingRow",
    "IntelligenceRow",
    "MLResultRow",
    "ReportExportRow",
    "Database",
    "utcnow",
]

#: Bumped with every migration step below.
SCHEMA_VERSION: Final = 2


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class _JSONText:
    """Store a dict or list as JSON text.

    A small helper rather than SQLAlchemy's JSON type, so the sorting is
    explicit: ``sort_keys`` makes a stored document byte-stable, which is what
    lets a test compare two persisted investigations directly.
    """

    @staticmethod
    def dump(value: Any) -> str:
        return json.dumps(value, sort_keys=True, default=str)

    @staticmethod
    def load(value: str | None) -> Any:
        return json.loads(value) if value else None


class CaptureRow(Base):
    """One uploaded capture file.

    ``stored_path`` points outside the repository and outside any served
    directory. ``original_name`` is recorded for display only and is never used
    to build a path.
    """

    __tablename__ = "captures"

    capture_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    #: Server-generated. The uploaded filename never reaches the filesystem.
    storage_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    original_name: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(Text)
    file_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(80), index=True)
    file_format: Mapped[str | None] = mapped_column(String(16), nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    session_count: Mapped[int] = mapped_column(Integer, default=0)
    first_packet_timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_packet_timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="UPLOADED", index=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    #: The full per-capture analysis document, exactly as the engine produced it.
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class InvestigationRow(Base):
    """One investigation: a set of captures analysed together."""

    __tablename__ = "investigations"

    investigation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    status: Mapped[str] = mapped_column(String(24), default="QUEUED", index=True)
    capture_count: Mapped[int] = mapped_column(Integer, default=0)
    analysed_capture_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_capture_count: Mapped[int] = mapped_column(Integer, default=0)
    session_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    #: None when coverage was insufficient. Never zero as a stand-in.
    posture_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    score_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    score_band: Mapped[str | None] = mapped_column(String(24), nullable=True)
    coverage_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(24), nullable=True)
    policy_fingerprint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity_counts: Mapped[str | None] = mapped_column(Text, nullable=True)
    protocol_counts: Mapped[str | None] = mapped_column(Text, nullable=True)
    capture_ids: Mapped[str] = mapped_column(Text, default="[]")


class JobRow(Base):
    """An analysis job.

    A job interrupted by a restart must never look finished, so recovery marks
    any job left in QUEUED or RUNNING as FAILED with a stated reason rather
    than assuming it completed.
    """

    __tablename__ = "jobs"

    job_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.investigation_id"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="QUEUED", index=True)
    stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Captures finished, out of the total. Real progress, not a timer.
    captures_total: Mapped[int] = mapped_column(Integer, default=0)
    captures_done: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    warnings_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class SessionRow(Base):
    """One reconstructed TCP session, denormalised for the session explorer."""

    __tablename__ = "sessions"

    # Composite key. ``session_id`` is a deterministic digest of the session
    # itself, so the same capture analysed in two investigations produces the
    # same value twice. Keyed on ``session_id`` alone, the second investigation
    # failed to persist with a UNIQUE constraint violation and was marked
    # FAILED -- a capture could belong to exactly one investigation, for ever.
    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), primary_key=True, index=True
    )
    capture_id: Mapped[str] = mapped_column(String(80), index=True)
    client: Mapped[str] = mapped_column(String(64))
    server: Mapped[str] = mapped_column(String(64), index=True)
    protocol: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    detection_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    tls_version: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(64), nullable=True)
    key_exchange: Mapped[str | None] = mapped_column(String(24), nullable=True)
    forward_secrecy: Mapped[str | None] = mapped_column(String(32), nullable=True)
    certificate_visibility: Mapped[str | None] = mapped_column(String(24), nullable=True)
    certificate_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    upgrade_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    completeness: Mapped[str | None] = mapped_column(String(24), nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    first_packet: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_packet: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    posture_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    score_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    coverage_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    #: Full detail for the session page, rendered from the analysis document.
    detail_json: Mapped[str | None] = mapped_column(Text, nullable=True)


Index("ix_sessions_investigation_server", SessionRow.investigation_id, SessionRow.server)


class FindingRow(Base):
    """One security finding, with its evidence references preserved."""

    __tablename__ = "findings"

    # Composite key, for the same reason as SessionRow: ``finding_id`` is a
    # digest of the rule, the session and the policy, so it repeats whenever
    # the same capture is analysed again in a different investigation.
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), primary_key=True, index=True
    )
    capture_id: Mapped[str] = mapped_column(String(80), index=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    category: Mapped[str] = mapped_column(String(32), index=True)
    evaluation_status: Mapped[str] = mapped_column(String(16))
    priority: Mapped[str | None] = mapped_column(String(8), nullable=True)
    rank: Mapped[int | None] = mapped_column(Integer, nullable=True)
    technical_impact: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[str | None] = mapped_column(String(24), nullable=True)
    standards_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    limitations_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Packet references: number, timestamp, offset. Never payload bytes.
    evidence_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class IntelligenceRow(Base):
    """The investigation's cryptographic intelligence, stored whole."""

    __tablename__ = "intelligence"

    investigation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    fingerprint_count: Mapped[int] = mapped_column(Integer, default=0)
    entity_count: Mapped[int] = mapped_column(Integer, default=0)
    drift_count: Mapped[int] = mapped_column(Integer, default=0)
    correlation_count: Mapped[int] = mapped_column(Integer, default=0)
    timeline_event_count: Mapped[int] = mapped_column(Integer, default=0)
    investigation_json: Mapped[str] = mapped_column(Text)


class MLResultRow(Base):
    """ML metadata and per-session results.

    Validation status is a column, not something a caller has to dig out of a
    JSON blob, because the UI must never render a classifier prediction
    without it.
    """

    __tablename__ = "ml_results"

    investigation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ml_status: Mapped[str] = mapped_column(String(24))
    feature_schema_version: Mapped[str | None] = mapped_column(String(24), nullable=True)
    anomaly_algorithm: Mapped[str | None] = mapped_column(String(48), nullable=True)
    anomaly_model_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    anomaly_model_version: Mapped[str | None] = mapped_column(String(24), nullable=True)
    classifier_model_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    classification_validation_status: Mapped[str] = mapped_column(
        String(24), default="NOT_VALIDATED"
    )
    anomalous_session_count: Mapped[int] = mapped_column(Integer, default=0)
    not_evaluable_session_count: Mapped[int] = mapped_column(Integer, default=0)
    results_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class ReportExportRow(Base):
    """A generated report, so exports can be listed and re-downloaded."""

    __tablename__ = "report_exports"

    export_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String(64), index=True)
    report_format: Mapped[str] = mapped_column(String(8))
    filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    contains_evidence_refs: Mapped[bool] = mapped_column(Boolean, default=True)


# ---------------------------------------------------------------------------
# migrations
# ---------------------------------------------------------------------------
def _migration_1(connection: Any) -> None:
    """Initial schema. Created from the model metadata."""
    Base.metadata.create_all(connection)


def _migration_2(connection: Any) -> None:
    """Widen the primary key of ``sessions`` and ``findings``.

    Both ids are deterministic digests of their content, so analysing the same
    capture in a second investigation produced the same ids again and the
    insert failed on the old single-column primary key. The investigation was
    marked FAILED with a raw database error, and the capture was effectively
    locked to whichever investigation used it first.

    SQLite cannot alter a primary key, so each table is rebuilt: create the new
    shape, copy the rows, drop the old table, rename. Existing rows all satisfy
    the wider key -- the old one was strictly stricter -- so nothing is lost.
    """
    for table in ("sessions", "findings"):
        info = connection.execute(text(f"PRAGMA table_info({table})")).fetchall()
        if not info:
            continue
        key = {row[1] for row in info if row[5]}
        if "investigation_id" in key:
            # Already the new shape: a database created after this migration
            # existed gets it from the model metadata in migration 1.
            continue

        columns = [row[1] for row in info]
        names = ", ".join(f'"{column}"' for column in columns)

        # SQLite carries a table's indexes across a RENAME, so they have to go
        # before the new table recreates them under the same names.
        indexes = connection.execute(
            text(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name=:table AND name NOT LIKE 'sqlite_%'"
            ),
            {"table": table},
        ).fetchall()

        connection.execute(text(f"ALTER TABLE {table} RENAME TO {table}_old"))
        for (index_name,) in indexes:
            connection.execute(text(f'DROP INDEX IF EXISTS "{index_name}"'))
        Base.metadata.tables[table].create(connection)
        # `table` comes from the literal tuple above and `names` from PRAGMA
        # table_info on that same table. Neither is user input, and SQLite does
        # not accept a bound parameter for an identifier, so the statement has
        # to be composed.
        copy = f"INSERT INTO {table} ({names}) SELECT {names} FROM {table}_old"  # noqa: S608
        connection.execute(text(copy))
        connection.execute(text(f"DROP TABLE {table}_old"))


#: Ordered. Index i applies when user_version == i, then sets it to i + 1.
_MIGRATIONS: Final = (_migration_1, _migration_2)


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    """Enforce foreign keys and use a durable, concurrent-friendly journal.

    SQLite disables foreign keys by default, which would let this schema drift
    into orphaned rows silently.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
    finally:
        cursor.close()


class Database:
    """A local SQLite database with explicit, ordered migrations."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            f"sqlite:///{self.path}",
            future=True,
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        self._sessionmaker = sessionmaker(
            bind=self.engine, expire_on_commit=False, future=True
        )
        self.migrate()

    def migrate(self) -> int:
        """Apply pending migrations. Returns the resulting schema version."""
        with self.engine.begin() as connection:
            current = connection.execute(text("PRAGMA user_version")).scalar_one()
            for index in range(int(current), len(_MIGRATIONS)):
                _MIGRATIONS[index](connection)
                connection.execute(text(f"PRAGMA user_version={index + 1}"))
            return len(_MIGRATIONS)

    @property
    def schema_version(self) -> int:
        with self.engine.connect() as connection:
            return int(connection.execute(text("PRAGMA user_version")).scalar_one())

    @contextmanager
    def session(self) -> Iterator[Session]:
        """A transactional scope. Commits on success, rolls back on error."""
        db_session = self._sessionmaker()
        try:
            yield db_session
            db_session.commit()
        except Exception:
            db_session.rollback()
            raise
        finally:
            db_session.close()

    def recover_interrupted_jobs(self) -> int:
        """Mark jobs left running by a restart as failed.

        Conservative on purpose. A process that died mid-analysis left no
        results, and a job still marked RUNNING would either spin forever in
        the UI or, worse, be read as COMPLETED. Neither is true, so it is
        recorded as failed with the reason.
        """
        with self.session() as db_session:
            rows = (
                db_session.query(JobRow)
                .filter(JobRow.status.in_(("QUEUED", "RUNNING")))
                .all()
            )
            for row in rows:
                row.status = "FAILED"
                row.finished_at = utcnow()
                row.error = (
                    "The application restarted while this job was in progress. It "
                    "produced no results and is recorded as failed rather than "
                    "left appearing to run or assumed complete. Re-run the analysis."
                )
            for row in rows:
                investigation = db_session.get(InvestigationRow, row.investigation_id)
                if investigation is not None and investigation.status in (
                    "QUEUED",
                    "RUNNING",
                ):
                    investigation.status = "FAILED"
            return len(rows)

    def close(self) -> None:
        self.engine.dispose()
