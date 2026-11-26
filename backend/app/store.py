"""SQLite persistence for scans and their findings.

Each call opens its own short-lived connection, so the store is safe to use from
the request threads and the background scan threads at the same time. WAL mode
lets readers keep reading while a scan writes its findings.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.scanner.engine import ScanResult
from app.scanner.models import SEVERITY_ORDER, STATUS_ORDER

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    account_ids TEXT,             -- JSON list; NULL means "every account"
    error       TEXT
);

CREATE TABLE IF NOT EXISTS scan_accounts (
    scan_id    TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    account_id TEXT NOT NULL,
    provider   TEXT NOT NULL,
    name       TEXT,
    PRIMARY KEY (scan_id, account_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    check_id      TEXT NOT NULL,
    title         TEXT NOT NULL,
    provider      TEXT NOT NULL,
    account_id    TEXT NOT NULL,
    region        TEXT,
    resource_id   TEXT,
    status        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    details       TEXT NOT NULL,
    status_rank   INTEGER NOT NULL,  -- FAIL 0, CANNOT_SCAN 1, PASS 2
    severity_rank INTEGER NOT NULL   -- CRITICAL 0 ... LOW 3
);

CREATE INDEX IF NOT EXISTS ix_findings_scan_order
    ON findings (scan_id, status_rank, severity_rank, check_id, resource_id);
CREATE INDEX IF NOT EXISTS ix_scans_started ON scans (started_at);
"""

STATUS_RANK = {status.value: rank for rank, status in enumerate(STATUS_ORDER)}
SEVERITY_RANK = {severity.value: rank for rank, severity in enumerate(SEVERITY_ORDER)}

FINDING_COLUMNS = (
    "id, scan_id, check_id, title, provider, account_id, region, resource_id, "
    "status, severity, details"
)
FINDING_ORDER = "status_rank, severity_rank, check_id, resource_id, account_id, id"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class ScanRecord:
    id: str
    status: str
    started_at: str
    finished_at: str | None
    account_ids: list[str] | None
    error: str | None


@dataclass(frozen=True)
class AccountRecord:
    account_id: str
    provider: str
    name: str | None


@dataclass(frozen=True)
class FindingFilters:
    """Already-normalised filters. status and severity are upper case and validated."""

    status: str | None = None
    severity: str | None = None
    provider: str | None = None
    account_id: str | None = None
    check_id: str | None = None


Counts = dict[str, int]


class Store:
    def __init__(self, path: Path) -> None:
        self._path = path

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:  # commits on success, rolls back on error
                yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(SCHEMA)

    def fail_interrupted_scans(self) -> int:
        """A scan still RUNNING at startup was cut off by a restart; it will never finish."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE scans SET status = 'FAILED', finished_at = ?, error = ? "
                "WHERE status = 'RUNNING'",
                (utc_now(), "Interrupted because the API restarted before the scan finished"),
            )
            return cursor.rowcount

    # --- Writes -----------------------------------------------------------------

    def create_scan(self, account_ids: list[str] | None) -> ScanRecord:
        record = ScanRecord(
            id=str(uuid.uuid4()),
            status="RUNNING",
            started_at=utc_now(),
            finished_at=None,
            account_ids=account_ids,
            error=None,
        )
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scans (id, status, started_at, account_ids) VALUES (?, ?, ?, ?)",
                (
                    record.id,
                    record.status,
                    record.started_at,
                    None if account_ids is None else json.dumps(account_ids),
                ),
            )
        return record

    def complete_scan(self, scan_id: str, result: ScanResult) -> None:
        """Save every finding and mark the scan COMPLETED in one transaction."""
        accounts = [
            (scan_id, position, account.account_id, account.provider, account.name)
            for position, account in enumerate(result.accounts)
        ]
        findings = [
            (
                scan_id,
                finding.check_id,
                finding.title,
                finding.provider,
                finding.account_id,
                finding.region,
                finding.resource_id,
                finding.status.value,
                finding.severity.value,
                finding.details,
                STATUS_RANK[finding.status.value],
                SEVERITY_RANK[finding.severity.value],
            )
            for finding in result.findings
        ]
        account_ids = [account.account_id for account in result.accounts]
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO scan_accounts (scan_id, position, account_id, provider, name) "
                "VALUES (?, ?, ?, ?, ?)",
                accounts,
            )
            conn.executemany(
                "INSERT INTO findings (scan_id, check_id, title, provider, account_id, region, "
                "resource_id, status, severity, details, status_rank, severity_rank) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                findings,
            )
            conn.execute(
                "UPDATE scans SET status = 'COMPLETED', finished_at = ?, account_ids = ? "
                "WHERE id = ?",
                (utc_now(), json.dumps(account_ids), scan_id),
            )

    def fail_scan(self, scan_id: str, error: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status = 'FAILED', finished_at = ?, error = ? WHERE id = ?",
                (utc_now(), error, scan_id),
            )

    # --- Reads ------------------------------------------------------------------

    def list_scans(self) -> list[ScanRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC, rowid DESC"
            ).fetchall()
        return [_scan_record(row) for row in rows]

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return None if row is None else _scan_record(row)

    def status_counts(self) -> dict[str, Counts]:
        """Counts by status for every scan, keyed by scan ID."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT scan_id, status, COUNT(*) AS n FROM findings GROUP BY scan_id, status"
            ).fetchall()
        counts: dict[str, Counts] = {}
        for row in rows:
            counts.setdefault(row["scan_id"], {})[row["status"]] = row["n"]
        return counts

    def scan_status_counts(self, scan_id: str) -> Counts:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY status",
                (scan_id,),
            ).fetchall()
        return {row["status"]: row["n"] for row in rows}

    def fail_counts_by_severity(self, scan_id: str) -> Counts:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings "
                "WHERE scan_id = ? AND status = 'FAIL' GROUP BY severity",
                (scan_id,),
            ).fetchall()
        return {row["severity"]: row["n"] for row in rows}

    def account_status_counts(self, scan_id: str) -> dict[str, Counts]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT account_id, status, COUNT(*) AS n FROM findings "
                "WHERE scan_id = ? GROUP BY account_id, status",
                (scan_id,),
            ).fetchall()
        counts: dict[str, Counts] = {}
        for row in rows:
            counts.setdefault(row["account_id"], {})[row["status"]] = row["n"]
        return counts

    def scan_accounts(self, scan_id: str) -> list[AccountRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT account_id, provider, name FROM scan_accounts "
                "WHERE scan_id = ? ORDER BY position",
                (scan_id,),
            ).fetchall()
        return [AccountRecord(row["account_id"], row["provider"], row["name"]) for row in rows]

    def list_findings(
        self, scan_id: str, filters: FindingFilters, page: int, page_size: int
    ) -> tuple[list[dict[str, Any]], int]:
        clauses = ["scan_id = ?"]
        params: list[Any] = [scan_id]
        # Column names are fixed strings; every user-supplied value is a bound parameter.
        for column, value in (
            ("status", filters.status),
            ("severity", filters.severity),
            ("provider", filters.provider),
            ("account_id", filters.account_id),
            ("check_id", filters.check_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ? COLLATE NOCASE")
                params.append(value)
        where = " AND ".join(clauses)

        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM findings WHERE {where}",  # noqa: S608
                params,
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT {FINDING_COLUMNS} FROM findings WHERE {where} "  # noqa: S608
                f"ORDER BY {FINDING_ORDER} LIMIT ? OFFSET ?",
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        return [dict(row) for row in rows], int(total)


def _scan_record(row: sqlite3.Row) -> ScanRecord:
    account_ids = row["account_ids"]
    return ScanRecord(
        id=row["id"],
        status=row["status"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        account_ids=None if account_ids is None else json.loads(account_ids),
        error=row["error"],
    )
