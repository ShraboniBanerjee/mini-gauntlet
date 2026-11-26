"""Starting and running scans: the glue between the API, the engine and the store."""

from __future__ import annotations

import logging
from pathlib import Path

from app.scanner.engine import (
    Scanner,
    SnapshotError,
    UnknownAccountsError,
    load_snapshot,
    select_accounts,
)
from app.store import ScanRecord, Store

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, store: Store, scanner: Scanner, inventory_path: Path) -> None:
        self._store = store
        self._scanner = scanner
        self._inventory_path = inventory_path

    def create_scan(self, account_ids: list[str] | None) -> ScanRecord:
        """Validate the request and record a RUNNING scan.

        Raises ``UnknownAccountsError`` for IDs that aren't in the snapshot. If the
        snapshot can't be read right now, the scan is still created: running it
        will fail and record why, which is what a FAILED scan is for.
        """
        if account_ids is not None:
            account_ids = list(dict.fromkeys(account_ids))  # drop duplicates, keep order
            try:
                snapshot = load_snapshot(self._inventory_path)
            except SnapshotError:
                snapshot = None
            if snapshot is not None:
                select_accounts(snapshot, account_ids)
        return self._store.create_scan(account_ids)

    def run_scan(self, scan_id: str, account_ids: list[str] | None) -> None:
        """Runs in the background. Always leaves the scan COMPLETED or FAILED."""
        try:
            snapshot = load_snapshot(self._inventory_path)
            result = self._scanner.scan(snapshot, account_ids)
            self._store.complete_scan(scan_id, result)
        except (SnapshotError, UnknownAccountsError) as exc:
            logger.error("Scan %s failed: %s", scan_id, exc)
            self._safely_fail(scan_id, str(exc))
        except Exception:
            logger.exception("Scan %s crashed", scan_id)
            self._safely_fail(scan_id, "Internal error while running the scan")
        else:
            logger.info("Scan %s completed with %d findings", scan_id, len(result.findings))

    def _safely_fail(self, scan_id: str, error: str) -> None:
        try:
            self._store.fail_scan(scan_id, error)
        except Exception:
            logger.exception("Could not mark scan %s as FAILED", scan_id)
