"""Scanner engine: loads a snapshot and runs every registered check over it.

Accounts are scanned concurrently by a bounded thread pool. Each account first
waits its ``simulated_latency_ms`` (standing in for cloud API calls), then runs
the checks for its provider. Nothing a single account, collection or resource
contains can stop the scan: bad data becomes CANNOT_SCAN findings and warnings.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.scanner.helpers import clean, parse_timestamp, show
from app.scanner.models import Finding, ScanContext, Status, Unevaluable
from app.scanner.registry import Check, CheckRegistry

logger = logging.getLogger(__name__)

MAX_INVENTORY_BYTES = 50 * 1024 * 1024
MAX_DETAILS_LENGTH = 1000
DEFAULT_WORKERS = 4
DEFAULT_MAX_LATENCY_MS = 60_000


class SnapshotError(Exception):
    """The snapshot as a whole can't be read, so the scan fails."""


class UnknownAccountsError(Exception):
    def __init__(self, account_ids: Sequence[str]) -> None:
        self.account_ids = list(account_ids)
        super().__init__("Unknown account IDs: " + ", ".join(self.account_ids))


@dataclass(frozen=True)
class Account:
    account_id: str
    provider: str
    name: str | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class Snapshot:
    taken_at: datetime
    accounts: list[Account]


@dataclass(frozen=True)
class ScanResult:
    accounts: list[Account]
    findings: list[Finding]


# --- Loading ------------------------------------------------------------------------


def load_snapshot(path: Path) -> Snapshot:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        raise SnapshotError(f"Inventory file not found: {path}") from None
    except OSError as exc:
        raise SnapshotError(f"Inventory file can't be read: {exc.strerror}") from None
    if size > MAX_INVENTORY_BYTES:
        raise SnapshotError("Inventory file is larger than 50 MB")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        raise SnapshotError("Inventory file is not valid UTF-8") from None
    except json.JSONDecodeError as exc:
        raise SnapshotError(
            f"Inventory file is not valid JSON (line {exc.lineno}, column {exc.colno})"
        ) from None
    except OSError as exc:
        raise SnapshotError(f"Inventory file can't be read: {exc.strerror}") from None
    return parse_snapshot(raw)


def parse_snapshot(raw: object) -> Snapshot:
    if not isinstance(raw, dict):
        raise SnapshotError("Inventory must be a JSON object")
    try:
        taken_at = parse_timestamp(raw.get("snapshot_taken_at"), "snapshot_taken_at")
    except Unevaluable as exc:
        raise SnapshotError(f"Inventory {exc}") from None

    entries = raw.get("accounts")
    if not isinstance(entries, list):
        raise SnapshotError("Inventory accounts must be a list")

    accounts: list[Account] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        account = _parse_account(entry, index)
        if account is None:
            continue
        if account.account_id in seen:
            logger.warning(
                "Skipping account %d: duplicate account_id %r", index, account.account_id
            )
            continue
        seen.add(account.account_id)
        accounts.append(account)
    return Snapshot(taken_at=taken_at, accounts=accounts)


def _parse_account(entry: object, index: int) -> Account | None:
    if not isinstance(entry, dict):
        logger.warning("Skipping account %d: it is not an object", index)
        return None
    account_id = entry.get("account_id")
    if isinstance(account_id, bool) or not isinstance(account_id, (str, int)):
        logger.warning("Skipping account %d: account_id is %s", index, show(account_id))
        return None
    provider = entry.get("provider")
    if not isinstance(provider, str) or not provider.strip():
        logger.warning("Skipping account %d: provider is %s", index, show(provider))
        return None
    account_id_text = clean(str(account_id).strip(), 128)
    if not account_id_text:
        logger.warning("Skipping account %d: account_id is empty", index)
        return None
    name = entry.get("name")
    return Account(
        account_id=account_id_text,
        provider=clean(provider.strip().lower(), 32),
        name=clean(name, 200) if isinstance(name, str) else None,
        raw=entry,
    )


def select_accounts(snapshot: Snapshot, account_ids: Sequence[str] | None) -> list[Account]:
    """Every account when ``account_ids`` is None; otherwise exactly those, in snapshot order."""
    if account_ids is None:
        return list(snapshot.accounts)
    known = {account.account_id for account in snapshot.accounts}
    unknown = [account_id for account_id in dict.fromkeys(account_ids) if account_id not in known]
    if unknown:
        raise UnknownAccountsError(unknown)
    wanted = set(account_ids)
    return [account for account in snapshot.accounts if account.account_id in wanted]


# --- Evaluating ---------------------------------------------------------------------


def _finding(
    check: Check,
    account: Account,
    region: str | None,
    resource_id: str | None,
    status: Status,
    details: str,
) -> Finding:
    text = clean(details, MAX_DETAILS_LENGTH)
    return Finding(
        check_id=check.check_id,
        title=check.title,
        provider=account.provider,
        account_id=account.account_id,
        region=region,
        resource_id=resource_id,
        status=status,
        severity=check.severity,
        details=text[:1].upper() + text[1:],
    )


def _cannot_scan(
    check: Check, account: Account, region: str | None, resource_id: str | None, reason: str
) -> Finding:
    logger.warning(
        "CANNOT_SCAN %s account=%r resource=%r: %s",
        check.check_id,
        account.account_id,
        resource_id,
        reason,
    )
    return _finding(check, account, region, resource_id, Status.CANNOT_SCAN, reason)


def _resource_id(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = clean(str(value).strip(), 256)
    return text or None


def evaluate_resource(
    check: Check, account: Account, resource: object, index: int, context: ScanContext
) -> Finding:
    """Run one check on one resource. Never raises: failures become CANNOT_SCAN."""
    if not isinstance(resource, dict):
        return _cannot_scan(
            check, account, None, None, f"Resource {index} in {check.collection} is not an object"
        )
    region_value = resource.get("region")
    region = clean(region_value, 64) if isinstance(region_value, str) else None
    resource_id = _resource_id(resource.get(check.resource_id_field))
    if resource_id is None:
        return _cannot_scan(
            check,
            account,
            region,
            None,
            f"Resource {index} in {check.collection} has no valid {check.resource_id_field}",
        )
    try:
        result = check.evaluate(resource, context)
    except Unevaluable as exc:
        return _cannot_scan(check, account, region, resource_id, str(exc))
    except Exception:
        # A bug in one check must not stop the scan; log it with the traceback.
        logger.exception("Check %s crashed on resource %r", check.check_id, resource_id)
        return _cannot_scan(
            check, account, region, resource_id, "Internal error while evaluating this resource"
        )
    return _finding(check, account, region, resource_id, result.status, result.details)


def run_check_on_account(check: Check, account: Account, context: ScanContext) -> list[Finding]:
    """Apply the collection rules, then evaluate every resource in the check's collection."""
    errors = account.raw.get("errors") or {}
    if not isinstance(errors, dict):
        logger.warning("Account %r: errors is not an object; ignoring it", account.account_id)
        errors = {}
    resources = account.raw.get("resources")
    resources = {} if resources is None else resources
    collection = check.collection

    if collection in errors:
        code = clean(errors[collection], 100)
        return [_cannot_scan(check, account, None, None, f"Could not read {collection}: {code}")]
    if not isinstance(resources, dict):
        return [
            _cannot_scan(
                check, account, None, None, f"Could not read {collection}: resources is malformed"
            )
        ]
    if collection not in resources:
        return []  # missing from both resources and errors: no resources, no findings
    items = resources[collection]
    if not isinstance(items, list):
        return [
            _cannot_scan(
                check, account, None, None, f"Could not read {collection}: it is not a list"
            )
        ]
    return [
        evaluate_resource(check, account, item, index, context)
        for index, item in enumerate(items, start=1)
    ]


# --- Scanning -----------------------------------------------------------------------


class Scanner:
    def __init__(
        self,
        registry: CheckRegistry,
        *,
        workers: int = DEFAULT_WORKERS,
        max_latency_ms: int = DEFAULT_MAX_LATENCY_MS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if workers < 1:
            raise ValueError("workers must be at least 1")
        self._registry = registry
        self._workers = workers
        self._max_latency_ms = max_latency_ms
        self._sleep = sleep

    def scan(self, snapshot: Snapshot, account_ids: Sequence[str] | None = None) -> ScanResult:
        accounts = select_accounts(snapshot, account_ids)
        context = ScanContext(snapshot_taken_at=snapshot.taken_at)
        with ThreadPoolExecutor(
            max_workers=self._workers, thread_name_prefix="scan-account"
        ) as pool:
            # map() keeps snapshot order, so findings come out the same on every run.
            per_account = list(
                pool.map(lambda account: self._scan_account(account, context), accounts)
            )
        findings = [finding for group in per_account for finding in group]
        return ScanResult(accounts=accounts, findings=findings)

    def _scan_account(self, account: Account, context: ScanContext) -> list[Finding]:
        checks = self._registry.for_provider(account.provider)
        try:
            self._sleep(self._latency_seconds(account))
            if not checks:
                logger.warning(
                    "Account %r: no checks for provider %r", account.account_id, account.provider
                )
            findings: list[Finding] = []
            for check in checks:
                findings.extend(run_check_on_account(check, account, context))
            return findings
        except Exception:
            # Defensive: run_check_on_account already contains per-resource failures.
            logger.exception("Unexpected error while scanning account %r", account.account_id)
            return [
                _cannot_scan(
                    check, account, None, None, "Internal error while scanning this account"
                )
                for check in checks
            ]

    def _latency_seconds(self, account: Account) -> float:
        value = account.raw.get("simulated_latency_ms", 0)
        if value is None:
            return 0.0
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            logger.warning(
                "Account %r: ignoring invalid simulated_latency_ms %s",
                account.account_id,
                show(value),
            )
            return 0.0
        if value > self._max_latency_ms:
            logger.warning(
                "Account %r: capping simulated_latency_ms %s at %d",
                account.account_id,
                value,
                self._max_latency_ms,
            )
            value = self._max_latency_ms
        return float(value) / 1000
