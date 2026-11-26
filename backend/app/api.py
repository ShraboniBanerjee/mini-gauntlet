"""REST endpoints."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, Query

from app.scanner.engine import UnknownAccountsError
from app.scanner.models import Severity, Status
from app.scanner.registry import CheckRegistry
from app.scanner.scoring import posture_score
from app.schemas import (
    AccountScore,
    CheckOut,
    FindingOut,
    FindingsPage,
    ScanDetail,
    ScanRequest,
    ScanSummary,
    SeverityCounts,
    StatusCounts,
)
from app.service import ScanService
from app.store import Counts, FindingFilters, ScanRecord, Store

FilterParam = Annotated[str | None, Query(max_length=128)]


def _validation_error(location: list[str], message: str, value: Any) -> HTTPException:
    """A 422 shaped like FastAPI's own validation errors, so clients handle one format."""
    return HTTPException(
        status_code=422,
        detail=[{"loc": location, "msg": message, "type": "value_error", "input": value}],
    )


def _enum_filter(value: str | None, enum: type[Enum], name: str) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().upper().replace("-", "_").replace(" ", "_")
    allowed = [member.value for member in enum]
    if normalized not in allowed:
        raise _validation_error(["query", name], f"Must be one of: {', '.join(allowed)}", value)
    return normalized


def _text_filter(value: str | None) -> str | None:
    return value.strip() if value and value.strip() else None


def _status_counts(counts: Counts) -> StatusCounts:
    return StatusCounts(**{status.value: counts.get(status.value, 0) for status in Status})


def _summary(record: ScanRecord, counts: Counts) -> ScanSummary:
    return ScanSummary(
        id=record.id,
        status=record.status,  # type: ignore[arg-type]  # constrained by the DB CHECK
        started_at=record.started_at,
        finished_at=record.finished_at,
        account_ids=record.account_ids,
        score=posture_score(counts.get("PASS", 0), counts.get("FAIL", 0)),
        counts=_status_counts(counts),
        error=record.error,
    )


def build_router(store: Store, service: ScanService, registry: CheckRegistry) -> APIRouter:
    router = APIRouter(prefix="/api")

    @router.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @router.get("/checks")
    def list_checks() -> list[CheckOut]:
        return [
            CheckOut(
                check_id=item.check_id,
                title=item.title,
                severity=item.severity.value,
                provider=item.provider,
                collection=item.collection,
                resource_id_field=item.resource_id_field,
            )
            for item in registry.list_checks()
        ]

    @router.post("/scans", status_code=202)
    def start_scan(
        background_tasks: BackgroundTasks,
        request: Annotated[ScanRequest | None, Body()] = None,
    ) -> ScanSummary:
        account_ids = request.account_ids if request is not None else None
        try:
            record = service.create_scan(account_ids)
        except UnknownAccountsError as exc:
            raise _validation_error(["body", "account_ids"], str(exc), exc.account_ids) from None
        # Runs after the 202 is sent, in a worker thread.
        background_tasks.add_task(service.run_scan, record.id, record.account_ids)
        return _summary(record, {})

    @router.get("/scans")
    def list_scans() -> list[ScanSummary]:
        counts = store.status_counts()
        return [_summary(record, counts.get(record.id, {})) for record in store.list_scans()]

    @router.get("/scans/{scan_id}")
    def get_scan(scan_id: str) -> ScanDetail:
        record = store.get_scan(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        summary = _summary(record, store.scan_status_counts(scan_id))
        severity_counts = store.fail_counts_by_severity(scan_id)
        account_counts = store.account_status_counts(scan_id)
        accounts = [
            AccountScore(
                account_id=account.account_id,
                provider=account.provider,
                name=account.name,
                score=posture_score(
                    account_counts.get(account.account_id, {}).get("PASS", 0),
                    account_counts.get(account.account_id, {}).get("FAIL", 0),
                ),
                counts=_status_counts(account_counts.get(account.account_id, {})),
            )
            for account in store.scan_accounts(scan_id)
        ]
        return ScanDetail(
            **summary.model_dump(),
            fail_counts_by_severity=SeverityCounts(
                **{sev.value: severity_counts.get(sev.value, 0) for sev in Severity}
            ),
            accounts=accounts,
        )

    @router.get("/scans/{scan_id}/findings")
    def list_findings(
        scan_id: str,
        status: FilterParam = None,
        severity: FilterParam = None,
        provider: FilterParam = None,
        account_id: FilterParam = None,
        check_id: FilterParam = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> FindingsPage:
        if store.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        filters = FindingFilters(
            status=_enum_filter(status, Status, "status"),
            severity=_enum_filter(severity, Severity, "severity"),
            provider=_text_filter(provider),
            account_id=_text_filter(account_id),
            check_id=_text_filter(check_id),
        )
        rows, total = store.list_findings(scan_id, filters, page, page_size)
        return FindingsPage(
            items=[FindingOut(**row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    return router
