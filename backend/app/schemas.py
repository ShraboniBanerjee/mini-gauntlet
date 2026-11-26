"""Request and response models for the REST API."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

ScanStatus = Literal["RUNNING", "COMPLETED", "FAILED"]
AccountId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_ids: Annotated[list[AccountId], Field(min_length=1, max_length=100)] | None = None


class StatusCounts(BaseModel):
    PASS: int = 0
    FAIL: int = 0
    CANNOT_SCAN: int = 0


class SeverityCounts(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0


class ScanSummary(BaseModel):
    id: str
    status: ScanStatus
    started_at: str
    finished_at: str | None
    account_ids: list[str] | None = Field(
        description="Accounts scanned; null while a scan of every account hasn't started"
    )
    score: float | None
    counts: StatusCounts
    error: str | None = None


class AccountScore(BaseModel):
    account_id: str
    provider: str
    name: str | None
    score: float | None
    counts: StatusCounts


class ScanDetail(ScanSummary):
    fail_counts_by_severity: SeverityCounts
    accounts: list[AccountScore]


class FindingOut(BaseModel):
    id: int
    scan_id: str
    check_id: str
    title: str
    provider: str
    account_id: str
    region: str | None
    resource_id: str | None
    status: Literal["PASS", "FAIL", "CANNOT_SCAN"]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    details: str


class FindingsPage(BaseModel):
    items: list[FindingOut]
    total: int
    page: int
    page_size: int


class CheckOut(BaseModel):
    check_id: str
    title: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    provider: str
    collection: str
    resource_id_field: str
