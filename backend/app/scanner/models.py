"""Core types shared by the scanner engine, the checks and the API."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"  # noqa: S105 - a finding status, not a password
    FAIL = "FAIL"
    CANNOT_SCAN = "CANNOT_SCAN"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Sort order used by the API: FAIL first, then CANNOT_SCAN, then PASS;
# severity from CRITICAL down to LOW.
STATUS_ORDER: tuple[Status, ...] = (Status.FAIL, Status.CANNOT_SCAN, Status.PASS)
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)


class Unevaluable(Exception):  # noqa: N818 - reads naturally at raise sites
    """Raised by a check when a resource's fields can't be evaluated.

    The engine turns it into a CANNOT_SCAN finding whose details are the message.
    """


@dataclass(frozen=True)
class CheckResult:
    """What a check returns for one resource."""

    status: Status
    details: str

    @classmethod
    def passed(cls, details: str) -> CheckResult:
        return cls(Status.PASS, details)

    @classmethod
    def failed(cls, details: str) -> CheckResult:
        return cls(Status.FAIL, details)


@dataclass(frozen=True)
class ScanContext:
    """Scan-wide facts a check may need. Age-based rules use the snapshot time, never the clock."""

    snapshot_taken_at: datetime


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    provider: str
    account_id: str
    region: str | None
    resource_id: str | None
    status: Status
    severity: Severity
    details: str
