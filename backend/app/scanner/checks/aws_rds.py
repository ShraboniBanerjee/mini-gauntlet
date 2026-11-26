"""AWS RDS checks."""

from __future__ import annotations

from typing import Any

from app.scanner.helpers import require_bool
from app.scanner.models import CheckResult, ScanContext, Severity
from app.scanner.registry import check


@check(
    check_id="AWS-RDS-01",
    title="RDS instance isn't publicly accessible",
    severity=Severity.HIGH,
    provider="aws",
    collection="rds_instances",
    resource_id_field="db_instance_id",
)
def rds_instance_not_public(instance: dict[str, Any], ctx: ScanContext) -> CheckResult:
    if require_bool(instance, "publicly_accessible"):
        return CheckResult.failed(
            "Instance is publicly accessible (publicly_accessible is true), so its endpoint "
            "resolves to a public IP address"
        )
    return CheckResult.passed("Instance is not publicly accessible")
