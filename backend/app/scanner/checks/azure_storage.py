"""Azure Storage checks."""

from __future__ import annotations

from typing import Any

from app.scanner.helpers import require_bool
from app.scanner.models import CheckResult, ScanContext, Severity
from app.scanner.registry import check


@check(
    check_id="AZ-STG-01",
    title="Storage account blocks public blob access",
    severity=Severity.HIGH,
    provider="azure",
    collection="storage_accounts",
    resource_id_field="name",
)
def storage_account_blocks_public_blobs(account: dict[str, Any], ctx: ScanContext) -> CheckResult:
    if require_bool(account, "allow_blob_public_access"):
        return CheckResult.failed(
            "Anonymous public read access to blobs is allowed (allow_blob_public_access is true)"
        )
    return CheckResult.passed("Anonymous public blob access is disallowed")
