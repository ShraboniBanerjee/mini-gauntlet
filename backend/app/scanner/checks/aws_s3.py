"""AWS S3 checks."""

from __future__ import annotations

from typing import Any

from app.scanner.helpers import require_field, require_object, show
from app.scanner.models import CheckResult, ScanContext, Severity, Unevaluable
from app.scanner.registry import check

BLOCK_PUBLIC_ACCESS_SETTINGS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)


@check(
    check_id="AWS-S3-01",
    title="S3 bucket blocks public access",
    severity=Severity.HIGH,
    provider="aws",
    collection="s3_buckets",
    resource_id_field="name",
)
def s3_bucket_blocks_public_access(bucket: dict[str, Any], ctx: ScanContext) -> CheckResult:
    config = require_field(bucket, "public_access_block")
    if config is None:
        # AWS returns no configuration when Block Public Access was never set up.
        return CheckResult.failed(
            "No Block Public Access configuration is set on the bucket; turn on "
            + ", ".join(BLOCK_PUBLIC_ACCESS_SETTINGS)
        )
    settings = require_object(config, "public_access_block")

    turned_off = []
    for setting in BLOCK_PUBLIC_ACCESS_SETTINGS:
        value = settings.get(setting)
        if not isinstance(value, bool):
            raise Unevaluable(
                f"public_access_block.{setting} is {show(value)}, expected true or false"
            )
        if not value:
            turned_off.append(setting)

    if turned_off:
        return CheckResult.failed(
            "Block Public Access settings are turned off: " + ", ".join(turned_off)
        )
    return CheckResult.passed("All four Block Public Access settings are on")
