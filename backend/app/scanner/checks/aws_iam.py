"""AWS IAM checks."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from app.scanner.helpers import (
    clean,
    collect,
    parse_timestamp,
    require_bool,
    require_field,
    require_list,
    require_object,
    require_str,
    show,
    verdict,
)
from app.scanner.models import CheckResult, ScanContext, Severity, Unevaluable
from app.scanner.registry import check

MAX_ACCESS_KEY_AGE = timedelta(days=90)


@check(
    check_id="AWS-IAM-01",
    title="Console users have MFA",
    severity=Severity.HIGH,
    provider="aws",
    collection="iam_users",
    resource_id_field="user_name",
)
def console_users_have_mfa(user: dict[str, Any], ctx: ScanContext) -> CheckResult:
    if not require_bool(user, "console_access"):
        return CheckResult.passed("User has no console password, so console MFA does not apply")
    if require_bool(user, "mfa_enabled"):
        return CheckResult.passed("Console user has MFA enabled")
    return CheckResult.failed(
        "User can sign in to the AWS console without MFA "
        "(console_access is true, mfa_enabled is false)"
    )


def _stale_key(key: object, number: int, snapshot_taken_at: datetime) -> str | None:
    label = f"access key {number}"
    entry = require_object(key, label)

    status = require_str(entry, "status", f"{label} status").lower()
    if status == "inactive":
        return None
    if status != "active":
        raise Unevaluable(f"{label} status is {show(entry['status'])}, expected Active or Inactive")

    created_at = parse_timestamp(
        require_field(entry, "created_at", f"{label} created_at"), f"{label} created_at"
    )
    age = snapshot_taken_at - created_at
    if age <= MAX_ACCESS_KEY_AGE:  # exactly 90 days old is not "older than 90 days"
        return None

    key_id = entry.get("key_id")
    name = clean(key_id, 64) if isinstance(key_id, str) and key_id.strip() else f"#{number}"
    return (
        f"Active access key {name} is {age.days} days old "
        f"(created {created_at:%Y-%m-%d}), over the 90-day limit"
    )


@check(
    check_id="AWS-IAM-02",
    title="No active access key is older than 90 days",
    severity=Severity.MEDIUM,
    provider="aws",
    collection="iam_users",
    resource_id_field="user_name",
)
def access_keys_rotated(user: dict[str, Any], ctx: ScanContext) -> CheckResult:
    stale, unreadable = collect(
        require_list(user, "access_keys"),
        lambda key, number: _stale_key(key, number, ctx.snapshot_taken_at),
    )
    return verdict(stale, unreadable, "No active access key is older than 90 days")
