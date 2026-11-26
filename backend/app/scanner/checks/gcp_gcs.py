"""Google Cloud Storage checks."""

from __future__ import annotations

from typing import Any

from app.scanner.helpers import (
    collect,
    require_bool,
    require_list,
    require_object,
    show,
    verdict,
)
from app.scanner.models import CheckResult, ScanContext, Severity, Unevaluable
from app.scanner.registry import check

PUBLIC_PRINCIPALS = {
    "allusers": "allUsers (anyone on the internet)",
    "allauthenticatedusers": "allAuthenticatedUsers (anyone with a Google account)",
}


def _public_grant(binding: object, number: int) -> str | None:
    label = f"IAM binding {number}"
    entry = require_object(binding, label)
    public = []
    for member in require_list(entry, "members", f"{label} members"):
        if not isinstance(member, str):
            raise Unevaluable(f"{label} has member {show(member)}, expected a string")
        principal = PUBLIC_PRINCIPALS.get(member.strip().lower())
        if principal and principal not in public:
            public.append(principal)
    if not public:
        return None
    role = entry.get("role")
    role_text = show(role) if isinstance(role, str) else "(unknown role)"
    return f"Role {role_text} is granted to {' and '.join(public)}"


@check(
    check_id="GCP-GCS-01",
    title="Bucket isn't public",
    severity=Severity.HIGH,
    provider="gcp",
    collection="gcs_buckets",
    resource_id_field="name",
)
def bucket_not_public(bucket: dict[str, Any], ctx: ScanContext) -> CheckResult:
    grants, unreadable = collect(require_list(bucket, "iam_bindings"), _public_grant)
    return verdict(
        grants, unreadable, "No IAM binding grants access to allUsers or allAuthenticatedUsers"
    )


@check(
    check_id="GCP-GCS-02",
    title="Bucket uses uniform bucket-level access",
    severity=Severity.LOW,
    provider="gcp",
    collection="gcs_buckets",
    resource_id_field="name",
)
def bucket_uses_uniform_access(bucket: dict[str, Any], ctx: ScanContext) -> CheckResult:
    if require_bool(bucket, "uniform_bucket_level_access"):
        return CheckResult.passed("Uniform bucket-level access is on")
    return CheckResult.failed(
        "Uniform bucket-level access is off (uniform_bucket_level_access is false), so "
        "object ACLs can grant access that the bucket's IAM policy doesn't show"
    )
