"""Scanner engine: the snapshot rules, concurrency, robustness and the registry."""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from app.scanner.engine import (
    Scanner,
    SnapshotError,
    UnknownAccountsError,
    load_snapshot,
    parse_snapshot,
)
from app.scanner.models import CheckResult, ScanContext, Severity, Status
from app.scanner.registry import CheckRegistry, check
from app.scanner.scoring import posture_score
from tests.conftest import INVENTORY_PATH, REGISTRY

PROD, DEV, AZURE, GCP = (
    "123456789012",
    "210987654321",
    "8f14e45f-ceea-4e7a-9d3b-2f6c1a0b7d21",
    "example-corp-gcp",
)

# Every finding the shipped snapshot must produce: (check, account, resource) -> status.
EXPECTED = {
    ("AWS-S3-01", PROD, "example-corp-web-assets"): "PASS",
    ("AWS-S3-01", PROD, "example-corp-public-downloads"): "FAIL",
    ("AWS-S3-01", PROD, "example-corp-logs"): "FAIL",
    ("AWS-EC2-01", PROD, "sg-0a1b2c3d4e5f60001"): "PASS",
    ("AWS-EC2-01", PROD, "sg-0a1b2c3d4e5f60002"): "FAIL",
    ("AWS-EC2-01", PROD, "sg-0a1b2c3d4e5f60003"): "FAIL",
    ("AWS-EC2-01", PROD, "sg-0a1b2c3d4e5f60004"): "FAIL",
    ("AWS-EC2-01", PROD, "sg-0a1b2c3d4e5f60005"): "PASS",
    ("AWS-EC2-01", PROD, "sg-0a1b2c3d4e5f60006"): "FAIL",
    ("AWS-EC2-01", PROD, "sg-0a1b2c3d4e5f60007"): "PASS",
    ("AWS-IAM-01", PROD, "alice"): "PASS",
    ("AWS-IAM-01", PROD, "bob"): "FAIL",
    ("AWS-IAM-01", PROD, "ci-deployer"): "PASS",
    ("AWS-IAM-01", PROD, "reporting-bot"): "PASS",
    ("AWS-IAM-01", PROD, "legacy-etl"): "PASS",
    ("AWS-IAM-01", PROD, "former-contractor"): "PASS",
    ("AWS-IAM-02", PROD, "alice"): "PASS",
    ("AWS-IAM-02", PROD, "bob"): "PASS",
    ("AWS-IAM-02", PROD, "ci-deployer"): "PASS",  # exactly 90 days old
    ("AWS-IAM-02", PROD, "reporting-bot"): "FAIL",  # 91 days old
    ("AWS-IAM-02", PROD, "legacy-etl"): "FAIL",
    ("AWS-IAM-02", PROD, "former-contractor"): "PASS",  # only an inactive key
    ("AWS-RDS-01", PROD, "orders-db"): "PASS",
    ("AWS-RDS-01", PROD, "analytics-replica"): "FAIL",
    ("AWS-S3-01", DEV, "example-corp-dev-artifacts"): "PASS",
    ("AWS-S3-01", DEV, "example-corp-dev-scratch"): "FAIL",
    ("AWS-EC2-01", DEV, "sg-0b1c2d3e4f5a60001"): "PASS",
    ("AWS-EC2-01", DEV, "sg-0b1c2d3e4f5a60002"): "CANNOT_SCAN",  # "twenty-two"
    ("AWS-IAM-01", DEV, None): "CANNOT_SCAN",  # AccessDenied
    ("AWS-IAM-02", DEV, None): "CANNOT_SCAN",
    ("AWS-RDS-01", DEV, None): "CANNOT_SCAN",  # UnauthorizedOperation
    ("AZ-STG-01", AZURE, "examplecorpdata"): "PASS",
    ("AZ-STG-01", AZURE, "examplecorppublic"): "FAIL",
    ("AZ-STG-01", AZURE, "examplecorpbackup"): "PASS",
    ("AZ-NSG-01", AZURE, "nsg-web"): "PASS",
    ("AZ-NSG-01", AZURE, "nsg-jumpbox"): "FAIL",
    ("AZ-NSG-01", AZURE, "nsg-mgmt"): "FAIL",
    ("AZ-NSG-01", AZURE, "nsg-locked"): "PASS",  # Deny + Outbound
    ("GCP-GCS-01", GCP, "example-corp-public-site"): "FAIL",
    ("GCP-GCS-01", GCP, "example-corp-ml-data"): "PASS",
    ("GCP-GCS-01", GCP, "example-corp-partner-share"): "FAIL",
    ("GCP-GCS-02", GCP, "example-corp-public-site"): "PASS",
    ("GCP-GCS-02", GCP, "example-corp-ml-data"): "FAIL",
    ("GCP-GCS-02", GCP, "example-corp-partner-share"): "PASS",
    ("GCP-VPC-01", GCP, "allow-ssh-from-iap"): "PASS",
    ("GCP-VPC-01", GCP, "allow-rdp-anywhere"): "FAIL",
    ("GCP-VPC-01", GCP, "allow-all-disabled"): "PASS",
    ("GCP-VPC-01", GCP, "allow-app-ports"): "PASS",
    ("GCP-VPC-01", GCP, "allow-ssh-egress"): "PASS",
}


def no_sleep(_: float) -> None:
    return None


def scan_raw(raw: dict[str, Any], registry: CheckRegistry = REGISTRY, **kwargs: Any) -> list[Any]:
    return Scanner(registry, sleep=no_sleep, **kwargs).scan(parse_snapshot(raw)).findings


def snapshot_with(account: dict[str, Any]) -> dict[str, Any]:
    base = {"provider": "aws", "account_id": "111", "name": "t", "simulated_latency_ms": 0}
    return {"snapshot_taken_at": "2026-10-01T00:00:00Z", "accounts": [{**base, **account}]}


# --- The shipped snapshot ---------------------------------------------------------


def test_shipped_snapshot_produces_exactly_the_expected_findings() -> None:
    findings = Scanner(REGISTRY, sleep=no_sleep).scan(load_snapshot(INVENTORY_PATH)).findings
    actual = {(f.check_id, f.account_id, f.resource_id): f.status.value for f in findings}
    assert len(findings) == len(actual)  # no duplicate findings
    assert actual == EXPECTED

    counts = Counter(f.status.value for f in findings)
    assert counts == {"PASS": 27, "FAIL": 18, "CANNOT_SCAN": 4}
    assert posture_score(counts["PASS"], counts["FAIL"]) == 60.0


def test_errored_collection_reports_its_code_and_no_resource_id() -> None:
    findings = Scanner(REGISTRY, sleep=no_sleep).scan(load_snapshot(INVENTORY_PATH), [DEV]).findings
    errored = [f for f in findings if f.check_id == "AWS-IAM-01"]
    assert len(errored) == 1
    assert errored[0].resource_id is None
    assert errored[0].details == "Could not read iam_users: AccessDenied"


def test_scanning_twice_gives_identical_findings() -> None:
    snapshot = load_snapshot(INVENTORY_PATH)
    scanner = Scanner(REGISTRY, sleep=no_sleep)
    assert scanner.scan(snapshot).findings == scanner.scan(snapshot).findings


def test_account_subset_is_scanned_in_snapshot_order() -> None:
    result = Scanner(REGISTRY, sleep=no_sleep).scan(load_snapshot(INVENTORY_PATH), [GCP, AZURE])
    assert [a.account_id for a in result.accounts] == [AZURE, GCP]
    assert {f.account_id for f in result.findings} == {AZURE, GCP}


def test_unknown_account_ids_are_rejected() -> None:
    with pytest.raises(UnknownAccountsError) as excinfo:
        Scanner(REGISTRY, sleep=no_sleep).scan(load_snapshot(INVENTORY_PATH), [PROD, "nope"])
    assert excinfo.value.account_ids == ["nope"]


# --- Concurrency -------------------------------------------------------------------


def latency_snapshot(latencies_ms: list[int]) -> dict[str, Any]:
    return {
        "snapshot_taken_at": "2026-10-01T00:00:00Z",
        "accounts": [
            {"provider": "aws", "account_id": str(i), "simulated_latency_ms": ms, "resources": {}}
            for i, ms in enumerate(latencies_ms)
        ],
    }


def timed_scan(latencies_ms: list[int], workers: int) -> float:
    snapshot = parse_snapshot(latency_snapshot(latencies_ms))
    start = time.monotonic()
    Scanner(REGISTRY, workers=workers).scan(snapshot)
    return time.monotonic() - start


def test_accounts_are_scanned_concurrently() -> None:
    # Same shape as the real snapshot (1.5 + 3 + 1 + 2.5 s), scaled down 10x.
    elapsed = timed_scan([150, 300, 100, 250], workers=4)
    assert 0.29 <= elapsed < 0.6  # about the slowest account, not the 0.8 s sum


def test_worker_limit_is_respected() -> None:
    elapsed = timed_scan([200, 200, 200, 200], workers=2)
    assert 0.39 <= elapsed < 0.7  # two waves of two


@pytest.mark.parametrize("latency", [-5, "fast", None, float("nan"), True])
def test_invalid_latency_is_ignored(latency: Any) -> None:
    findings = scan_raw(snapshot_with({"simulated_latency_ms": latency, "resources": {}}))
    assert findings == []


def test_latency_is_capped() -> None:
    waits: list[float] = []
    raw = snapshot_with({"simulated_latency_ms": 10**9, "resources": {}})
    Scanner(REGISTRY, max_latency_ms=500, sleep=waits.append).scan(parse_snapshot(raw))
    assert waits == [0.5]


# --- Collection and record rules ---------------------------------------------------


def test_errored_collection_gives_one_cannot_scan_per_check_on_it() -> None:
    findings = scan_raw(snapshot_with({"errors": {"iam_users": "AccessDenied"}, "resources": {}}))
    assert sorted(f.check_id for f in findings) == ["AWS-IAM-01", "AWS-IAM-02"]
    assert all(f.status is Status.CANNOT_SCAN and f.resource_id is None for f in findings)


def test_errors_take_precedence_over_resources() -> None:
    raw = snapshot_with(
        {
            "errors": {"rds_instances": "Throttling"},
            "resources": {"rds_instances": [{"db_instance_id": "db", "publicly_accessible": True}]},
        }
    )
    findings = scan_raw(raw)
    assert [(f.status, f.details) for f in findings] == [
        (Status.CANNOT_SCAN, "Could not read rds_instances: Throttling")
    ]


def test_missing_collection_produces_no_findings() -> None:
    assert scan_raw(snapshot_with({"errors": {}, "resources": {}})) == []


@pytest.mark.parametrize("value", [None, {"a": 1}, "buckets"])
def test_collection_that_is_not_a_list_cannot_scan(value: Any) -> None:
    findings = scan_raw(snapshot_with({"resources": {"rds_instances": value}}))
    assert [f.status for f in findings] == [Status.CANNOT_SCAN]


def test_resource_that_is_not_an_object_cannot_scan_and_others_continue() -> None:
    raw = snapshot_with(
        {
            "resources": {
                "rds_instances": [
                    "garbage",
                    {"db_instance_id": "db2", "publicly_accessible": False},
                ]
            }
        }
    )
    assert [f.status for f in scan_raw(raw)] == [Status.CANNOT_SCAN, Status.PASS]


def test_crashing_check_is_contained() -> None:
    registry = CheckRegistry()

    @check(
        check_id="TEST-BOOM",
        title="Crashes",
        severity=Severity.LOW,
        provider="aws",
        collection="things",
        resource_id_field="id",
        into=registry,
    )
    def boom(resource: dict[str, Any], ctx: ScanContext) -> CheckResult:
        if resource["id"] == "bad":
            raise ZeroDivisionError("bug")
        return CheckResult.passed("fine")

    raw = snapshot_with({"resources": {"things": [{"id": "bad"}, {"id": "good"}]}})
    findings = scan_raw(raw, registry)
    assert [(f.resource_id, f.status) for f in findings] == [
        ("bad", Status.CANNOT_SCAN),
        ("good", Status.PASS),
    ]
    assert "Internal error" in findings[0].details
    assert "bug" not in findings[0].details  # internals don't leak into findings


def test_untrusted_text_is_sanitised() -> None:
    raw = snapshot_with(
        {
            "errors": {"iam_users": "Denied\n\u202eevil"},
            "resources": {
                "rds_instances": [{"db_instance_id": "db\x00\n1", "publicly_accessible": False}]
            },
        }
    )
    findings = scan_raw(raw)
    assert all("\n" not in f.details and "\u202e" not in f.details for f in findings)
    rds = next(f for f in findings if f.check_id == "AWS-RDS-01")
    assert rds.resource_id == "db??1"


def test_unknown_provider_produces_no_findings() -> None:
    raw = snapshot_with({"provider": "oracle", "resources": {"s3_buckets": [{"name": "x"}]}})
    result = Scanner(REGISTRY, sleep=no_sleep).scan(parse_snapshot(raw))
    assert result.findings == []
    assert [a.provider for a in result.accounts] == ["oracle"]


# --- Snapshot-level problems fail the whole scan ------------------------------------


def test_missing_inventory_file(tmp_path: Path) -> None:
    with pytest.raises(SnapshotError, match="not found"):
        load_snapshot(tmp_path / "missing.json")


def test_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "inventory.json"
    path.write_text("{not json")
    with pytest.raises(SnapshotError, match="not valid JSON"):
        load_snapshot(path)


@pytest.mark.parametrize(
    "raw",
    [
        [],
        {"accounts": []},  # no snapshot time
        {"snapshot_taken_at": "yesterday", "accounts": []},
        {"snapshot_taken_at": "2026-10-01T00:00:00Z", "accounts": {}},
    ],
)
def test_malformed_snapshot(raw: Any, tmp_path: Path) -> None:
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(SnapshotError):
        load_snapshot(path)


def test_malformed_accounts_are_skipped() -> None:
    raw = {
        "snapshot_taken_at": "2026-10-01T00:00:00Z",
        "accounts": [
            "nonsense",
            {"provider": "aws"},  # no account_id
            {"account_id": "1"},  # no provider
            {"provider": "aws", "account_id": "2", "resources": {}},
            {"provider": "aws", "account_id": "2", "resources": {}},  # duplicate
        ],
    }
    assert [a.account_id for a in parse_snapshot(raw).accounts] == ["2"]


# --- Registry -------------------------------------------------------------------------


def test_builtin_catalog_has_the_ten_checks() -> None:
    assert [c.check_id for c in REGISTRY.list_checks()] == [
        "AWS-EC2-01",
        "AWS-IAM-01",
        "AWS-IAM-02",
        "AWS-RDS-01",
        "AWS-S3-01",
        "AZ-NSG-01",
        "AZ-STG-01",
        "GCP-GCS-01",
        "GCP-GCS-02",
        "GCP-VPC-01",
    ]


def test_registering_a_check_is_all_it_takes_to_run_it() -> None:
    registry = CheckRegistry()

    @check(
        check_id="AWS-S3-99",
        title="Bucket name is short",
        severity=Severity.LOW,
        provider="aws",
        collection="s3_buckets",
        resource_id_field="name",
        into=registry,
    )
    def short_name(bucket: dict[str, Any], ctx: ScanContext) -> CheckResult:
        if len(bucket["name"]) > 20:
            return CheckResult.failed("Name is longer than 20 characters")
        return CheckResult.passed("Name is short")

    findings = Scanner(registry, sleep=no_sleep).scan(load_snapshot(INVENTORY_PATH)).findings
    assert {f.check_id for f in findings} == {"AWS-S3-99"}
    assert len(findings) == 5  # every S3 bucket in both AWS accounts


def test_duplicate_check_id_is_rejected() -> None:
    registry = CheckRegistry()
    existing = REGISTRY.get("AWS-S3-01")
    registry.register(existing)
    with pytest.raises(ValueError, match="Duplicate"):
        registry.register(existing)


# --- Score ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("passed", "failed", "score"),
    [
        (27, 18, 60.0),
        (14, 10, 58.3),
        (2, 1, 66.7),
        (1, 15, 6.3),  # 6.25 rounds half up
        (0, 5, 0.0),
        (5, 0, 100.0),
        (0, 0, None),
    ],
)
def test_posture_score(passed: int, failed: int, score: float | None) -> None:
    assert posture_score(passed, failed) == score
