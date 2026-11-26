"""AWS checks: PASS, FAIL and CANNOT_SCAN for each, plus the catalog's edge cases."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.scanner.models import Status
from tests.conftest import SNAPSHOT_TIME, evaluate

ALL_ON = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
}


# --- AWS-S3-01 ------------------------------------------------------------------


def bucket(pab: Any = ALL_ON) -> dict[str, Any]:
    return {"name": "b1", "region": "us-east-1", "public_access_block": pab}


def test_s3_all_settings_on_passes() -> None:
    finding = evaluate("AWS-S3-01", bucket())
    assert finding.status is Status.PASS
    assert finding.resource_id == "b1"
    assert finding.region == "us-east-1"


def test_s3_settings_off_fails_and_names_them() -> None:
    finding = evaluate("AWS-S3-01", bucket({**ALL_ON, "block_public_acls": False}))
    assert finding.status is Status.FAIL
    assert "block_public_acls" in finding.details
    assert "ignore_public_acls" not in finding.details


def test_s3_missing_configuration_fails() -> None:
    finding = evaluate("AWS-S3-01", bucket(None))
    assert finding.status is Status.FAIL
    assert "No Block Public Access configuration" in finding.details


@pytest.mark.parametrize(
    "resource",
    [
        {"name": "b1"},  # field absent
        bucket({**ALL_ON, "block_public_policy": "yes"}),
        bucket({"block_public_acls": True}),  # settings missing
        bucket("enabled"),
    ],
)
def test_s3_malformed_cannot_scan(resource: dict[str, Any]) -> None:
    assert evaluate("AWS-S3-01", resource).status is Status.CANNOT_SCAN


# --- AWS-EC2-01 -------------------------------------------------------------------


def group(*rules: dict[str, Any]) -> dict[str, Any]:
    return {"group_id": "sg-1", "region": "us-east-1", "ingress": list(rules)}


def rule(protocol: Any = "tcp", low: Any = 22, high: Any = 22, *cidrs: Any) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "from_port": low,
        "to_port": high,
        "cidrs": list(cidrs) or ["0.0.0.0/0"],
    }


@pytest.mark.parametrize(
    ("ingress_rule", "expected", "detail"),
    [
        (rule("tcp", 22, 22), Status.FAIL, "SSH (22)"),
        (rule("tcp", 3389, 3389), Status.FAIL, "RDP (3389)"),
        (rule("tcp", 3000, 3500), Status.FAIL, "ports 3000-3500"),  # range covering 3389
        (rule("tcp", 0, 65535), Status.FAIL, "SSH (22) and RDP (3389)"),
        (rule("tcp", 20, 21), Status.PASS, None),  # range ending just below 22
        (rule("tcp", 23, 3388), Status.PASS, None),  # range between the two ports
        (rule("tcp", 3390, 4000), Status.PASS, None),
        (rule("tcp", 22, 22, "::/0"), Status.FAIL, "::/0"),  # IPv6 any
        (rule("tcp", 22, 22, "203.0.113.0/24"), Status.PASS, None),
        (rule("tcp", 22, 22, "10.0.0.0/8", "0.0.0.0/0"), Status.FAIL, "0.0.0.0/0"),
        (rule("-1", None, None), Status.FAIL, "all traffic"),
        (rule("udp", 22, 22), Status.PASS, None),
        (rule("udp", 53, 53), Status.PASS, None),
        (rule("6", 22, 22), Status.FAIL, "SSH (22)"),  # protocol number for TCP
        (rule("TCP", "22", "22"), Status.FAIL, "SSH (22)"),  # case and numeric strings
        (rule("tcp", 443, 443, "0.0.0.0/0", "::/0"), Status.PASS, None),
    ],
)
def test_ec2_rules(ingress_rule: dict[str, Any], expected: Status, detail: str | None) -> None:
    finding = evaluate("AWS-EC2-01", group(ingress_rule))
    assert finding.status is expected, finding.details
    if detail:
        assert detail in finding.details


def test_ec2_fail_details_name_rule_port_and_source() -> None:
    finding = evaluate("AWS-EC2-01", group(rule("tcp", 22, 22)))
    assert finding.details == "Inbound rule 1 allows TCP port 22 from 0.0.0.0/0, exposing SSH (22)"


def test_ec2_no_ingress_rules_passes() -> None:
    assert evaluate("AWS-EC2-01", group()).status is Status.PASS


@pytest.mark.parametrize(
    "ingress_rule",
    [
        rule("tcp", "twenty-two", 22),
        rule("tcp", 22, None),
        rule("tcp", 3400, 3300),  # start after end
        rule("tcp", 22, 70000),
        rule("tcp", True, 22),  # booleans aren't ports
        rule("tcp", 22, 22, "not-a-cidr"),
        {"protocol": "tcp", "from_port": 22, "to_port": 22},  # no cidrs
        "not an object",
    ],
)
def test_ec2_malformed_rules_cannot_scan(ingress_rule: Any) -> None:
    finding = evaluate("AWS-EC2-01", group(ingress_rule))
    assert finding.status is Status.CANNOT_SCAN


def test_ec2_port_that_is_not_a_number_is_explained() -> None:
    finding = evaluate("AWS-EC2-01", group(rule("tcp", "twenty-two", 22)))
    assert finding.status is Status.CANNOT_SCAN
    assert 'from_port is "twenty-two"' in finding.details


def test_ec2_malformed_ports_ignored_when_source_is_private() -> None:
    # Not reachable from the internet whatever the ports are, so the verdict is certain.
    finding = evaluate("AWS-EC2-01", group(rule("tcp", "twenty-two", 22, "10.0.0.0/8")))
    assert finding.status is Status.PASS


def test_ec2_exposure_wins_over_an_unreadable_rule() -> None:
    finding = evaluate("AWS-EC2-01", group(rule("tcp", "x", 22), rule("tcp", 22, 22)))
    assert finding.status is Status.FAIL
    assert "Could not evaluate" in finding.details


def test_ec2_missing_ingress_cannot_scan() -> None:
    assert evaluate("AWS-EC2-01", {"group_id": "sg-1"}).status is Status.CANNOT_SCAN


def test_ec2_missing_group_id_cannot_scan() -> None:
    finding = evaluate("AWS-EC2-01", {"ingress": []})
    assert finding.status is Status.CANNOT_SCAN
    assert finding.resource_id is None


# --- AWS-IAM-01 -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("console", "mfa", "expected"),
    [
        (True, True, Status.PASS),
        (True, False, Status.FAIL),
        (False, False, Status.PASS),  # no console password: MFA rule doesn't apply
        (False, "unknown", Status.PASS),  # mfa_enabled isn't needed for the verdict
        ("yes", True, Status.CANNOT_SCAN),
        (True, None, Status.CANNOT_SCAN),
    ],
)
def test_iam_console_mfa(console: Any, mfa: Any, expected: Status) -> None:
    user = {"user_name": "u", "console_access": console, "mfa_enabled": mfa}
    assert evaluate("AWS-IAM-01", user).status is expected


def test_iam_console_without_mfa_details() -> None:
    finding = evaluate(
        "AWS-IAM-01", {"user_name": "bob", "console_access": True, "mfa_enabled": False}
    )
    assert "without MFA" in finding.details


# --- AWS-IAM-02 -------------------------------------------------------------------


def user_with_keys(*keys: Any) -> dict[str, Any]:
    return {
        "user_name": "u",
        "console_access": False,
        "mfa_enabled": False,
        "access_keys": list(keys),
    }


def key(created: datetime | str, status: str = "Active", key_id: str = "k1") -> dict[str, Any]:
    created_text = (
        created if isinstance(created, str) else created.isoformat().replace("+00:00", "Z")
    )
    return {"key_id": key_id, "status": status, "created_at": created_text}


def test_iam_key_exactly_90_days_old_passes() -> None:
    finding = evaluate("AWS-IAM-02", user_with_keys(key("2026-07-03T00:00:00Z")))
    assert finding.status is Status.PASS


def test_iam_key_one_second_over_90_days_fails() -> None:
    created = SNAPSHOT_TIME - timedelta(days=90, seconds=1)
    assert evaluate("AWS-IAM-02", user_with_keys(key(created))).status is Status.FAIL


def test_iam_key_91_days_old_fails_with_details() -> None:
    finding = evaluate("AWS-IAM-02", user_with_keys(key("2026-07-02T00:00:00Z", key_id="AKIA-1")))
    assert finding.status is Status.FAIL
    assert finding.details == (
        "Active access key AKIA-1 is 91 days old (created 2026-07-02), over the 90-day limit"
    )


def test_iam_inactive_old_key_passes() -> None:
    finding = evaluate("AWS-IAM-02", user_with_keys(key("2020-01-01T00:00:00Z", "Inactive")))
    assert finding.status is Status.PASS


def test_iam_no_keys_passes() -> None:
    assert evaluate("AWS-IAM-02", user_with_keys()).status is Status.PASS


def test_iam_age_uses_snapshot_time_not_the_clock() -> None:
    resource = user_with_keys(key("2026-09-01T00:00:00Z"))
    assert evaluate("AWS-IAM-02", resource).status is Status.PASS
    later = datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert evaluate("AWS-IAM-02", resource, snapshot_taken_at=later).status is Status.FAIL


def test_iam_naive_timestamp_is_treated_as_utc() -> None:
    finding = evaluate("AWS-IAM-02", user_with_keys(key("2026-07-03T00:00:00")))
    assert finding.status is Status.PASS


@pytest.mark.parametrize(
    "bad_key",
    [
        key("last tuesday"),
        key("2026-07-01T00:00:00Z", status="Suspended"),
        {"key_id": "k1", "status": "Active"},  # no created_at
        "AKIA-123",
    ],
)
def test_iam_malformed_keys_cannot_scan(bad_key: Any) -> None:
    assert evaluate("AWS-IAM-02", user_with_keys(bad_key)).status is Status.CANNOT_SCAN


def test_iam_stale_key_fails_even_with_another_malformed_key() -> None:
    finding = evaluate(
        "AWS-IAM-02", user_with_keys(key("garbage"), key("2025-01-01T00:00:00Z", key_id="old"))
    )
    assert finding.status is Status.FAIL
    assert "old" in finding.details


# --- AWS-RDS-01 -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (False, Status.PASS),
        (True, Status.FAIL),
        ("true", Status.CANNOT_SCAN),
        (None, Status.CANNOT_SCAN),
    ],
)
def test_rds_publicly_accessible(value: Any, expected: Status) -> None:
    instance = {"db_instance_id": "db1", "region": "us-east-1", "publicly_accessible": value}
    assert evaluate("AWS-RDS-01", instance).status is expected
