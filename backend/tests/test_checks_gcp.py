"""Google Cloud checks."""

from __future__ import annotations

from typing import Any

import pytest

from app.scanner.models import Status
from tests.conftest import evaluate

# --- GCP-GCS-01 ---------------------------------------------------------------------


def bucket(*bindings: Any, uniform: Any = True) -> dict[str, Any]:
    return {
        "name": "bkt",
        "region": "asia-south1",
        "uniform_bucket_level_access": uniform,
        "iam_bindings": list(bindings),
    }


def binding(*members: Any, role: str = "roles/storage.objectViewer") -> dict[str, Any]:
    return {"role": role, "members": list(members)}


@pytest.mark.parametrize(
    ("bindings", "expected", "detail"),
    [
        ([binding("allUsers")], Status.FAIL, "allUsers"),
        (
            [binding("allAuthenticatedUsers", "user:a@example.com")],
            Status.FAIL,
            "allAuthenticatedUsers",
        ),
        ([binding("group:eng@example.com")], Status.PASS, None),
        ([], Status.PASS, None),
    ],
)
def test_gcs_public(bindings: list[Any], expected: Status, detail: str | None) -> None:
    finding = evaluate("GCP-GCS-01", bucket(*bindings))
    assert finding.status is expected
    if detail:
        assert detail in finding.details
        assert "roles/storage.objectViewer" in finding.details


@pytest.mark.parametrize(
    "resource",
    [
        {"name": "bkt"},  # no iam_bindings
        bucket(binding(42)),
        bucket({"role": "roles/x"}),  # no members
    ],
)
def test_gcs_public_malformed_cannot_scan(resource: dict[str, Any]) -> None:
    assert evaluate("GCP-GCS-01", resource).status is Status.CANNOT_SCAN


# --- GCP-GCS-02 ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uniform", "expected"),
    [(True, Status.PASS), (False, Status.FAIL), ("true", Status.CANNOT_SCAN)],
)
def test_gcs_uniform_access(uniform: Any, expected: Status) -> None:
    assert evaluate("GCP-GCS-02", bucket(uniform=uniform)).status is expected


# --- GCP-VPC-01 ---------------------------------------------------------------------


def firewall(**overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "name": "fw-1",
        "region": "global",
        "direction": "INGRESS",
        "disabled": False,
        "source_ranges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    }
    rule.update(overrides)
    return rule


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        (firewall(), Status.FAIL),
        (firewall(allowed=[{"IPProtocol": "tcp", "ports": ["3389"]}]), Status.FAIL),
        (firewall(allowed=[{"IPProtocol": "tcp", "ports": ["20-25"]}]), Status.FAIL),
        (firewall(allowed=[{"IPProtocol": "tcp"}]), Status.FAIL),  # no ports: every port
        (firewall(allowed=[{"IPProtocol": "all"}]), Status.FAIL),
        (firewall(source_ranges=["::/0"]), Status.FAIL),
        (firewall(allowed=[{"IPProtocol": "tcp", "ports": ["8000-9000"]}]), Status.PASS),
        (firewall(allowed=[{"IPProtocol": "udp", "ports": ["22"]}]), Status.PASS),
        (firewall(source_ranges=["35.235.240.0/20"]), Status.PASS),
        (firewall(disabled=True), Status.PASS),  # disabled rule
        (firewall(direction="EGRESS"), Status.PASS),  # egress rule
        (firewall(allowed=None, denied=[{"IPProtocol": "all"}]), Status.PASS),
    ],
)
def test_vpc_rules(rule: dict[str, Any], expected: Status) -> None:
    if rule.get("allowed") is None:
        rule.pop("allowed", None)
    finding = evaluate("GCP-VPC-01", rule)
    assert finding.status is expected, finding.details


def test_vpc_fail_details() -> None:
    finding = evaluate("GCP-VPC-01", firewall(allowed=[{"IPProtocol": "tcp", "ports": ["3389"]}]))
    assert (
        finding.details == "Ingress rule allows TCP port 3389 from 0.0.0.0/0, exposing RDP (3389)"
    )


def test_vpc_rule_without_source_defaults_to_internet() -> None:
    rule = firewall()
    del rule["source_ranges"]
    assert evaluate("GCP-VPC-01", rule).status is Status.FAIL
    rule["source_tags"] = ["bastion"]
    assert evaluate("GCP-VPC-01", rule).status is Status.PASS


@pytest.mark.parametrize(
    "rule",
    [
        firewall(allowed=[{"IPProtocol": "tcp", "ports": ["ssh"]}]),
        firewall(disabled="no"),
        firewall(direction="SIDEWAYS"),
        firewall(source_ranges=["0.0.0.0/0", "not-a-range"]),
        firewall(allowed="tcp:22"),
    ],
)
def test_vpc_malformed_cannot_scan(rule: dict[str, Any]) -> None:
    assert evaluate("GCP-VPC-01", rule).status is Status.CANNOT_SCAN


def test_vpc_untrusted_description_is_never_copied_into_details() -> None:
    rule = firewall(description="<img src=x onerror=alert(1)>")
    assert "<img" not in evaluate("GCP-VPC-01", rule).details
