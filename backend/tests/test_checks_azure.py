"""Azure checks."""

from __future__ import annotations

from typing import Any

import pytest

from app.scanner.models import Status
from tests.conftest import evaluate

# --- AZ-STG-01 ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(False, Status.PASS), (True, Status.FAIL), ("false", Status.CANNOT_SCAN)],
)
def test_storage_public_blob_access(value: Any, expected: Status) -> None:
    account = {"name": "st1", "region": "centralindia", "allow_blob_public_access": value}
    assert evaluate("AZ-STG-01", account).status is expected


def test_storage_missing_field_cannot_scan() -> None:
    assert evaluate("AZ-STG-01", {"name": "st1"}).status is Status.CANNOT_SCAN


# --- AZ-NSG-01 ---------------------------------------------------------------------


def nsg(*rules: Any) -> dict[str, Any]:
    return {"name": "nsg-1", "region": "centralindia", "rules": list(rules)}


def nsg_rule(
    ports: Any = "22",
    source: Any = "*",
    *,
    direction: str = "Inbound",
    access: str = "Allow",
    protocol: str = "Tcp",
    name: str = "r1",
) -> dict[str, Any]:
    return {
        "name": name,
        "direction": direction,
        "access": access,
        "protocol": protocol,
        "source": source,
        "destination_ports": ports,
    }


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        (nsg_rule("22", "*"), Status.FAIL),
        (nsg_rule("22", "Internet"), Status.FAIL),
        (nsg_rule("22", "Any"), Status.FAIL),
        (nsg_rule("3389", "0.0.0.0/0"), Status.FAIL),
        (nsg_rule("22", "::/0"), Status.FAIL),
        (nsg_rule("3380-3400", "0.0.0.0/0", protocol="*"), Status.FAIL),  # port range
        (nsg_rule("*", "Internet"), Status.FAIL),  # every port
        (nsg_rule("80,3389", "Internet"), Status.FAIL),  # comma-separated list
        (nsg_rule(["443", "22"], "Internet"), Status.FAIL),  # list form
        (nsg_rule("22", ["10.0.0.0/8", "Internet"]), Status.FAIL),  # list of sources
        (nsg_rule("443", "Internet"), Status.PASS),
        (nsg_rule("23-3388", "Internet"), Status.PASS),
        (nsg_rule("22", "Internet", access="Deny"), Status.PASS),  # Deny rule
        (nsg_rule("22", "*", direction="Outbound"), Status.PASS),  # Outbound rule
        (nsg_rule("3389", "Internet", protocol="Udp"), Status.PASS),
        (nsg_rule("22", "VirtualNetwork"), Status.PASS),  # service tag, not internet
        (nsg_rule("22", "10.0.0.0/8"), Status.PASS),
    ],
)
def test_nsg_rules(rule: dict[str, Any], expected: Status) -> None:
    finding = evaluate("AZ-NSG-01", nsg(rule))
    assert finding.status is expected, finding.details


def test_nsg_fail_details_name_rule_port_and_source() -> None:
    finding = evaluate("AZ-NSG-01", nsg(nsg_rule("22", "*", name="allow-ssh")))
    assert finding.details == (
        'Inbound allow rule "allow-ssh" permits TCP port 22 from any source ("*"), '
        "exposing SSH (22)"
    )


def test_nsg_deny_and_outbound_only_passes() -> None:
    finding = evaluate(
        "AZ-NSG-01",
        nsg(
            nsg_rule("22", "Internet", access="Deny"),
            nsg_rule("22", "*", direction="Outbound"),
        ),
    )
    assert finding.status is Status.PASS


def test_nsg_allow_is_reported_even_alongside_a_deny() -> None:
    # The snapshot has no priorities, so an inbound Allow is treated as effective.
    finding = evaluate(
        "AZ-NSG-01", nsg(nsg_rule("22", "Internet", access="Deny"), nsg_rule("22", "Internet"))
    )
    assert finding.status is Status.FAIL


@pytest.mark.parametrize(
    "rule",
    [
        nsg_rule("ssh", "Internet"),
        nsg_rule("3400-3300", "Internet"),
        nsg_rule("22", "Internet", direction="Sideways"),
        nsg_rule("22", "Internet", access="Maybe"),
        nsg_rule("22", "0.0.0.0/99"),
        nsg_rule("", "Internet"),
    ],
)
def test_nsg_malformed_rules_cannot_scan(rule: dict[str, Any]) -> None:
    assert evaluate("AZ-NSG-01", nsg(rule)).status is Status.CANNOT_SCAN


def test_nsg_rules_not_a_list_cannot_scan() -> None:
    finding = evaluate("AZ-NSG-01", {"name": "nsg-1", "rules": "allow all"})
    assert finding.status is Status.CANNOT_SCAN
