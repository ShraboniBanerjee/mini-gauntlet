"""Google Cloud VPC firewall checks."""

from __future__ import annotations

from typing import Any

from app.scanner.helpers import (
    ALL_PORTS,
    admin_ports_in,
    collect,
    describe_admin_ports,
    describe_ports,
    internet_cidr,
    parse_port_spec,
    require_list,
    require_object,
    require_str,
    show,
    verdict,
)
from app.scanner.models import CheckResult, ScanContext, Severity, Unevaluable
from app.scanner.registry import check

TCP = {"tcp", "6"}
ALL_PROTOCOLS = {"all"}


def _allowed_exposure(entry: object, number: int, open_ranges: list[str]) -> str | None:
    label = f"allowed entry {number}"
    allowed = require_object(entry, label)
    protocol = require_str(allowed, "IPProtocol", f"{label} IPProtocol").lower()

    if protocol in ALL_PROTOCOLS:
        ranges = [ALL_PORTS]
        what = "all protocols and ports"
    elif protocol in TCP:
        # Google Cloud applies a TCP entry with no ports to every port.
        specs = require_list(allowed, "ports", f"{label} ports") if "ports" in allowed else []
        ranges = [parse_port_spec(spec, f"{label} port") for spec in specs] or [ALL_PORTS]
        what = f"TCP {describe_ports(ranges)}"
    else:
        return None  # UDP, ICMP and others can't carry SSH or RDP sessions

    exposed = admin_ports_in(ranges)
    if not exposed:
        return None
    return (
        f"Ingress rule allows {what} from {', '.join(open_ranges)}, "
        f"exposing {describe_admin_ports(exposed)}"
    )


@check(
    check_id="GCP-VPC-01",
    title="Firewall rule doesn't expose SSH or RDP to the internet",
    severity=Severity.CRITICAL,
    provider="gcp",
    collection="firewall_rules",
    resource_id_field="name",
)
def firewall_rule_blocks_admin_ports(rule: dict[str, Any], ctx: ScanContext) -> CheckResult:
    # Where Google Cloud documents a default for an omitted field, apply it.
    direction = rule.get("direction", "INGRESS")
    if not isinstance(direction, str):
        raise Unevaluable(f"direction is {show(direction)}, expected INGRESS or EGRESS")
    if direction.strip().upper() == "EGRESS":
        return CheckResult.passed("Egress rule, so it doesn't admit inbound traffic")
    if direction.strip().upper() != "INGRESS":
        raise Unevaluable(f"direction is {show(direction)}, expected INGRESS or EGRESS")

    disabled = rule.get("disabled", False)
    if not isinstance(disabled, bool):
        raise Unevaluable(f"disabled is {show(disabled)}, expected true or false")
    if disabled:
        return CheckResult.passed("Rule is disabled")

    if "source_ranges" in rule:
        sources = require_list(rule, "source_ranges")
    elif rule.get("source_tags") or rule.get("source_service_accounts"):
        sources = []  # matches tagged instances only, not IP ranges
    else:
        sources = ["0.0.0.0/0"]  # an ingress rule with no source applies to 0.0.0.0/0

    open_ranges = []
    for index, source in enumerate(sources, start=1):
        network = internet_cidr(source, f"source range {index}")
        if network:
            open_ranges.append(network)
    if not open_ranges:
        return CheckResult.passed("No source range is open to the internet")

    if "allowed" not in rule and "denied" in rule:
        return CheckResult.passed("Deny rule, so it doesn't admit traffic")
    exposures, unreadable = collect(
        require_list(rule, "allowed"),
        lambda entry, number: _allowed_exposure(entry, number, open_ranges),
    )
    return verdict(
        exposures, unreadable, "Rule doesn't allow SSH (22) or RDP (3389) from the internet"
    )
