"""Azure network security group checks."""

from __future__ import annotations

import re
from typing import Any

from app.scanner.helpers import (
    PortRange,
    admin_ports_in,
    collect,
    describe_admin_ports,
    describe_ports,
    internet_cidr,
    parse_port_spec,
    require_field,
    require_list,
    require_object,
    require_str,
    show,
    verdict,
)
from app.scanner.models import CheckResult, ScanContext, Severity, Unevaluable
from app.scanner.registry import check

ANY_SOURCE = {"*", "any"}
INTERNET_SOURCES = ANY_SOURCE | {"internet"}
TCP_OR_ANY = {"tcp", "*", "any"}
# Azure service tags such as VirtualNetwork, AzureLoadBalancer or Storage.WestUS.
# Anything else in a source must be an IP address or CIDR.
SERVICE_TAG = re.compile(r"[A-Za-z][A-Za-z0-9.]*")


def _is_internet_source(source: object, label: str) -> bool:
    if not isinstance(source, str) or not source.strip():
        raise Unevaluable(f"{label} is {show(source)}, expected an address prefix or service tag")
    text = source.strip()
    if text.lower() in INTERNET_SOURCES:
        return True
    if SERVICE_TAG.fullmatch(text):
        return False
    return internet_cidr(text, label) is not None


def _describe_source(source: str) -> str:
    if source.lower() in ANY_SOURCE:
        return f"any source ({show(source)})"
    return show(source)


def _parse_destination_ports(value: object, label: str) -> list[PortRange]:
    """Azure accepts "22", "3380-3400", "*", a comma-separated mix, or a list of those."""
    if isinstance(value, list):
        specs: list[object] = list(value)
    elif isinstance(value, str):
        specs = [part for part in value.split(",") if part.strip()]
    else:
        specs = [value]
    if not specs:
        raise Unevaluable(f"{label} is {show(value)}, expected at least one port")
    return [parse_port_spec(spec, label) for spec in specs]


def _rule_exposure(rule: object, number: int) -> str | None:
    entry = require_object(rule, f"rule {number}")
    name = entry.get("name")
    label = f"rule {show(name)}" if isinstance(name, str) and name.strip() else f"rule {number}"

    direction = require_str(entry, "direction", f"{label} direction").lower()
    if direction == "outbound":
        return None
    if direction != "inbound":
        raise Unevaluable(f"{label} direction is {show(entry['direction'])}")

    access = require_str(entry, "access", f"{label} access").lower()
    if access == "deny":
        return None
    if access != "allow":
        raise Unevaluable(f"{label} access is {show(entry['access'])}")

    protocol = require_str(entry, "protocol", f"{label} protocol").lower()
    if protocol not in TCP_OR_ANY:
        return None  # UDP, ICMP, ESP and AH can't carry SSH or RDP sessions

    source_value = require_field(entry, "source", f"{label} source")
    sources = source_value if isinstance(source_value, list) else [source_value]
    open_sources = [
        str(source).strip() for source in sources if _is_internet_source(source, f"{label} source")
    ]
    if not open_sources:
        return None

    ranges = _parse_destination_ports(
        require_field(entry, "destination_ports", f"{label} destination_ports"),
        f"{label} destination_ports",
    )
    exposed = admin_ports_in(ranges)
    if not exposed:
        return None

    what = "TCP" if protocol == "tcp" else "any protocol on"
    return (
        f"Inbound allow {label} permits {what} {describe_ports(ranges)} from "
        f"{', '.join(_describe_source(source) for source in open_sources)}, "
        f"exposing {describe_admin_ports(exposed)}"
    )


@check(
    check_id="AZ-NSG-01",
    title="NSG doesn't expose SSH or RDP to the internet",
    severity=Severity.CRITICAL,
    provider="azure",
    collection="network_security_groups",
    resource_id_field="name",
)
def nsg_blocks_admin_ports(nsg: dict[str, Any], ctx: ScanContext) -> CheckResult:
    # The snapshot has no rule priorities, so every inbound Allow rule is treated as
    # effective; Deny rules and outbound rules can never expose a port.
    exposures, unreadable = collect(require_list(nsg, "rules"), _rule_exposure)
    return verdict(
        exposures,
        unreadable,
        "No inbound Allow rule exposes SSH (22) or RDP (3389) to the internet",
    )
