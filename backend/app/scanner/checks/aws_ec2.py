"""AWS EC2 security group checks."""

from __future__ import annotations

from typing import Any

from app.scanner.helpers import (
    ALL_PORTS,
    admin_ports_in,
    collect,
    describe_admin_ports,
    describe_ports,
    internet_cidr,
    parse_port,
    require_field,
    require_list,
    require_object,
    show,
    verdict,
)
from app.scanner.models import CheckResult, ScanContext, Severity, Unevaluable
from app.scanner.registry import check

TCP = {"tcp", "6"}
ALL_TRAFFIC = {"-1", "all"}


def _ingress_exposure(rule: object, number: int) -> str | None:
    """Describe how one ingress rule exposes SSH or RDP to the internet, or return None.

    Fields are read only when the verdict depends on them: a UDP rule's ports, or the
    ports of a rule open only to private ranges, can't make it a FAIL.
    """
    label = f"ingress rule {number}"
    entry = require_object(rule, label)

    protocol_value = require_field(entry, "protocol", f"{label} protocol")
    if isinstance(protocol_value, bool) or not isinstance(protocol_value, (str, int)):
        raise Unevaluable(f"{label} protocol is {show(protocol_value)}")
    protocol = str(protocol_value).strip().lower()
    if protocol not in TCP | ALL_TRAFFIC:
        return None  # UDP, ICMP and others can't carry SSH or RDP sessions

    open_sources = []
    for cidr in require_list(entry, "cidrs", f"{label} cidrs"):
        network = internet_cidr(cidr, f"{label} source")
        if network:
            open_sources.append(network)
    if not open_sources:
        return None

    if protocol in ALL_TRAFFIC:
        port_range = ALL_PORTS
        what = f"all traffic (protocol {protocol})"
    else:
        low = parse_port(
            require_field(entry, "from_port", f"{label} from_port"), f"{label} from_port"
        )
        high = parse_port(require_field(entry, "to_port", f"{label} to_port"), f"{label} to_port")
        if low > high:
            raise Unevaluable(f"{label} port range {low}-{high} starts after it ends")
        port_range = (low, high)
        what = f"TCP {describe_ports([port_range])}"

    exposed = admin_ports_in([port_range])
    if not exposed:
        return None
    return (
        f"Inbound rule {number} allows {what} from {', '.join(open_sources)}, "
        f"exposing {describe_admin_ports(exposed)}"
    )


@check(
    check_id="AWS-EC2-01",
    title="Security group doesn't expose SSH or RDP to the internet",
    severity=Severity.CRITICAL,
    provider="aws",
    collection="security_groups",
    resource_id_field="group_id",
)
def security_group_blocks_admin_ports(group: dict[str, Any], ctx: ScanContext) -> CheckResult:
    exposures, unreadable = collect(require_list(group, "ingress"), _ingress_exposure)
    return verdict(
        exposures,
        unreadable,
        "No inbound rule exposes SSH (22) or RDP (3389) to 0.0.0.0/0 or ::/0",
    )
