"""Defensive helpers for reading untrusted resource fields.

Every value in the inventory comes from a customer's cloud, so checks never
trust its shape. These helpers raise ``Unevaluable`` (which becomes a
CANNOT_SCAN finding) with a readable reason when a field is missing or has the
wrong type, and they make untrusted text safe to store and display.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, TypeVar

from app.scanner.models import CheckResult, Unevaluable

T = TypeVar("T")
PortRange = tuple[int, int]

MAX_PORT = 65535
ALL_PORTS: PortRange = (0, MAX_PORT)
ADMIN_PORTS: dict[int, str] = {22: "SSH", 3389: "RDP"}

# Control characters, zero-width characters and bidirectional overrides: they can
# hide or reorder text in logs and in the dashboard, so they never leave the scanner.
_UNSAFE_CHARS = re.compile(
    "[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
)
_PORT_NUMBER = re.compile(r"[0-9]{1,5}")


# --- Untrusted text -----------------------------------------------------------


def clean(value: object, limit: int = 200) -> str:
    """Render an untrusted value as one safe line of text, truncated to ``limit``."""
    text = value if isinstance(value, str) else str(value)
    text = _UNSAFE_CHARS.sub("?", text)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def show(value: object, limit: int = 60) -> str:
    """Quote an unexpected value for an error message: JSON-style, ASCII-only, truncated."""
    try:
        text = json.dumps(value, ensure_ascii=True)
    except (TypeError, ValueError):
        text = clean(repr(value))
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


# --- Typed field access ---------------------------------------------------------


def require_field(resource: Mapping[str, Any], field: str, label: str | None = None) -> Any:
    if field not in resource:
        raise Unevaluable(f"{label or field} is missing")
    return resource[field]


def require_bool(resource: Mapping[str, Any], field: str, label: str | None = None) -> bool:
    value = require_field(resource, field, label)
    if not isinstance(value, bool):
        raise Unevaluable(f"{label or field} is {show(value)}, expected true or false")
    return value


def require_str(resource: Mapping[str, Any], field: str, label: str | None = None) -> str:
    value = require_field(resource, field, label)
    if not isinstance(value, str) or not value.strip():
        raise Unevaluable(f"{label or field} is {show(value)}, expected a non-empty string")
    return value.strip()


def require_list(resource: Mapping[str, Any], field: str, label: str | None = None) -> list[Any]:
    value = require_field(resource, field, label)
    if not isinstance(value, list):
        raise Unevaluable(f"{label or field} is {show(value)}, expected a list")
    return value


def require_object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise Unevaluable(f"{label} is {show(value)}, expected an object")
    return value


def parse_timestamp(value: object, label: str) -> datetime:
    """Parse an ISO 8601 timestamp into an aware UTC datetime. Naive values are taken as UTC."""
    if not isinstance(value, str):
        raise Unevaluable(f"{label} is {show(value)}, expected an ISO 8601 timestamp")
    text = value.strip()
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"  # Python 3.10's fromisoformat doesn't accept "Z"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise Unevaluable(f"{label} {show(value)} is not an ISO 8601 timestamp") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# --- Ports and networks -------------------------------------------------------------


def parse_port(value: object, label: str) -> int:
    """Accept an integer port or a string of digits; anything else can't be evaluated."""
    if isinstance(value, int) and not isinstance(value, bool):
        port = value
    elif isinstance(value, str) and _PORT_NUMBER.fullmatch(value.strip()):
        port = int(value.strip())
    else:
        raise Unevaluable(f"{label} is {show(value)}, which is not a port number")
    if not 0 <= port <= MAX_PORT:
        raise Unevaluable(f"{label} {port} is outside the range 0-{MAX_PORT}")
    return port


def parse_port_range(low: object, high: object, label: str) -> PortRange:
    start = parse_port(low, f"{label} start")
    end = parse_port(high, f"{label} end")
    if start > end:
        raise Unevaluable(f"{label} {start}-{end} starts after it ends")
    return (start, end)


def parse_port_spec(spec: object, label: str) -> PortRange:
    """Parse one port expression: ``"22"``, ``"3380-3400"``, ``"*"`` or an integer."""
    if isinstance(spec, bool) or not isinstance(spec, (str, int)):
        raise Unevaluable(f"{label} is {show(spec)}, expected a port or a port range")
    text = str(spec).strip()
    if text.lower() in ("*", "any"):
        return ALL_PORTS
    if "-" in text:
        low, _, high = text.partition("-")
        return parse_port_range(low, high, label)
    port = parse_port(text, label)
    return (port, port)


def admin_ports_in(ranges: Iterable[PortRange]) -> list[int]:
    """The admin ports (SSH 22, RDP 3389) that fall inside any of the ranges."""
    ranges = list(ranges)
    return [port for port in ADMIN_PORTS if any(low <= port <= high for low, high in ranges)]


def describe_admin_ports(ports: Sequence[int]) -> str:
    return " and ".join(f"{ADMIN_PORTS[port]} ({port})" for port in ports)


def describe_ports(ranges: Sequence[PortRange]) -> str:
    if ALL_PORTS in ranges:
        return "all ports"
    parts = [f"port {low}" if low == high else f"ports {low}-{high}" for low, high in ranges]
    return ", ".join(parts)


def internet_cidr(value: object, label: str) -> str | None:
    """Return the normalised CIDR if it is open to the whole internet (prefix /0), else None."""
    if not isinstance(value, str):
        raise Unevaluable(f"{label} is {show(value)}, expected a CIDR")
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise Unevaluable(f"{label} {show(value)} is not a valid CIDR") from None
    return str(network) if network.prefixlen == 0 else None


# --- Combining per-item outcomes ---------------------------------------------------


def collect(
    items: Iterable[T], evaluate: Callable[[T, int], str | None]
) -> tuple[list[str], list[str]]:
    """Evaluate each item (numbered from 1) and split the outcomes.

    Returns ``(problems, unreadable)``: the problem descriptions ``evaluate``
    returned, and the reasons for items that raised ``Unevaluable``.
    """
    problems: list[str] = []
    unreadable: list[str] = []
    for number, item in enumerate(items, start=1):
        try:
            problem = evaluate(item, number)
        except Unevaluable as exc:
            unreadable.append(str(exc))
            continue
        if problem:
            problems.append(problem)
    return problems, unreadable


def verdict(problems: list[str], unreadable: list[str], pass_details: str) -> CheckResult:
    """Any problem is a FAIL, even if other items were unreadable: the FAIL is certain.

    With no problem, one unreadable item means we can't claim a PASS: CANNOT_SCAN.
    """
    if problems:
        details = "; ".join(problems)
        if unreadable:
            details += ". Could not evaluate: " + "; ".join(unreadable)
        return CheckResult.failed(details)
    if unreadable:
        raise Unevaluable("; ".join(unreadable))
    return CheckResult.passed(pass_details)
