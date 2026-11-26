"""Check registry.

A check is a plain function decorated with ``@check(...)``. The decorator records
the check's metadata in the registry, and the engine looks checks up by provider.
Every module in ``app/scanner/checks/`` is imported automatically, so adding a
check means writing one decorated function and nothing else.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.scanner.models import CheckResult, ScanContext, Severity

CheckFunction = Callable[[dict[str, Any], ScanContext], CheckResult]


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    severity: Severity
    provider: str
    collection: str
    resource_id_field: str
    evaluate: CheckFunction


class CheckRegistry:
    def __init__(self) -> None:
        self._checks: dict[str, Check] = {}

    def register(self, new_check: Check) -> None:
        if new_check.check_id in self._checks:
            raise ValueError(f"Duplicate check ID: {new_check.check_id}")
        self._checks[new_check.check_id] = new_check

    def get(self, check_id: str) -> Check:
        return self._checks[check_id]

    def list_checks(self) -> list[Check]:
        return sorted(self._checks.values(), key=lambda item: item.check_id)

    def for_provider(self, provider: str) -> list[Check]:
        return [item for item in self.list_checks() if item.provider == provider]

    def __len__(self) -> int:
        return len(self._checks)


registry = CheckRegistry()


def check(
    *,
    check_id: str,
    title: str,
    severity: Severity,
    provider: str,
    collection: str,
    resource_id_field: str,
    into: CheckRegistry | None = None,
) -> Callable[[CheckFunction], CheckFunction]:
    """Register the decorated function as a check (in the default registry unless ``into``)."""
    target = registry if into is None else into

    def decorator(func: CheckFunction) -> CheckFunction:
        target.register(
            Check(
                check_id=check_id,
                title=title,
                severity=severity,
                provider=provider.lower(),
                collection=collection,
                resource_id_field=resource_id_field,
                evaluate=func,
            )
        )
        return func

    return decorator


def load_builtin_checks() -> CheckRegistry:
    """Import every module in ``app.scanner.checks`` so its ``@check`` decorators run.

    Python caches imports, so calling this more than once registers nothing twice.
    """
    from app.scanner import checks as package

    for module in pkgutil.iter_modules(package.__path__):
        importlib.import_module(f"{package.__name__}.{module.name}")
    return registry
