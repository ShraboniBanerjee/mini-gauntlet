from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from app.scanner.engine import Account, evaluate_resource
from app.scanner.models import Finding, ScanContext
from app.scanner.registry import load_builtin_checks

INVENTORY_PATH = Path(__file__).resolve().parents[2] / "data" / "inventory.json"
SNAPSHOT_TIME = datetime(2026, 10, 1, tzinfo=timezone.utc)

REGISTRY = load_builtin_checks()


def evaluate(
    check_id: str, resource: Any, *, snapshot_taken_at: datetime = SNAPSHOT_TIME
) -> Finding:
    """Run one check on one resource exactly as the engine does."""
    check = REGISTRY.get(check_id)
    account = Account(account_id="acct-1", provider=check.provider, name="test", raw={})
    return evaluate_resource(check, account, resource, 1, ScanContext(snapshot_taken_at))


@pytest.fixture
def inventory_path() -> Path:
    return INVENTORY_PATH
