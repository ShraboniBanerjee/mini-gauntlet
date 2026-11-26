"""Posture score: 100 * PASS / (PASS + FAIL), rounded half-up to one decimal place."""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal


def posture_score(passed: int, failed: int) -> float | None:
    """CANNOT_SCAN findings are not counted. Returns None when there is nothing to score."""
    total = passed + failed
    if total == 0:
        return None
    exact = Decimal(100 * passed) / Decimal(total)
    # Decimal avoids float surprises such as round(6.25, 1) == 6.2.
    return float(exact.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))
