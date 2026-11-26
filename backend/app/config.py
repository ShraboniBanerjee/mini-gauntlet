"""Settings, read once from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INVENTORY_PATH = REPO_ROOT / "data" / "inventory.json"
DEFAULT_CORS_ORIGINS = "http://localhost:3000,http://localhost:5173"


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be a whole number, got {raw!r}") from None
    if value < 1:
        raise ValueError(f"{name} must be at least 1, got {value}")
    return value


@dataclass(frozen=True)
class Settings:
    inventory_path: Path
    database_path: Path
    scan_workers: int = 4
    max_latency_ms: int = 60_000
    cors_origins: tuple[str, ...] = ()
    log_level: str = "INFO"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        origins = env.get("CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
        return cls(
            inventory_path=Path(env.get("INVENTORY_PATH", str(DEFAULT_INVENTORY_PATH))),
            database_path=Path(env.get("DATABASE_PATH", "mini_gauntlet.db")),
            scan_workers=_positive_int(env, "SCAN_WORKERS", 4),
            max_latency_ms=_positive_int(env, "MAX_SIMULATED_LATENCY_MS", 60_000),
            cors_origins=tuple(origin.strip() for origin in origins.split(",") if origin.strip()),
            log_level=env.get("LOG_LEVEL", "INFO").upper(),
        )
