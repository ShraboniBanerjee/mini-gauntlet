"""Application factory. Run with: uvicorn app.main:create_app --factory"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.api import build_router
from app.config import Settings
from app.scanner.engine import Scanner
from app.scanner.registry import load_builtin_checks
from app.service import ScanService
from app.store import Store

logger = logging.getLogger("app")


def create_app(
    settings: Settings | None = None, *, sleep: Callable[[float], None] = time.sleep
) -> FastAPI:
    """Build the app. Tests pass their own settings and a no-op ``sleep``."""
    settings = settings or Settings.from_env()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    registry = load_builtin_checks()
    store = Store(settings.database_path)
    scanner = Scanner(
        registry,
        workers=settings.scan_workers,
        max_latency_ms=settings.max_latency_ms,
        sleep=sleep,
    )
    service = ScanService(store, scanner, settings.inventory_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        store.initialize()
        interrupted = store.fail_interrupted_scans()
        if interrupted:
            logger.warning("Marked %d interrupted scan(s) as FAILED", interrupted)
        logger.info(
            "Ready: %d checks, %d workers, inventory %s",
            len(registry),
            settings.scan_workers,
            settings.inventory_path,
        )
        yield

    app = FastAPI(title="Mini Gauntlet API", version="1.0.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    app.include_router(build_router(store, service, registry))
    return app
