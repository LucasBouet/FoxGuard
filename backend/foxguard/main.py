"""FastAPI application entry point."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import (
    acl,
    admin,
    agent,
    audit,
    dashboard,
    dns,
    enroll,
    groups,
    killswitch,
    peers,
    policies,
    portal,
    proxy,
    ruleset,
    services,
    sessions,
    sso,
    users,
    zones,
)
from .api.static import mount_portal
from .config import get_settings
from .services.scheduler import SessionSweeper

logger = logging.getLogger("foxguard")


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # Session expiry runs here rather than as a systemd timer so it ships
        # with the API and cannot be forgotten. It is safe under several workers
        # because each tick takes a PostgreSQL advisory lock first.
        sweeper = SessionSweeper(settings)
        await sweeper.start()
        try:
            yield
        finally:
            await sweeper.stop()

    app = FastAPI(
        title="Foxguard",
        version="0.1.0",
        description=(
            "Self-hosted WireGuard access control: groups, ACL policies and an "
            "nftables dataplane generated from a single source of truth."
        ),
        lifespan=lifespan,
    )

    if settings.dev_mode:
        # The admin UI runs on another port in development only. In production
        # it is served from the same origin, so no CORS exemption is needed.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        logger.warning(
            "dev mode is ON: CORS is open, and with no admin token configured "
            "any LOOPBACK request is treated as an administrator. Never set "
            "FOXGUARD_DEV_MODE on a gateway."
        )

    for router in (
        users.router,
        groups.router,
        zones.router,
        peers.router,
        acl.router,
        dns.router,
        services.router,
        proxy.router,
        sso.router,
        policies.router,
        ruleset.router,
        audit.router,
        agent.router,
        enroll.router,
        portal.router,
        sessions.router,
        dashboard.router,
        killswitch.router,
        admin.router,
    ):
        app.include_router(router)

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # Last, so every /api route and /healthz keep priority over the bundle.
    mount_portal(app, settings.portal_static_dir)

    return app


app = create_app()
