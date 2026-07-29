"""Serving the captive portal from the API process.

This looks like a deployment convenience and is actually a correctness
requirement.

The portal identifies its caller by the source address of the TCP connection
(``deps.calling_peer``), because inside WireGuard that address is bound to a
public key. ``deps.client_ip`` therefore reads ``request.client.host`` and
deliberately ignores ``X-Forwarded-For``.

Put *anything* in between -- a Next.js server rendering the page and calling the
API on the browser's behalf, an nginx in front, a Traefik doing TLS -- and the
API sees the intermediary's address instead of the peer's. Every portal request
then resolves to the wrong peer or, more likely, to none at all: a flat 403.

So the portal is a **static bundle executed by the browser**, served from the
same origin as the API. The browser calls ``/api/v1/portal/*`` itself, one TCP
connection from the peer to the gateway, and the address the API reads is the
peer's own. Same-origin also means no CORS exemption is needed, which matters on
the one surface a quarantined peer can already reach.

The mount is added *after* every router, so ``/api/...`` keeps winning and only
unmatched paths fall through to the bundle.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

__all__ = ["mount_portal"]


def mount_portal(app: FastAPI, directory: str | None) -> bool:
    """Serve ``directory`` at ``/``. Returns whether anything was mounted.

    A missing directory is a warning rather than a failure: the API must still
    start on a gateway where the portal has not been built, so that peers can be
    enrolled and the admin API used while the UI is sorted out.
    """
    if not directory:
        return False

    path = Path(directory)
    if not path.is_dir():
        logger.warning(
            "FOXGUARD_PORTAL_STATIC_DIR=%s does not exist; the portal will not be "
            "served (the API is unaffected)",
            directory,
        )
        return False

    # html=True serves index.html for directory paths, which is what a static
    # export needs for its routes to resolve.
    app.mount("/", StaticFiles(directory=str(path), html=True), name="portal")
    logger.info("serving the captive portal from %s", path)
    return True
