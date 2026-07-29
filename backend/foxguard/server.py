"""``foxguard-serve`` -- run the API with the settings its security model needs.

Plain ``uvicorn foxguard.main:app`` starts a server whose
``ProxyHeadersMiddleware`` is **on by default** and trusts ``127.0.0.1``. That
middleware rewrites ``scope["client"]`` from ``X-Forwarded-For`` before the
application runs, so ``request.client.host`` is no longer the address the
connection came from.

For most APIs that is a convenience. Here it is an authentication bypass: the
portal and the enrollment endpoint identify their caller *by that address*
(``deps.calling_peer``), because inside WireGuard it is bound to a public key.
Anything able to connect from ``127.0.0.1`` -- a process or container on the
gateway -- can name any peer's tunnel address in a header and be believed.

So this entry point exists to make the safe configuration the default one, and
the flag not something to remember at 3am:

    foxguard-serve --host 10.88.0.1 --port 8080

``deps.assert_no_forwarded_headers`` still guards the peer-identified endpoints
in case someone runs uvicorn directly. Both, on purpose: one prevents the
misconfiguration, the other survives it.
"""

from __future__ import annotations

import argparse
import logging

import uvicorn

from .config import get_settings

logger = logging.getLogger("foxguard")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="foxguard-serve",
        description="Run the Foxguard control plane with proxy headers disabled.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address. Use the tunnel address to serve the portal; never the WAN.",
    )
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help=(
            "Leave at 1. The login throttle and in-flight OIDC transactions are "
            "per-process; extra workers multiply the login budget and can drop an "
            "OIDC callback on a process that never saw the request. (Session "
            "expiry is safe either way -- it takes an advisory lock.)"
        ),
    )
    parser.add_argument("--reload", action="store_true", help="Development only.")
    args = parser.parse_args(argv)

    settings = get_settings()
    if args.workers > 1:
        logger.warning(
            "starting with %d workers: the portal login throttle is per-process, "
            "so the effective budget is %d times what you configured",
            args.workers,
            args.workers,
        )

    uvicorn.run(
        "foxguard.main:app",
        host=args.host,
        port=args.port,
        workers=args.workers if not args.reload else None,
        reload=args.reload,
        log_level=settings.log_level.lower(),
        # The reason this module exists. Do not "helpfully" turn it back on.
        proxy_headers=False,
        forwarded_allow_ips=[],
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
