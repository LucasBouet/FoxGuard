"""The sign-in page published services send people to.

**The one place the proxy is put in front of the Foxguard API**, and the reason
that is safe here and nowhere else: these endpoints identify the caller by
password and TOTP, not by source address. The portal and enrollment endpoints do
the opposite -- ``deps.calling_peer`` treats the source address as an identity
because cryptokey routing binds it to a key -- and a proxy in front of *those*
destroys the thing they run on. ``_sso_vhost`` in the renderer routes only
``/api/v1/sso/`` here and 404s everything else on that host name.

Two consequences of sitting behind our own proxy:

* **The real client address arrives in a header.** ``X-Foxguard-Client-IP`` is
  set by the proxy after deleting any copy the caller sent, so it cannot be
  forged -- but it is only trusted when the request actually came from the
  gateway. Without it every sign-in attempt would look like it came from the
  proxy and share one throttle budget.
* **The redirect target is validated against published services.** A login page
  that redirects wherever ``?h=`` says is a phishing hop wearing your own
  domain.
"""

from __future__ import annotations

import html

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...db import get_db
from ...models import ActorType
from ...services import admin_auth, audit
from ...services import proxy as proxy_service
from ...services import sso as sso_service
from ..deps import client_ip

router = APIRouter(prefix="/api/v1/sso", tags=["sso"])


def _origin_ip(request: Request, settings: Settings) -> str | None:
    """The browser's address, as far as it can be trusted.

    The header is only read when the request reached us from the gateway
    itself, which is where the proxy runs. Anywhere else it is an ordinary
    client-supplied string and is ignored -- the same reasoning that makes
    ``assert_no_forwarded_headers`` refuse the request outright on the portal,
    applied to an endpoint that can safely sit behind the proxy.
    """
    peer = client_ip(request)
    trusted = {settings.gateway_ip, "127.0.0.1", "::1", *settings.proxy_internal_listen}
    if peer in trusted:
        forwarded = request.headers.get("x-foxguard-client-ip")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return peer


def _safe_target(
    session: Session, settings: Settings, host: str | None, path: str | None
) -> str | None:
    """Where to send the browser after a successful sign-in.

    ``None`` unless the host is one Foxguard actually publishes. Rejecting
    rather than falling back to a default keeps the failure visible.
    """
    if not host:
        return None
    candidate = host.strip().lower()
    if candidate not in proxy_service.sso_hostnames(session, settings):
        return None
    tail = path or "/"
    if not tail.startswith("/") or tail.startswith("//"):
        tail = "/"
    return f"https://{candidate}{tail}"


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — Foxguard</title>
<style>
 :root{{color-scheme:light dark}}
 body{{font:15px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;
      min-height:100vh;background:Canvas;color:CanvasText}}
 form{{width:min(22rem,90vw);padding:2rem;border:1px solid color-mix(in srgb,CanvasText 15%,transparent);
      border-radius:12px}}
 h1{{font-size:1.1rem;margin:0 0 .25rem}}
 p.sub{{margin:0 0 1.5rem;opacity:.7;font-size:.85rem}}
 label{{display:block;margin-bottom:1rem;font-size:.85rem}}
 input{{width:100%;box-sizing:border-box;margin-top:.35rem;padding:.6rem;border-radius:6px;
       border:1px solid color-mix(in srgb,CanvasText 25%,transparent);background:Canvas;color:CanvasText}}
 button{{width:100%;padding:.65rem;border:0;border-radius:6px;background:CanvasText;color:Canvas;
        font-weight:600;cursor:pointer}}
 .err{{padding:.6rem .75rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem;
      background:color-mix(in srgb,#d33 15%,transparent)}}
</style></head><body>
<form method="post" action="/api/v1/sso/login">
  <h1>Sign in</h1>
  <p class="sub">{where}</p>
  {error}
  <input type="hidden" name="h" value="{host}">
  <input type="hidden" name="p" value="{path}">
  <label>Username<input name="username" autocomplete="username" autofocus required></label>
  <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
  <label>Six-digit code<input name="totp" inputmode="numeric" autocomplete="one-time-code"
         pattern="[0-9]*" placeholder="if enabled"></label>
  <button type="submit">Sign in</button>
</form></body></html>"""


def _render_page(host: str | None, path: str | None, error: str | None) -> str:
    where = f"to continue to {html.escape(host)}" if host else "Foxguard single sign-on"
    return _PAGE.format(
        where=where,
        host=html.escape(host or "", quote=True),
        path=html.escape(path or "", quote=True),
        error=f'<div class="err">{html.escape(error)}</div>' if error else "",
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    h: str | None = None,
    p: str | None = None,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> HTMLResponse:
    """The sign-in form. Served by the API, not the dashboard.

    Self-contained HTML on purpose: the dashboard lives on the tunnel and a
    person reaching a published service from outside cannot load it.
    """
    if sso_service.secret_problem(settings):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "single sign-on is not configured")
    target = _safe_target(session, settings, h, p)
    return HTMLResponse(
        _render_page(
            h if target else None,
            p if target else None,
            None if target or not h else "that destination is not a published service",
        )
    )


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp: str = Form(""),
    h: str = Form(""),
    p: str = Form(""),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Verify the credentials, set the cookie, send the browser on.

    Reuses ``admin_auth.authenticate`` so there is one password and TOTP path in
    the system rather than a second one that drifts. What differs is what is
    handed back: an SSO cookie, which opens published services and **not** the
    admin API.
    """
    problem = sso_service.secret_problem(settings)
    if problem:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, problem)

    source = _origin_ip(request, settings)
    target = _safe_target(session, settings, h, p)

    outcome = admin_auth.authenticate(
        session,
        username=username,
        password=password,
        totp_code=totp or None,
        require_admin=False,
    )
    if not outcome:
        audit.record(
            session,
            action="sso.login_failed",
            actor_type=ActorType.USER,
            actor_label=username,
            source_ip=source,
            detail={"reason": outcome.reason},
        )
        session.commit()
        # One message for a bad password, a bad code and an unknown account.
        # Distinguishing them turns this page into an account enumerator.
        return HTMLResponse(
            _render_page(h or None, p or None, "those details did not work"),
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user = outcome.user
    if user is None:  # pragma: no cover - a truthy outcome always carries one
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication failed")
    token, row = sso_service.issue(
        session,
        settings,
        user,
        source_ip=source,
        user_agent=request.headers.get("user-agent"),
    )
    audit.record(
        session,
        action="sso.login",
        actor_type=ActorType.USER,
        actor_user_id=user.id,
        actor_label=user.username,
        object_type="sso_session",
        object_id=row.id,
        source_ip=source,
        detail={"target": target},
    )
    session.commit()

    redirect = RedirectResponse(target or "/api/v1/sso/ok", status_code=303)
    # Scoped to the parent domain so one sign-in covers every published service.
    # HttpOnly because nothing in a browser needs to read it; Secure because the
    # proxy only ever serves this over TLS; Lax so a normal navigation carries
    # it while a cross-site POST does not.
    redirect.set_cookie(
        settings.proxy_sso_cookie_name,
        token,
        max_age=settings.proxy_sso_lifetime_seconds,
        domain=settings.proxy_domain or None,
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return redirect


@router.get("/ok", response_class=HTMLResponse)
def signed_in() -> HTMLResponse:
    """Where a sign-in with no destination lands."""
    return HTMLResponse(
        "<!doctype html><meta charset=utf-8><title>Signed in</title>"
        "<p style='font:15px system-ui;padding:2rem'>Signed in. Open the service "
        "you were trying to reach.</p>"
    )


@router.get("/logout")
def logout(
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Clear the cookie and revoke the session behind it.

    Both halves matter. Clearing the cookie alone would leave a token that still
    verifies, which is exactly the property that makes the proxy fast; revoking
    puts its id in the map the proxy consults, and the agent pushes that without
    a reload.
    """
    raw = request.cookies.get(settings.proxy_sso_cookie_name)
    if raw:
        import uuid

        from joserfc import jwt
        from joserfc.jwk import OctKey

        try:
            decoded = jwt.decode(raw, OctKey.import_key(settings.proxy_sso_secret_value))
            jti = uuid.UUID(str(decoded.claims.get("jti")))
        except Exception:  # noqa: BLE001 - a malformed cookie is just "no session"
            jti = None
        if jti and sso_service.revoke(session, settings, jti):
            audit.record(
                session,
                action="sso.logout",
                actor_type=ActorType.USER,
                object_type="sso_session",
                object_id=jti,
                source_ip=_origin_ip(request, settings),
            )
            session.commit()

    response = RedirectResponse("/api/v1/sso/login", status_code=303)
    response.delete_cookie(
        settings.proxy_sso_cookie_name, domain=settings.proxy_domain or None, path="/"
    )
    return response
