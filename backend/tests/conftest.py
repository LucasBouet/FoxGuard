"""Shared test helpers.

Nothing here touches the database, the network or the ``nft`` binary: the
dataplane tests must run on a laptop, unprivileged, with no PostgreSQL around.
Database-backed tests opt in via the ``db_session`` fixture and are skipped when
``FOXGUARD_TEST_DATABASE_URL`` is unset.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from foxguard.nftables import (
    Action,
    Endpoint,
    GatewaySpec,
    GroupSpec,
    PeerSpec,
    PeerState,
    PeerType,
    Protocol,
    RulesetSpec,
    RuleSpec,
)

# --------------------------------------------------------------------------- #
# spec builders
# --------------------------------------------------------------------------- #


def gateway(**overrides) -> GatewaySpec:
    defaults = dict(
        wg_interface="wg0",
        wan_interface=None,
        table_name="foxguard",
        portal_port=8080,
        internal_cidrs=("10.0.0.0/8", "192.168.0.0/16"),
        allow_dns_in_quarantine=True,
        allow_icmp_to_gateway=True,
    )
    defaults.update(overrides)
    return GatewaySpec(**defaults)


def peer(
    peer_id: str,
    ip: str | None = None,
    *,
    ip6: str | None = None,
    state: PeerState = PeerState.ACTIVE,
    groups: tuple[str, ...] = (),
    peer_type: PeerType = PeerType.USER,
) -> PeerSpec:
    return PeerSpec(
        id=peer_id,
        name=peer_id,
        state=state,
        peer_type=peer_type,
        tunnel_ip=ip,
        tunnel_ip6=ip6,
        group_slugs=groups,
    )


def rule(
    rule_id: str,
    *,
    src: Endpoint | None = None,
    dst: Endpoint | None = None,
    action: Action = Action.ACCEPT,
    protocol: Protocol = Protocol.ANY,
    priority: int = 100,
    port: int | None = None,
    port_end: int | None = None,
    comment: str | None = None,
) -> RuleSpec:
    return RuleSpec(
        id=rule_id,
        priority=priority,
        action=action,
        src=src or Endpoint.any_(),
        dst=dst or Endpoint.any_(),
        protocol=protocol,
        dst_port_start=port,
        dst_port_end=port_end,
        comment=comment,
    )


def spec(
    *,
    groups: tuple[GroupSpec, ...] = (),
    peers: tuple[PeerSpec, ...] = (),
    rules: tuple[RuleSpec, ...] = (),
    gw: GatewaySpec | None = None,
) -> RulesetSpec:
    return RulesetSpec(
        gateway=gw or gateway(), groups=groups, peers=peers, rules=rules
    )


# --------------------------------------------------------------------------- #
# nft script inspection
# --------------------------------------------------------------------------- #


def chain_lines(ruleset: str, name: str) -> list[str]:
    """Return the actual rules of a chain.

    Blank lines, comments and the ``type ... hook ...`` declaration are stripped
    so that indices line up with rule evaluation order -- several tests assert
    on ``lines[0]`` / ``lines[-1]``.
    """
    lines = ruleset.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == f"chain {name} {{"), None
    )
    if start is None:
        raise AssertionError(f"chain {name!r} not found in ruleset")
    body: list[str] = []
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if stripped == "}":
            return body
        if not stripped or stripped.startswith("#") or stripped.startswith("type "):
            continue
        body.append(stripped)
    raise AssertionError(f"chain {name!r} is not closed")


def chain_header(ruleset: str, name: str) -> str:
    """Return the ``type ... hook ...`` declaration of a chain."""
    lines = ruleset.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == f"chain {name} {{"), None
    )
    if start is None:
        raise AssertionError(f"chain {name!r} not found in ruleset")
    for line in lines[start + 1 :]:
        if line.strip().startswith("type "):
            return line.strip()
    raise AssertionError(f"chain {name!r} has no type declaration")


def index_of(lines: list[str], needle: str) -> int:
    for position, line in enumerate(lines):
        if needle in line:
            return position
    raise AssertionError(f"{needle!r} not found in:\n" + "\n".join(lines))


def set_elements(ruleset: str, set_name: str) -> list[str]:
    """Return the elements declared for ``set_name`` (empty list if none)."""
    lines = ruleset.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == f"set {set_name} {{"), None
    )
    if start is None:
        raise AssertionError(f"set {set_name!r} not found in ruleset")
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if stripped == "}":
            return []
        if stripped.startswith("elements = {"):
            inner = stripped.split("{", 1)[1].rsplit("}", 1)[0]
            return [item.strip() for item in inner.split(",") if item.strip()]
    raise AssertionError(f"set {set_name!r} is not closed")


# --------------------------------------------------------------------------- #
# optional database fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def database_url() -> str:
    url = os.environ.get("FOXGUARD_TEST_DATABASE_URL")
    if not url:
        pytest.skip("FOXGUARD_TEST_DATABASE_URL is not set; skipping database tests")
    return url


@pytest.fixture()
def db_session(database_url: str) -> Iterator:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from foxguard.models import Base

    engine = create_engine(database_url, future=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()
