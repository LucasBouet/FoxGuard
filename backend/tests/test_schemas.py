"""Response-model tests.

These exist because response serialisation failures are 500s that no amount of
request validation catches -- they only show up when a real database row is
serialised, which is exactly what unit tests on the ORM never do.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime

import pytest

from foxguard.models import ActorType
from foxguard.nftables import PeerState, PeerType
from foxguard.schemas import AuditLogRead, PeerRead


def _audit_payload(**overrides):
    payload = {
        "id": uuid.uuid4(),
        "created_at": datetime.now(UTC),
        "actor_type": ActorType.ADMIN,
        "actor_label": None,
        "action": "peer.create",
        "object_type": "peer",
        "object_id": str(uuid.uuid4()),
        "source_ip": "127.0.0.1",
        "detail": {},
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    "value",
    [
        ipaddress.IPv4Address("10.88.0.2"),
        ipaddress.IPv6Address("fd00:88::2"),
        ipaddress.IPv4Interface("10.88.0.2/32"),
        "10.88.0.2",
        None,
    ],
)
def test_audit_source_ip_accepts_what_psycopg_returns(value):
    """psycopg 3 hands back ipaddress objects for INET columns, not strings."""
    model = AuditLogRead(**_audit_payload(source_ip=value))
    assert model.source_ip is None or isinstance(model.source_ip, str)


def test_peer_tunnel_addresses_accept_ipaddress_objects():
    peer = PeerRead(
        id=uuid.uuid4(),
        name="laptop",
        description=None,
        peer_type=PeerType.USER,
        state=PeerState.ACTIVE,
        wg_public_key="x" * 44,
        wg_interface="wg0",
        tunnel_ip=ipaddress.IPv4Address("10.88.0.2"),
        tunnel_ip6=ipaddress.IPv6Address("fd00:88::2"),
        owner_user_id=None,
        created_at=datetime.now(UTC),
    )
    assert peer.tunnel_ip == "10.88.0.2"
    assert peer.tunnel_ip6 == "fd00:88::2"


def test_audit_entry_serialises_to_json():
    """The failure mode was at JSON serialisation time, so assert on that."""
    model = AuditLogRead(**_audit_payload(source_ip=ipaddress.IPv4Address("10.0.0.1")))
    assert model.model_dump(mode="json")["source_ip"] == "10.0.0.1"


def test_a_peer_public_key_cannot_be_swapped_in_place():
    """It used to answer 200 and change nothing.

    Re-keying is the first thing an operator reaches for when a device's private
    key is lost, and unknown fields are dropped by default -- so the request
    succeeded, the key stayed, and the device still could not connect. A peer's
    identity *is* its key pair: the address, the DNS name, the memberships and
    the audit trail all hang off a key fixed at registration.
    """
    import pydantic

    from foxguard.schemas import PeerUpdate

    assert PeerUpdate(name="ok").name == "ok"
    with pytest.raises(pydantic.ValidationError, match="cannot be changed"):
        PeerUpdate(wg_public_key="ox3iCjdNGr7iHRvp1E+jSVNIUNt/5iaw86e15HOo0Vw=")
