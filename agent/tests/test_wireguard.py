"""Tests for WireGuard peer reconciliation.

The important property here is the one the project constraints call out: a
reconciliation that changes nothing must touch nothing, so unrelated peers keep
their handshakes and their open connections.
"""

from __future__ import annotations

import pytest
from foxguard.nftables.applier import CommandResult

from foxguard_agent.client import WireGuardPeer
from foxguard_agent.wireguard import WireGuardError, WireGuardManager, _peer_sections

SHOWCONF = """[Interface]
ListenPort = 51820
PrivateKey = QEmxkfsEr9WNiXVUuTBmLuTLIbBigT8xMPHTgPq1L1Y=

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.88.0.2/32
"""

PEER_A = WireGuardPeer("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", ("10.88.0.2/32",))
PEER_B = WireGuardPeer("TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=", ("10.88.0.3/32",))


class FakeRunner:
    def __init__(self, showconf: str = SHOWCONF) -> None:
        self.calls: list[list[str]] = []
        self.showconf = showconf
        self.sync_result = CommandResult(0, "", "")

    def run(self, argv, *, timeout: float = 30.0) -> CommandResult:
        argv = list(argv)
        self.calls.append(argv)
        if "showconf" in argv:
            return CommandResult(0, self.showconf, "")
        return self.sync_result

    @property
    def commands(self) -> list[str]:
        return [call[1] for call in self.calls]


def test_interface_section_keeps_the_private_key_local():
    section = WireGuardManager.interface_section(SHOWCONF)
    assert "PrivateKey" in section
    assert "[Peer]" not in section
    assert "PublicKey" not in section


def test_render_config_orders_peers_deterministically():
    first = WireGuardManager.render_config("[Interface]\nListenPort = 51820", [PEER_A, PEER_B])
    second = WireGuardManager.render_config("[Interface]\nListenPort = 51820", [PEER_B, PEER_A])
    assert first == second
    assert first.count("[Peer]") == 2


def test_sync_is_a_no_op_when_nothing_changed():
    """No syncconf call at all -- existing handshakes are never disturbed."""
    runner = FakeRunner()
    manager = WireGuardManager("wg0", runner=runner)

    assert manager.sync([PEER_A]) is False
    assert runner.commands == ["showconf"]


def test_sync_applies_a_new_peer_with_syncconf():
    runner = FakeRunner()
    manager = WireGuardManager("wg0", runner=runner)

    assert manager.sync([PEER_A, PEER_B]) is True
    assert runner.commands == ["showconf", "syncconf"]


def test_sync_removes_peers_that_are_gone():
    runner = FakeRunner()
    manager = WireGuardManager("wg0", runner=runner)

    assert manager.sync([]) is True
    written = runner.calls[-1][-1]
    assert written.endswith(".conf")


def test_sync_never_uses_wg_quick():
    """wg-quick down/up would drop every tunnel on the box."""
    runner = FakeRunner()
    WireGuardManager("wg0", runner=runner).sync([PEER_B])
    assert all("quick" not in " ".join(call) for call in runner.calls)


def test_a_failing_syncconf_is_reported():
    runner = FakeRunner()
    runner.sync_result = CommandResult(1, "", "Unable to modify interface")
    with pytest.raises(WireGuardError, match="Unable to modify interface"):
        WireGuardManager("wg0", runner=runner).sync([PEER_B])


def test_peer_sections_ignore_formatting_differences():
    a = "[Peer]\nPublicKey = K1=\nAllowedIPs = 10.0.0.1/32, 10.0.0.2/32\n"
    b = "[Peer]\nallowedips=10.0.0.1/32,10.0.0.2/32\npublickey=K1=\n"
    assert _peer_sections(a) == _peer_sections(b)


def test_temp_config_is_removed_after_sync(tmp_path):
    from pathlib import Path

    runner = FakeRunner()
    WireGuardManager("wg0", runner=runner).sync([PEER_B])
    written = Path(runner.calls[-1][-1])
    assert not written.exists()
