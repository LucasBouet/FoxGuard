"""Turning a peer's display name into a DNS label.

Kept separate from the renderer because it is a *suggestion*, not a rule: the
derived label is what a peer gets when nobody chose one, and ``peers.dns_label``
overrides it. Derivation is therefore allowed to be lossy, and two peers whose
names differ only in punctuation are expected to collide -- the API reports that
as a conflict rather than inventing ``laptop-2``, because a name that silently
becomes something else is a name nobody can predict from the dashboard.
"""

from __future__ import annotations

import re
import unicodedata

__all__ = ["MAX_LABEL", "derive_label", "fallback_label"]

MAX_LABEL = 63

_NON_LABEL = re.compile(r"[^a-z0-9]+")


def derive_label(name: str) -> str | None:
    """Best-effort DNS label for a display name, or ``None`` if nothing is left.

    ``"Lucas' MacBook Pro"`` becomes ``lucas-macbook-pro``. Accents are folded
    rather than dropped (``"Café"`` -> ``cafe``), because dropping them turns
    two distinguishable devices into the same label.
    """
    folded = unicodedata.normalize("NFKD", name)
    ascii_only = folded.encode("ascii", "ignore").decode("ascii").lower()
    label = _NON_LABEL.sub("-", ascii_only).strip("-")[:MAX_LABEL].rstrip("-")
    return label or None


def fallback_label(peer_id: str) -> str:
    """Label for a peer whose name yields nothing usable (e.g. all emoji).

    Derived from the id so it is stable across restarts and unique without a
    lookup. Prefixed because a bare hex string is a legal label but reads like
    a mistake in the dashboard.
    """
    return f"peer-{str(peer_id).replace('-', '')[:12]}"
