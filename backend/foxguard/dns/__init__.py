"""Internal DNS for the tunnel.

Same shape as :mod:`foxguard.nftables`: ``model`` holds pure data, ``dnsmasq``
turns it into text, and the agent applies it. Nothing here talks to a database
or to the network.
"""

from .dnsmasq import (
    DnsValidationError,
    dns_digest,
    render_conf,
    render_hosts,
    reverse_zone,
    validate_spec,
)
from .model import (
    LABEL_RE,
    NAME_RE,
    CnameEntry,
    DnsSpec,
    HostEntry,
    RecordKind,
    ResolverMode,
)
from .naming import MAX_LABEL, derive_label, fallback_label

__all__ = [
    "LABEL_RE",
    "MAX_LABEL",
    "NAME_RE",
    "CnameEntry",
    "DnsSpec",
    "DnsValidationError",
    "HostEntry",
    "RecordKind",
    "ResolverMode",
    "derive_label",
    "dns_digest",
    "fallback_label",
    "render_conf",
    "render_hosts",
    "reverse_zone",
    "validate_spec",
]
