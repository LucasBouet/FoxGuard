"""Country prefixes for the proxy, built on the gateway.

Two rules shape everything here, and both come from measurement rather than
taste.

**The reconciliation loop never reaches the internet.** Refreshing the dataset
is a separate, scheduled command (``foxguard-agent geo-refresh``). A reconcile
that depends on a third party being up is a reconcile that fails for reasons
that have nothing to do with Foxguard, and this one also installs firewall
rules.

**The map holds only the countries somebody asked about.** Measured against the
real DB-IP dataset and real HAProxy 3.0.11:

===============================  =========  ========  ==============
map                              entries    on disk   HAProxy RSS
===============================  =========  ========  ==============
none                             --         --        24.9 MiB
three countries, IPv4 only       33,948     0.6 MiB   34.4 MiB
three countries, IPv4 and IPv6   170,966    3.4 MiB   71.5 MiB
the whole world                  1,372,328  26.6 MiB  391.7 MiB
===============================  =========  ========  ==============

On a gateway that is often a 512 MiB container, shipping the planet is the
difference between a feature and an outage. A partial map is *correct*, not a
compromise: an address in no listed country simply does not match, so an allow
list refuses it and a deny list ignores it -- which is what each one means.

The dataset is `DB-IP lite <https://db-ip.com/db/download/ip-to-country-lite>`_,
chosen over MaxMind's GeoLite2 because it needs no account, no licence key and
no sign-up form on the operator's part. It is CC-BY-4.0, so
:data:`ATTRIBUTION` goes in the generated file.

None of this is a security control. Any VPN defeats it in one click. It is
noise reduction, and the documentation says so in those words.
"""

from __future__ import annotations

import gzip
import ipaddress
import logging
import os
import re
import tempfile
import urllib.request
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = [
    "ATTRIBUTION",
    "GeoBuilder",
    "GeoError",
    "dataset_url",
    "refresh_dataset",
]

#: Required by the dataset's licence, and it costs one comment line.
ATTRIBUTION = "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0"

_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")

#: Written next to the map so a reconcile can tell "already built for exactly
#: these countries" from "built for a different set", without parsing 3 MiB.
STAMP_SUFFIX = ".countries"


class GeoError(RuntimeError):
    """The map could not be built or refreshed."""


def dataset_url(when: datetime | None = None) -> str:
    """Where this month's dataset lives.

    DB-IP publishes one file per month at a predictable name. Deriving it from
    the date rather than hard-coding one keeps the agent from pinning itself to
    whatever month it was written in.
    """
    moment = when or datetime.now(UTC)
    return (
        "https://download.db-ip.com/free/"
        f"dbip-country-lite-{moment.year}-{moment.month:02d}.csv.gz"
    )


def refresh_dataset(destination: Path, *, url: str | None = None, timeout: float = 120.0) -> int:
    """Download the country dataset. Returns the byte count written.

    Written to a temporary file in the same directory and renamed, so an
    interrupted download can never leave a half-file that the next build would
    silently treat as the whole world.

    Falls back to the previous month once: on the first days of a month the
    current file may not be published yet, and failing then would mean the
    dataset goes stale every month for anyone whose timer fires early.
    """
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    candidates = [url] if url else _candidate_urls()
    last: Exception | None = None
    for candidate in candidates:
        try:
            return _download(candidate, destination, timeout)
        except OSError as exc:  # URLError is an OSError
            logger.warning("geo dataset not available at %s: %s", candidate, exc)
            last = exc
    raise GeoError(f"could not download the geo dataset: {last}")


def _candidate_urls() -> list[str]:
    now = datetime.now(UTC)
    previous = now.replace(day=1) - timedelta(days=1)
    return [dataset_url(now), dataset_url(previous)]


def _download(url: str, destination: Path, timeout: float) -> int:
    logger.info("fetching the geo dataset from %s", url)
    # delete=False and no context manager on the constructor: the file has to
    # outlive its own handle so it can be renamed into place. It *is* closed by
    # the `with handle` below, and removed by the except.
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        dir=destination.parent, prefix=destination.name, suffix=".part", delete=False
    )
    written = 0
    try:
        with handle:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                while chunk := response.read(1 << 16):
                    handle.write(chunk)
                    written += len(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, destination)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
    logger.info("geo dataset written to %s (%d bytes)", destination, written)
    return written


class GeoBuilder:
    """Turns the dataset into the one map HAProxy loads.

    ``build`` is idempotent and cheap to call on every reconciliation: it
    compares the requested countries against a stamp file and does nothing when
    they match.
    """

    def __init__(self, dataset: Path | str, map_path: Path | str) -> None:
        self._dataset = Path(dataset)
        self._map = Path(map_path)

    @property
    def map_path(self) -> Path:
        return self._map

    @property
    def dataset_path(self) -> Path:
        return self._dataset

    def has_dataset(self) -> bool:
        return self._dataset.exists() and self._dataset.stat().st_size > 0

    def current_countries(self) -> tuple[str, ...] | None:
        """What the map on disk was built for, or ``None`` if unknown."""
        stamp = self._map.with_suffix(self._map.suffix + STAMP_SUFFIX)
        if not stamp.exists() or not self._map.exists():
            return None
        return tuple(stamp.read_text().split())

    def build(self, countries: Iterable[str]) -> str:
        """Make the map match ``countries``. Returns what happened.

        ``"unchanged"``, ``"built"``, or ``"empty"`` -- the last meaning the
        countries were asked for and no dataset is present, so an empty map was
        written. Empty is deliberate rather than absent: ``haproxy -c`` resolves
        ``-f`` at parse time, so a missing file fails the *whole* configuration
        and would take every other service down with it. An empty one fails
        closed for an allow list and open for a deny list, and the caller
        reports it so neither is silent.
        """
        wanted = self._normalise(countries)

        if not wanted:
            # Nothing uses geo. Remove the map rather than leave a stale one:
            # nothing references it, and 3 MiB of dead prefixes on disk invites
            # somebody to wonder whether it is still in use.
            self._forget()
            return "unchanged"

        if self.current_countries() == wanted:
            return "unchanged"

        if not self.has_dataset():
            # Deliberately *without* a stamp. A stamp would say "built for FR"
            # about a file containing no prefixes, so the day the dataset
            # finally arrives this method would answer "unchanged" and the
            # filter would stay dead for as long as the country set held still.
            self._write(self._header(wanted, empty=True), None)
            return "empty"

        rows = list(self._entries(wanted))
        body = self._header(wanted, empty=False) + "".join(rows)
        self._write(body, wanted)
        logger.info(
            "geo map rebuilt for %s: %d prefixes", ", ".join(wanted), len(rows)
        )
        return "built"

    # -- internals --------------------------------------------------------- #

    @staticmethod
    def _normalise(countries: Iterable[str]) -> tuple[str, ...]:
        codes = {code.strip().upper() for code in countries if code and code.strip()}
        invalid = sorted(code for code in codes if not _COUNTRY_RE.fullmatch(code))
        if invalid:
            raise GeoError(f"not ISO 3166-1 alpha-2 country codes: {', '.join(invalid)}")
        return tuple(sorted(codes))

    def _header(self, countries: tuple[str, ...], *, empty: bool) -> str:
        lines = [
            "# Foxguard generated -- DO NOT EDIT BY HAND.",
            f"# {ATTRIBUTION}",
            f"# Countries: {', '.join(countries)}",
        ]
        if empty:
            lines.append(
                "# NO DATASET on this gateway, so this map is empty. An allow "
                "list therefore refuses everyone and a deny list blocks nobody."
            )
            lines.append("# Fix it with: foxguard-agent geo-refresh")
        return "\n".join(lines) + "\n"

    def _entries(self, wanted: tuple[str, ...]) -> Iterator[str]:
        """Ranges to prefixes, for the wanted countries only.

        DB-IP publishes inclusive ranges; HAProxy's ``map_ip`` wants prefixes.
        ``summarize_address_range`` is the exact conversion, and it is where the
        entry count roughly doubles -- 706k ranges become 1.37M prefixes for the
        whole world, which is the other half of why the subset matters.
        """
        keep = set(wanted)
        opener = gzip.open if self._dataset.suffix == ".gz" else open
        with opener(self._dataset, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.rstrip("\n").split(",")
                if len(parts) != 3 or parts[2] not in keep:
                    continue
                low, high, country = parts
                try:
                    networks = ipaddress.summarize_address_range(
                        ipaddress.ip_address(low), ipaddress.ip_address(high)
                    )
                    for network in networks:
                        yield f"{network} {country}\n"
                except (ValueError, TypeError):
                    # One malformed row must not cost the other 706,483.
                    continue

    def _write(self, body: str, countries: tuple[str, ...] | None) -> None:
        """Write the map, and stamp it only if it really holds those countries.

        ``countries=None`` means "this map is not the answer to anything", which
        leaves :meth:`current_countries` returning ``None`` and therefore forces
        a rebuild on the next pass.
        """
        self._map.parent.mkdir(parents=True, exist_ok=True)
        stamp = self._map.with_suffix(self._map.suffix + STAMP_SUFFIX)
        stamp.unlink(missing_ok=True)
        _atomic_write(self._map, body)
        # The stamp lands *after* the map, so an interrupted build leaves a map
        # with no stamp -- which reads as "unknown" and forces a rebuild, rather
        # than a stamp promising countries the map does not contain.
        if countries is not None:
            _atomic_write(stamp, " ".join(countries) + "\n")

    def _forget(self) -> None:
        self._map.unlink(missing_ok=True)
        self._map.with_suffix(self._map.suffix + STAMP_SUFFIX).unlink(missing_ok=True)


def _atomic_write(path: Path, content: str) -> None:
    # Same reason as _download: the temporary file is renamed over the target,
    # so it must survive its handle. Closed by `with`, removed by the except.
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        "w", dir=path.parent, prefix=path.name, suffix=".tmp", delete=False,
        encoding="utf-8",
    )
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(handle.name, 0o644)
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
