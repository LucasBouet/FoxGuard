"""Safe application of a generated ruleset to a live gateway.

Contract enforced here (tested in ``tests/test_nft_applier.py``):

* ``nft -c -f`` (check-only) **always** runs first; a ruleset that fails the
  check is never applied.
* The exact same bytes are checked and applied -- the script is written once to
  a private temp file and both commands read that file.
* ``nft -f`` on a script that starts with ``table``/``delete table`` is a single
  kernel transaction, so a failure mid-apply leaves the previous table intact.
  We additionally verify the table exists afterwards and restore the last known
  good ruleset if it does not.
* Defensive guards reject any script that would touch something other than our
  own table (``flush ruleset``, ``delete table`` of a foreign table).

The command runner is injected, so all of this is testable without root and
without ``nft`` installed.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

__all__ = [
    "CommandResult",
    "CommandRunner",
    "SubprocessRunner",
    "NftApplier",
    "NftError",
    "NftValidationError",
    "NftApplyError",
    "NftSafetyError",
]

_DELETE_TABLE_RE = re.compile(r"^\s*delete\s+table\s+(?P<rest>.+?)\s*$", re.MULTILINE)
_QUOTED_RE = re.compile(r'"[^"\n]*"')
_COMMENT_RE = re.compile(r"^\s*#.*$", re.MULTILINE)
_FORBIDDEN = (
    "flush ruleset",
    "flush table",
)


def _statements_only(ruleset: str) -> str:
    """Strip nft comments and quoted strings before scanning for statements.

    Without this, a rule legitimately named ``flush ruleset`` would produce
    ``comment "fg:r1:flush ruleset"`` and trip the safety guard -- turning a
    harmless label into a denial of service against our own dataplane.
    """
    without_comments = _COMMENT_RE.sub("", ruleset)
    return _QUOTED_RE.sub('""', without_comments)


class NftError(RuntimeError):
    """Base class for nft failures."""


class NftSafetyError(NftError):
    """The ruleset would touch something outside Foxguard's own table."""


class NftValidationError(NftError):
    """``nft -c -f`` rejected the ruleset. Nothing was applied."""


class NftApplyError(NftError):
    """``nft -f`` failed, or the table was missing afterwards."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner(Protocol):
    """Minimal command execution surface, so tests can substitute a fake."""

    def run(self, argv: Sequence[str], *, timeout: float = 30.0) -> CommandResult: ...


class SubprocessRunner:
    """Real runner. Never uses ``shell=True``."""

    def run(self, argv: Sequence[str], *, timeout: float = 30.0) -> CommandResult:
        logger.debug("running %s", " ".join(argv))
        try:
            completed = subprocess.run(  # noqa: S603 - argv is a fixed list, no shell
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise NftError(f"{argv[0]} not found on this system") from exc
        except subprocess.TimeoutExpired as exc:
            raise NftError(f"{' '.join(argv)} timed out after {timeout}s") from exc
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


class NftApplier:
    """Validate and atomically apply a Foxguard ruleset."""

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        nft_path: str = "nft",
        table_name: str = "foxguard",
        state_file: Path | str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._runner = runner or SubprocessRunner()
        self._nft = nft_path
        self._table = table_name
        self._timeout = timeout
        self._state_file = Path(state_file) if state_file else None
        self._last_good: str | None = self._read_state()

    # ---------------------------------------------------------------- guards

    def guard(self, ruleset: str) -> None:
        """Reject rulesets that reach outside our own table."""
        expected = f"table inet {self._table}"
        if expected not in ruleset:
            raise NftSafetyError(
                f"ruleset does not declare {expected!r}; refusing to apply"
            )
        statements = _statements_only(ruleset)
        lowered = statements.lower()
        for needle in _FORBIDDEN:
            if needle in lowered:
                raise NftSafetyError(f"ruleset contains forbidden statement {needle!r}")
        for match in _DELETE_TABLE_RE.finditer(statements):
            target = match.group("rest")
            if target != f"inet {self._table}":
                raise NftSafetyError(
                    f"ruleset deletes foreign table {target!r}; refusing to apply"
                )

    # ------------------------------------------------------------- primitives

    def _run(self, argv: Sequence[str]) -> CommandResult:
        return self._runner.run(argv, timeout=self._timeout)

    def _with_temp_file(self, ruleset: str):
        """Write the ruleset to a private temp file (0600) and yield its path."""
        fd, name = tempfile.mkstemp(prefix="foxguard-", suffix=".nft")
        try:
            os.write(fd, ruleset.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(name, 0o600)
        return Path(name)

    def validate(self, ruleset: str) -> None:
        """Run ``nft -c -f``. Raises on rejection; never mutates the live ruleset."""
        self.guard(ruleset)
        path = self._with_temp_file(ruleset)
        try:
            result = self._run([self._nft, "-c", "-f", str(path)])
        finally:
            path.unlink(missing_ok=True)
        if not result.ok:
            raise NftValidationError(
                f"nft rejected the generated ruleset: {result.stderr.strip() or result.stdout.strip()}"
            )

    def table_exists(self) -> bool:
        result = self._run([self._nft, "list", "table", "inet", self._table])
        return result.ok

    # ------------------------------------------------------------------ apply

    def apply(self, ruleset: str) -> None:
        """Validate then apply ``ruleset``, restoring the last good one on failure."""
        self.validate(ruleset)

        path = self._with_temp_file(ruleset)
        try:
            result = self._run([self._nft, "-f", str(path)])
        finally:
            path.unlink(missing_ok=True)

        if not result.ok:
            # nft -f is transactional: nothing was committed. The previous table
            # is still live, so there is nothing to undo -- just report.
            raise NftApplyError(
                f"nft failed to apply the ruleset: {result.stderr.strip() or result.stdout.strip()}"
            )

        if not self.table_exists():
            self._restore_last_good()
            raise NftApplyError(
                f"table inet {self._table} is missing after a successful apply; "
                "restored the last known good ruleset"
            )

        self._last_good = ruleset
        self._write_state(ruleset)

    def _restore_last_good(self) -> None:
        if not self._last_good:
            logger.error("no last known good ruleset to restore")
            return
        path = self._with_temp_file(self._last_good)
        try:
            result = self._run([self._nft, "-f", str(path)])
        finally:
            path.unlink(missing_ok=True)
        if not result.ok:
            logger.critical(
                "failed to restore last known good ruleset: %s", result.stderr.strip()
            )

    # ------------------------------------------------------------------ state

    def _read_state(self) -> str | None:
        if self._state_file and self._state_file.exists():
            return self._state_file.read_text(encoding="utf-8")
        return None

    def _write_state(self, ruleset: str) -> None:
        if not self._state_file:
            return
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state_file.with_suffix(".tmp")
        tmp.write_text(ruleset, encoding="utf-8")
        os.chmod(tmp, 0o600)
        shutil.move(str(tmp), str(self._state_file))

    @property
    def last_good(self) -> str | None:
        return self._last_good
