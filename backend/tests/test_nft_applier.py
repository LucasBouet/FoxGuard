"""Tests for the nft applier.

A fake command runner stands in for ``nft``, so these run unprivileged on any
machine -- including one where nftables is not installed at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from foxguard.nftables import (
    CommandResult,
    NftApplier,
    NftApplyError,
    NftSafetyError,
    NftValidationError,
)

VALID = 'table inet foxguard\ndelete table inet foxguard\n\ntable inet foxguard {\n}\n'


class FakeRunner:
    """Records every invocation, including the file contents nft would read."""

    def __init__(self, results: dict[str, CommandResult] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.payloads: list[str | None] = []
        self.results = results or {}
        self.missing_paths: list[str] = []

    def run(self, argv, *, timeout: float = 30.0) -> CommandResult:
        argv = list(argv)
        self.calls.append(argv)

        payload = None
        for token in argv:
            if token.endswith(".nft"):
                path = Path(token)
                if path.exists():
                    payload = path.read_text(encoding="utf-8")
                else:
                    self.missing_paths.append(token)
        self.payloads.append(payload)

        return self.results.get(self.kind(argv), CommandResult(0, "", ""))

    @staticmethod
    def kind(argv: list[str]) -> str:
        if "-c" in argv:
            return "check"
        if "list" in argv:
            return "list"
        if "-f" in argv:
            return "apply"
        return "other"

    @property
    def kinds(self) -> list[str]:
        return [self.kind(call) for call in self.calls]


# --------------------------------------------------------------------------- #
# guards
# --------------------------------------------------------------------------- #


def test_guard_rejects_a_ruleset_that_flushes_everything():
    applier = NftApplier(runner=FakeRunner())
    with pytest.raises(NftSafetyError, match="flush ruleset"):
        applier.guard("flush ruleset\ntable inet foxguard {\n}\n")


def test_guard_rejects_deleting_a_foreign_table():
    applier = NftApplier(runner=FakeRunner())
    hostile = "delete table inet filter\ntable inet foxguard {\n}\n"
    with pytest.raises(NftSafetyError, match="foreign table"):
        applier.guard(hostile)


def test_guard_rejects_a_ruleset_for_another_table():
    applier = NftApplier(runner=FakeRunner(), table_name="foxguard")
    with pytest.raises(NftSafetyError, match="does not declare"):
        applier.guard("table inet somethingelse {\n}\n")


def test_guard_ignores_forbidden_words_inside_comments():
    applier = NftApplier(runner=FakeRunner())
    applier.guard(VALID.replace("{\n}", '{\n  chain c { accept comment "flush ruleset" }\n}'))


# --------------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------------- #


def test_validate_runs_check_only_and_passes_the_exact_bytes():
    runner = FakeRunner()
    NftApplier(runner=runner).validate(VALID)

    assert runner.kinds == ["check"]
    assert runner.calls[0][:3] == ["nft", "-c", "-f"]
    assert runner.payloads[0] == VALID


def test_validate_raises_when_nft_rejects_the_ruleset():
    runner = FakeRunner({"check": CommandResult(1, "", "syntax error, unexpected junk")})
    with pytest.raises(NftValidationError, match="syntax error"):
        NftApplier(runner=runner).validate(VALID)


def test_validate_leaves_no_temp_file_behind():
    runner = FakeRunner()
    NftApplier(runner=runner).validate(VALID)
    path = Path(runner.calls[0][-1])
    assert not path.exists()


# --------------------------------------------------------------------------- #
# apply
# --------------------------------------------------------------------------- #


def test_apply_always_checks_first():
    runner = FakeRunner()
    NftApplier(runner=runner).apply(VALID)
    assert runner.kinds[0] == "check"
    assert "apply" in runner.kinds


def test_apply_is_skipped_entirely_when_the_check_fails():
    """The single most important property: never push an unvalidated ruleset."""
    runner = FakeRunner({"check": CommandResult(1, "", "bad rule")})
    with pytest.raises(NftValidationError):
        NftApplier(runner=runner).apply(VALID)
    assert runner.kinds == ["check"]


def test_apply_checks_and_applies_identical_bytes():
    runner = FakeRunner()
    NftApplier(runner=runner).apply(VALID)
    check_payload = runner.payloads[runner.kinds.index("check")]
    apply_payload = runner.payloads[runner.kinds.index("apply")]
    assert check_payload == apply_payload == VALID


def test_apply_reports_nft_failure():
    runner = FakeRunner({"apply": CommandResult(1, "", "Operation not permitted")})
    with pytest.raises(NftApplyError, match="Operation not permitted"):
        NftApplier(runner=runner).apply(VALID)


def test_apply_restores_the_last_good_ruleset_when_the_table_vanishes():
    runner = FakeRunner()
    applier = NftApplier(runner=runner)
    applier.apply(VALID)  # establishes a known good baseline

    newer = VALID.replace("}", '  chain c { }\n}')
    runner.results["list"] = CommandResult(1, "", "No such file or directory")
    with pytest.raises(NftApplyError, match="restored"):
        applier.apply(newer)

    # The last command must be a re-apply of the previous known good ruleset.
    assert runner.kinds[-1] == "apply"
    assert runner.payloads[-1] == VALID


def test_last_good_is_persisted_across_instances(tmp_path):
    state = tmp_path / "state" / "last-good.nft"
    NftApplier(runner=FakeRunner(), state_file=state).apply(VALID)
    assert state.read_text(encoding="utf-8") == VALID

    reloaded = NftApplier(runner=FakeRunner(), state_file=state)
    assert reloaded.last_good == VALID


def test_no_temp_file_survives_an_apply():
    runner = FakeRunner()
    NftApplier(runner=runner).apply(VALID)
    for call in runner.calls:
        for token in call:
            if token.endswith(".nft"):
                assert not Path(token).exists()


def test_subprocess_runner_reports_a_missing_binary():
    from foxguard.nftables import NftError, SubprocessRunner

    with pytest.raises(NftError, match="not found"):
        SubprocessRunner().run(["foxguard-no-such-binary-42"])


def test_a_custom_nft_path_is_honoured():
    runner = FakeRunner()
    NftApplier(runner=runner, nft_path="/usr/sbin/nft").validate(VALID)
    assert runner.calls[0][0] == "/usr/sbin/nft"
