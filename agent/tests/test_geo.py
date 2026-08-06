"""Building the country map, without the internet.

Every test here uses a tiny synthetic dataset in the real DB-IP shape, so the
suite never touches db-ip.com. What that shape costs at real scale is measured
separately and recorded in :mod:`foxguard_agent.geo`; what matters here is that
the conversion, the caching and the failure paths are right.
"""

from __future__ import annotations

import gzip

import pytest

from foxguard_agent.geo import ATTRIBUTION, GeoBuilder, GeoError, dataset_url

# Inclusive ranges, exactly as DB-IP publishes them. 1.0.0.0-1.0.0.255 is one
# clean /24; 2.0.0.0-2.0.1.255 needs two prefixes, which is the case that makes
# the entry count roughly double at real scale.
DATASET = """\
1.0.0.0,1.0.0.255,FR
2.0.0.0,2.0.1.255,FR
3.0.0.0,3.0.0.255,CH
4.0.0.0,4.0.0.255,CN
2001:db8::,2001:db8::ffff,FR
"""


@pytest.fixture
def dataset(tmp_path):
    path = tmp_path / "dbip.csv"
    path.write_text(DATASET)
    return path


@pytest.fixture
def builder(tmp_path, dataset):
    return GeoBuilder(dataset, tmp_path / "maps" / "geo.map")


def _entries(builder) -> list[str]:
    return [
        line
        for line in builder.map_path.read_text().splitlines()
        if line and not line.startswith("#")
    ]


def test_a_range_becomes_the_prefixes_that_cover_it(builder):
    assert builder.build(["FR"]) == "built"
    assert _entries(builder) == [
        "1.0.0.0/24 FR",
        "2.0.0.0/23 FR",
        "2001:db8::/112 FR",
    ]


def test_only_the_countries_asked_for_are_written(builder):
    """The whole reason this is built here and not shipped: the full dataset is
    1.37 million prefixes and 367 MiB of HAProxy memory."""
    builder.build(["CH"])
    assert _entries(builder) == ["3.0.0.0/24 CH"]


def test_codes_are_normalised_before_anything_is_compared(builder):
    assert builder.build([" fr ", "CH"]) == "built"
    assert builder.current_countries() == ("CH", "FR")
    # And the normalised form is what makes the next call a no-op.
    assert builder.build(["ch", "FR"]) == "unchanged"


def test_rebuilding_the_same_set_does_nothing(builder):
    builder.build(["FR", "CH"])
    assert builder.build(["CH", "FR"]) == "unchanged"


def test_changing_the_set_rebuilds(builder):
    builder.build(["FR"])
    assert builder.build(["CN"]) == "built"
    assert _entries(builder) == ["4.0.0.0/24 CN"]


def test_asking_for_nothing_removes_the_map(builder):
    """Nothing references it, and stale prefixes on disk invite the wrong question."""
    builder.build(["FR"])
    assert builder.build([]) == "unchanged"
    assert not builder.map_path.exists()
    assert builder.current_countries() is None


def test_the_licence_is_carried_into_the_file(builder):
    builder.build(["FR"])
    assert ATTRIBUTION in builder.map_path.read_text()


def test_a_gzipped_dataset_is_read_as_it_was_downloaded(tmp_path):
    path = tmp_path / "dbip.csv.gz"
    with gzip.open(path, "wt") as handle:
        handle.write(DATASET)
    builder = GeoBuilder(path, tmp_path / "geo.map")
    assert builder.build(["CH"]) == "built"
    assert _entries(builder) == ["3.0.0.0/24 CH"]


def test_a_malformed_row_costs_only_itself(tmp_path):
    path = tmp_path / "dbip.csv"
    path.write_text("garbage\n1.0.0.0,not-an-address,FR\n3.0.0.0,3.0.0.255,CH\n")
    builder = GeoBuilder(path, tmp_path / "geo.map")
    builder.build(["FR", "CH"])
    assert _entries(builder) == ["3.0.0.0/24 CH"]


def test_a_code_that_is_not_a_country_is_refused(builder):
    with pytest.raises(GeoError, match="ISO 3166-1"):
        builder.build(["FRANCE"])


# --------------------------------------------------------------------------- #
# no dataset: the path that must not take the whole proxy down
# --------------------------------------------------------------------------- #


def test_no_dataset_still_writes_a_map(tmp_path):
    """``haproxy -c`` resolves ``-f`` at parse time, so a *missing* map fails the
    entire configuration -- every unrelated service with it. An empty one only
    fails the filter that needed it."""
    builder = GeoBuilder(tmp_path / "absent.csv", tmp_path / "geo.map")
    assert builder.build(["FR"]) == "empty"
    assert builder.map_path.exists()
    assert _entries(builder) == []


def test_the_empty_map_says_what_it_means(tmp_path):
    builder = GeoBuilder(tmp_path / "absent.csv", tmp_path / "geo.map")
    builder.build(["FR"])
    body = builder.map_path.read_text()
    assert "NO DATASET" in body
    assert "refuses everyone" in body and "blocks nobody" in body
    assert "geo-refresh" in body


def test_an_empty_dataset_file_counts_as_no_dataset(tmp_path):
    (tmp_path / "dbip.csv").write_text("")
    builder = GeoBuilder(tmp_path / "dbip.csv", tmp_path / "geo.map")
    assert builder.build(["FR"]) == "empty"


def test_a_map_built_empty_is_rebuilt_once_the_dataset_arrives(tmp_path):
    """The trap an empty build sets for itself.

    The country set has not changed, so a stamp written by the empty build would
    make the next pass answer "unchanged" and leave the filter dead for as long
    as nobody edited it. An empty build therefore writes no stamp at all.
    """
    path = tmp_path / "dbip.csv"
    builder = GeoBuilder(path, tmp_path / "geo.map")
    assert builder.build(["FR"]) == "empty"
    assert _entries(builder) == []
    assert builder.current_countries() is None

    path.write_text(DATASET)
    assert builder.build(["FR"]) == "built"
    assert _entries(builder)
    assert builder.current_countries() == ("FR",)


def test_an_empty_build_repeats_until_it_can_succeed(tmp_path):
    """And it must stay repeatable rather than settling into "unchanged"."""
    builder = GeoBuilder(tmp_path / "absent.csv", tmp_path / "geo.map")
    assert builder.build(["FR"]) == "empty"
    assert builder.build(["FR"]) == "empty"


# --------------------------------------------------------------------------- #
# where the dataset comes from
# --------------------------------------------------------------------------- #


def test_the_url_follows_the_calendar_rather_than_being_pinned():
    from datetime import UTC, datetime

    url = dataset_url(datetime(2026, 3, 9, tzinfo=UTC))
    assert url.endswith("dbip-country-lite-2026-03.csv.gz")
    assert url.startswith("https://")


def test_a_download_that_fails_leaves_the_previous_dataset_alone(tmp_path):
    """The reason refreshing is a command and not part of a reconcile."""
    from foxguard_agent.geo import refresh_dataset

    dataset = tmp_path / "dbip.csv.gz"
    dataset.write_bytes(b"previous")
    with pytest.raises(GeoError):
        refresh_dataset(dataset, url="http://127.0.0.1:1/never", timeout=1.0)
    assert dataset.read_bytes() == b"previous"
    # And no half-written temporary file is left behind to be mistaken for one.
    assert [p.name for p in tmp_path.iterdir()] == ["dbip.csv.gz"]
