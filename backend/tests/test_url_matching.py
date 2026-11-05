import json
from pathlib import Path

import pytest

from url_match import (
    candidate_filter,
    could_match,
    matches,
    normalize,
    public_suffix,
    registrable_domain,
)

VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[2] / "testdata/vectors/url-matching.json"
    ).read_text(encoding="utf-8")
)


def test_the_vectors_cover_enough_cases() -> None:
    assert len(VECTORS["normalize"]) + len(VECTORS["match"]) >= 150
    assert any(case["subdomains"] for case in VECTORS["match"])


@pytest.mark.parametrize(
    "case", VECTORS["normalize"], ids=[repr(c["input"]) for c in VECTORS["normalize"]]
)
def test_normalize(case: dict) -> None:
    origin = normalize(case["input"])
    assert (None if origin is None else str(origin)) == case["origin"], case.get("note")


@pytest.mark.parametrize(
    "case",
    VECTORS["match"],
    ids=[f"{c['page']!r} {c['saved']!r} {c['subdomains']}" for c in VECTORS["match"]],
)
def test_match(case: dict) -> None:
    assert (
        matches(case["page"], case["saved"], subdomains=case["subdomains"])
        is case["match"]
    ), case.get("note")


def test_exact_matches_never_depend_on_the_subdomain_option() -> None:
    for case in VECTORS["match"]:
        if case["match"] and not case["subdomains"]:
            assert matches(case["page"], case["saved"], subdomains=True)


@pytest.mark.parametrize(
    ("host", "suffix", "registrable"),
    [
        ("www.example.co.uk", "co.uk", "example.co.uk"),
        ("co.uk", "co.uk", None),
        ("moth.github.io", "github.io", "moth.github.io"),
        ("github.io", "github.io", None),
        ("a.b.example.com", "com", "example.com"),
        ("localhost", "localhost", None),
        ("city.kawasaki.jp", "kawasaki.jp", "city.kawasaki.jp"),
        ("x.b.kawasaki.jp", "b.kawasaki.jp", "x.b.kawasaki.jp"),
        ("xn--r8jz45g.xn--zckzah", "xn--zckzah", "xn--r8jz45g.xn--zckzah"),
    ],
)
def test_public_suffix_list(host: str, suffix: str, registrable: str | None) -> None:
    assert public_suffix(host) == suffix
    assert registrable_domain(host) == registrable


@pytest.mark.parametrize("value", [None, 42, b"github.com", ["github.com"]])
def test_non_strings_have_no_origin(value: object) -> None:
    assert normalize(value) is None


def test_overlong_urls_have_no_origin() -> None:
    assert normalize("https://github.com/" + "a" * 3000) is None


def test_the_listing_shortcut_never_drops_a_match() -> None:
    for case in VECTORS["match"]:
        page = normalize(case["page"])
        if page is None or not case["match"]:
            continue
        needle = candidate_filter(page, subdomains=case["subdomains"])
        assert could_match(needle, case["saved"]), case
