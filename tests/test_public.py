import json

from sbom.verify import (
    compare,
    normalize_name,
    parse_manifest,
    sbom_batch,
)

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64


def _entry(name, version, digest=HASH_A, source="pypi", direct=True):
    return {
        "name": name,
        "version": version,
        "hash": digest,
        "source": source,
        "direct": direct,
    }


def test_parse_manifest_entries():
    text = json.dumps(
        [
            {
                "name": "Requests_Core",
                "version": "2.31.0",
                "hash": HASH_A,
                "source": "pypi",
                "direct": True,
            },
            {
                "name": "urllib3",
                "version": "2.0.7",
                "hash": HASH_B,
                "source": "pypi",
                "direct": False,
            },
        ]
    )

    entries = parse_manifest(text)

    assert len(entries) == 2
    assert entries[0]["name"] == "Requests_Core"
    assert entries[0]["version"] == "2.31.0"
    assert entries[0]["hash"] == HASH_A
    assert entries[0]["source"] == "pypi"
    assert entries[1]["direct"] is False
    assert normalize_name(entries[0]["name"]) == "requests-core"


def test_identical_manifests_have_no_differences():
    manifest = [
        _entry("lib-core", "1.0.0"),
        _entry("lib-core", "2.0.0"),
    ]
    actual = [
        _entry("lib-core", "1.0.0"),
        _entry("lib-core", "2.0.0"),
    ]

    diff = compare(manifest, actual)

    assert diff == {"missing": [], "extra": [], "hash_mismatch": []}


def test_missing_component_reported():
    manifest = [
        _entry("lib-a", "1.0.0"),
        _entry("lib-b", "2.0.0"),
    ]
    actual = [_entry("lib-a", "1.0.0")]

    diff = compare(manifest, actual)

    assert [item.get("name") for item in diff["missing"]] == ["lib-b"]


def test_extra_component_reported():
    manifest = [_entry("lib-a", "1.0.0")]
    actual = [
        _entry("lib-a", "1.0.0"),
        _entry("lib-c", "3.0.0"),
    ]

    diff = compare(manifest, actual)

    assert [item.get("name") for item in diff["extra"]] == ["lib-c"]


def test_batch_two_images_are_independent():
    pairs = [
        ("image-a", [_entry("lib-a", "1.0.0")], [_entry("lib-a", "1.0.0")]),
        ("image-b", [_entry("lib-b", "2.0.0")], [_entry("lib-b", "2.0.0")]),
    ]

    results = sbom_batch(pairs)
    empty = {"missing": [], "extra": [], "hash_mismatch": []}

    assert results["image-a"] == empty
    assert results["image-b"] == empty