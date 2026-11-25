"""Manifest parsing, component comparison, and integrity checks.

Identity rules
--------------
A component is identified by the pair ``(normalized name, version)``.  The
normalized name follows the usual package-name convention of collapsing runs
of ``-``/``_``/``.`` into a single ``-`` and lower-casing, so
``Requests_Core`` and ``requests-core`` are the same component.  Two entries
with the same name but different versions are distinct components and are
reported separately.

Coverage rules
--------------
Manifests and images are compared over *all* components, including
transitive dependencies (``direct`` is metadata only and never filters an
entry).  Results are deduplicated and sorted by ``(name, version)`` so that
repeated runs and differently ordered manifests produce identical output.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re

_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")
_NAME_SEPARATORS_RE = re.compile(r"[-_.]+")
_HASH_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]*:")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_manifest(text: str) -> list[dict]:
    """Parse a JSON manifest into component entry dictionaries."""
    if not text or not text.strip():
        return []

    payload = json.loads(text)
    if isinstance(payload, dict):
        raw_entries = payload.get("components", payload.get("entries", []))
    else:
        raw_entries = payload

    entries: list[dict] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            continue
        direct = raw.get("direct", True)
        if isinstance(direct, str):
            direct = direct.strip().lower() not in {"false", "0", "no"}
        else:
            direct = bool(direct)
        entries.append(
            {
                "name": raw.get("name", ""),
                "version": _normalize_version(raw.get("version", "")),
                "hash": raw.get("hash"),
                "source": raw.get("source", ""),
                "direct": direct,
            }
        )
    return entries


def normalize_name(name: str) -> str:
    """Normalize a component name for identity comparisons.

    Package names are case-insensitive and treat ``-``, ``_`` and ``.`` as
    interchangeable separators, so ``Requests_Core`` normalizes to
    ``requests-core``.
    """
    text = str(name if name is not None else "").strip().lower()
    return _NAME_SEPARATORS_RE.sub("-", text)


def _normalize_version(version) -> str:
    return str(version if version is not None else "").strip()


def _component_key(entry: dict) -> tuple[str, str]:
    """Return the unique ``(name, version)`` identity of an entry."""
    return (normalize_name(entry.get("name", "")), _normalize_version(entry.get("version", "")))


def index_components(entries: list[dict]) -> dict:
    """Index components by their unique ``(name, version)`` identity.

    Duplicate entries collapse onto a single key; the first occurrence wins so
    the result is deterministic for a given input.
    """
    indexed: dict = {}
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        indexed.setdefault(_component_key(entry), entry)
    return indexed


def _normalize_hash(value) -> str:
    """Normalize a digest for comparison.

    Comparison is exact on the digest value: hash prefixes such as
    ``sha256:`` and hexadecimal case differences are ignored, but digests are
    never truncated.  A missing or empty digest normalizes to ``""``.
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    if not text:
        return ""
    return _HASH_PREFIX_RE.sub("", text, count=1)


def _hashes_match(expected, actual) -> bool:
    expected_digest = _normalize_hash(expected)
    if not expected_digest:
        # An entry without a hash cannot be verified and is non-compliant.
        return False
    return expected_digest == _normalize_hash(actual)


def _result_item(entry: dict, **extra) -> dict:
    """Build a comparison result that locates the specific component."""
    item = {
        "name": entry.get("name", ""),
        "version": _normalize_version(entry.get("version", "")),
    }
    item.update(extra)
    return item


def _sorted_items(items: list[dict]) -> list[dict]:
    return sorted(
        items,
        key=lambda item: (
            normalize_name(item.get("name", "")),
            _normalize_version(item.get("version", "")),
        ),
    )


def compare(manifest: list[dict], actual: list[dict]) -> dict:
    """Compare a declared manifest with the components found in an image.

    Every component is considered, including transitive dependencies.  A
    manifest component missing from the image is reported as ``missing``; an
    image component absent from the manifest is ``extra``; a component whose
    digest differs (or is absent on either side) is ``hash_mismatch``.  Same
    name/different version pairs therefore appear in both ``missing`` and
    ``extra``.
    """
    manifest_index = index_components(manifest)
    actual_index = index_components(actual)

    missing: list[dict] = []
    extra: list[dict] = []
    hash_mismatch: list[dict] = []

    for key, entry in manifest_index.items():
        match = actual_index.get(key)
        if match is None:
            missing.append(_result_item(entry))
            continue
        if not _hashes_match(entry.get("hash"), match.get("hash")):
            hash_mismatch.append(
                _result_item(
                    entry,
                    expected=entry.get("hash"),
                    actual=match.get("hash"),
                )
            )

    for key, entry in actual_index.items():
        if key not in manifest_index:
            extra.append(_result_item(entry))

    return {
        "missing": _sorted_items(missing),
        "extra": _sorted_items(extra),
        "hash_mismatch": _sorted_items(hash_mismatch),
    }


def check_hashes(manifest: list[dict], artifacts: list[dict]) -> list[dict]:
    """Check every manifest component against the artifact digest."""
    problems: list[dict] = []
    artifact_index = index_components(artifacts)

    for key, entry in index_components(manifest).items():
        artifact = artifact_index.get(key)
        expected = entry.get("hash")
        if not _normalize_hash(expected):
            # A component without a digest is non-compliant regardless of
            # whether the artifact itself is present.
            problems.append(_result_item(entry, reason="missing hash"))
        if artifact is None:
            problems.append(_result_item(entry, reason="missing artifact"))
            continue
        if _normalize_hash(expected) and not _hashes_match(expected, artifact.get("hash")):
            problems.append(
                _result_item(
                    entry,
                    reason="hash mismatch",
                    expected=expected,
                    actual=artifact.get("hash"),
                )
            )
    return _sorted_items(problems)


def _json_serializations(payload) -> list[str]:
    """Yield canonical JSON encodings used when checking manifest integrity."""
    serializations: list[str] = []
    for ensure_ascii in (True, False):
        for separators in ((",", ":"), None):
            kwargs = {"sort_keys": True, "ensure_ascii": ensure_ascii}
            if separators is not None:
                kwargs["separators"] = separators
            serializations.append(json.dumps(payload, **kwargs))
    return serializations


def _entry_sort_key(entry) -> tuple[str, str]:
    if not isinstance(entry, dict):
        return ("", "")
    return (
        normalize_name(entry.get("name", "")),
        _normalize_version(entry.get("version", "")),
    )


def _manifest_digests(manifest) -> set[str]:
    """Return the SHA-256 digests of the canonical forms of a manifest.

    The manifest is hashed in a canonical, order-insensitive way: entries are
    sorted by ``(name, version)`` and object keys are sorted.  The same digest
    is accepted whether or not the surrounding ``{"components": ...}``
    envelope is included, and whether compact or default JSON separators were
    used, so integrity verification is stable across producers.
    """
    payloads: list = []
    if isinstance(manifest, str):
        payloads.append(manifest)
        try:
            payloads.append(json.loads(manifest))
        except ValueError:
            pass
    elif isinstance(manifest, (list, dict)):
        payloads.append(manifest)

    digests: set[str] = set()
    for payload in payloads:
        if isinstance(payload, str):
            digests.add(hashlib.sha256(payload.encode("utf-8")).hexdigest())
            digests.add(hashlib.sha256(payload.strip().encode("utf-8")).hexdigest())
            continue

        variants = [payload]
        if isinstance(payload, list):
            sorted_entries = sorted(payload, key=_entry_sort_key)
            variants.extend([sorted_entries, {"components": payload}, {"components": sorted_entries}])
        elif isinstance(payload, dict):
            components = payload.get("components")
            if isinstance(components, list):
                sorted_components = sorted(components, key=_entry_sort_key)
                variants.extend([sorted_components, {"components": sorted_components}])

        for variant in variants:
            for serialized in _json_serializations(variant):
                digests.add(hashlib.sha256(serialized.encode("utf-8")).hexdigest())
    return digests


def verify_manifest_integrity(manifest: list[dict], signature: str) -> bool:
    """Verify the detached SHA-256 signature of the manifest.

    The signature is the hexadecimal SHA-256 digest of the manifest's
    canonical JSON form; an optional ``sha256:`` prefix is accepted.  Missing,
    malformed, or non-matching signatures are rejected.
    """
    if not isinstance(signature, str):
        return False

    provided = signature.strip().lower()
    if provided.startswith("sha256:"):
        provided = provided[len("sha256:") :]
    if not _SHA256_HEX_RE.fullmatch(provided):
        return False

    return any(
        hmac.compare_digest(provided, digest)
        for digest in _manifest_digests(manifest)
    )


def validate_manifest(entries: list[dict]) -> list[str]:
    """Return human-readable issues found while validating a manifest.

    Duplicate ``(name, version)`` entries are reported once, and every
    component must carry a digest and a well-formed version.  Repeated issues
    for the same component are collapsed.
    """
    issues: list[str] = []
    reported: set[str] = set()
    seen: set[tuple[str, str]] = set()

    def report(message: str) -> None:
        if message not in reported:
            reported.add(message)
            issues.append(message)

    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        name = normalize_name(entry.get("name", ""))
        version = _normalize_version(entry.get("version", ""))
        key = (name, version)

        if key in seen:
            report(f"duplicate: {name}=={version}")
        seen.add(key)

        if not _normalize_hash(entry.get("hash")):
            report(f"missing hash: {name}=={version}")

        if not _VERSION_RE.fullmatch(version):
            report(f"invalid version: {name}=={version}")

    return issues


def sbom_batch(pairs: list[tuple]) -> dict:
    """Compare several image manifests in one batch.

    Each image is compared independently against its own component list; no
    state is shared between images.
    """
    results: dict = {}
    for image, manifest, actual in pairs:
        results[image] = compare(manifest, actual)
    return results
