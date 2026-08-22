from __future__ import annotations

import pytest

from ccm_audit_export.canonical import (
    CanonicalizationError,
    canonical_json,
    require_digest,
    sha256_bytes,
    sha256_digest,
    stable_identifier,
)


def test_canonical_json_sorts_and_hashes_deterministically() -> None:
    assert canonical_json({"b": 2, "a": [True, None]}) == b'{"a":[true,null],"b":2}'
    assert sha256_digest({"a": 1, "b": 2}) == sha256_digest({"b": 2, "a": 1})
    assert sha256_bytes(b"evidence") == (
        "sha256:ee8250fb76e094b34b471f13a73dbbe51d1ae142e9df59d7c0d31ec20f0a0a8e"
    )


def test_canonical_rejects_unsafe_values_and_identifiers() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json(1.5)
    with pytest.raises(CanonicalizationError):
        canonical_json(float("nan"))
    with pytest.raises(CanonicalizationError):
        canonical_json(9_007_199_254_740_992)
    with pytest.raises(CanonicalizationError):
        canonical_json({1: "non-string key"})
    with pytest.raises(CanonicalizationError):
        canonical_json("\ud800")
    with pytest.raises(CanonicalizationError):
        require_digest("sha256:UPPER")
    with pytest.raises(CanonicalizationError):
        stable_identifier("Bad", {"value": 1})
    with pytest.raises(CanonicalizationError):
        stable_identifier("valid", {"value": 1}, length=5)
