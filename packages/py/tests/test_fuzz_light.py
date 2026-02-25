from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustproof import generate, verify, verify_chain  # noqa: E402


def _load_allow_claims() -> dict:
    repo_root = Path(__file__).resolve().parents[3]
    allow_path = repo_root / "spec" / "examples" / "allow.json"
    return json.loads(allow_path.read_text(encoding="utf-8"))


def _generate_pem_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def _large_claims(base_claims: dict) -> dict:
    claims = json.loads(json.dumps(base_claims))
    claims["subject"]["id"] = "a" * 10_000
    claims["resource"]["id"] = "x" * 20_000
    claims["policy"]["scopes"] = [f"scope:{i}" for i in range(200)]
    claims["result"]["reason_codes"] = [f"reason_{i}" for i in range(200)]
    return claims


def test_verify_malformed_tokens_do_not_crash() -> None:
    claims = _load_allow_claims()
    private_pem, public_pem = _generate_pem_keypair()
    valid_token = generate(claims, private_pem)

    malformed_tokens = [
        "",
        "abc",
        "a.b",
        "a.b.c",
        "....",
        ".".join(valid_token.split(".")[:2]) + ".",
        "a.b.c$",
    ]

    for token in malformed_tokens:
        result = verify(token, public_pem)
        assert isinstance(result, dict)
        assert result.get("ok") is False
        assert isinstance(result.get("errors"), list)
        assert len(result["errors"]) >= 1
        assert "code" in result["errors"][0]


def test_verify_chain_empty_returns_ok_true() -> None:
    _private_pem, public_pem = _generate_pem_keypair()
    result = verify_chain([], public_pem)
    assert result["ok"] is True
    assert result["errors"] == []


def test_verify_chain_invalid_token_returns_structured_error() -> None:
    _private_pem, public_pem = _generate_pem_keypair()
    result = verify_chain(["a.b.c"], public_pem)
    assert result["ok"] is False
    assert result["errors"][0]["code"] == "INVALID_PROOF"
    assert result["errors"][0]["index"] == 0


def test_verify_chain_valid_then_malformed_fails_without_crash() -> None:
    claims = _load_allow_claims()
    private_pem, public_pem = _generate_pem_keypair()
    token = generate(claims, private_pem)

    result = verify_chain([token, "a.b.c"], public_pem)
    assert result["ok"] is False
    assert result["errors"][0]["code"] == "INVALID_PROOF"
    assert result["errors"][0]["index"] == 1


def test_large_claims_verify_or_fail_gracefully() -> None:
    claims = _large_claims(_load_allow_claims())
    private_pem, public_pem = _generate_pem_keypair()

    token = generate(claims, private_pem)
    result = verify(token, public_pem)

    assert isinstance(result, dict)
    assert "ok" in result
    assert isinstance(result.get("errors"), list)
    if result["ok"] is True:
        assert result["errors"] == []
    else:
        assert len(result["errors"]) > 0
