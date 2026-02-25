from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustproof import generate, verify  # noqa: E402


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


def test_generate_and_verify_happy_path() -> None:
    claims = _load_allow_claims()
    private_pem, public_pem = _generate_pem_keypair()

    token = generate(claims, private_pem)
    result = verify(token, public_pem)

    assert result["ok"] is True
    assert result["errors"] == []
    assert isinstance(result.get("claims"), dict)


def test_invalid_signature() -> None:
    claims = _load_allow_claims()
    private_pem_a, _public_pem_a = _generate_pem_keypair()
    _private_pem_b, public_pem_b = _generate_pem_keypair()

    token = generate(claims, private_pem_a)
    result = verify(token, public_pem_b)

    assert result["ok"] is False
    assert any(err.get("code") == "INVALID_SIGNATURE" for err in result["errors"])
