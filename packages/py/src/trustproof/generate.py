from __future__ import annotations

import copy
import re
import time
from typing import Any

import jwt

HEX_64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX_64_RE.fullmatch(value))


def _validate_for_generate(claims: dict[str, Any]) -> None:
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti.strip():
        raise ValueError("Invalid claims: jti must be a non-empty string.")

    chain = claims.get("chain")
    if not isinstance(chain, dict):
        raise ValueError("Invalid claims: chain must be an object.")

    prev_hash = chain.get("prev_hash")
    entry_hash = chain.get("entry_hash")
    if not _is_hex64(prev_hash):
        raise ValueError("Invalid claims: chain.prev_hash must be a 64-char hex string.")
    if not _is_hex64(entry_hash):
        raise ValueError("Invalid claims: chain.entry_hash must be a 64-char hex string.")


def generate(claims: dict[str, Any], private_key_pem: str, kid: str | None = None) -> str:
    if not isinstance(claims, dict):
        raise ValueError("Claims must be a dict.")

    payload = copy.deepcopy(claims)
    _validate_for_generate(payload)
    payload.setdefault("iat", int(time.time()))

    headers: dict[str, Any] = {"alg": "EdDSA", "typ": "JWT"}
    if kid is not None:
        headers["kid"] = kid

    token = jwt.encode(payload, private_key_pem, algorithm="EdDSA", headers=headers)
    if not isinstance(token, str):
        raise ValueError("JWT encode failed to produce a compact token.")
    return token
