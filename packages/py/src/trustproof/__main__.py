from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

from .verify import verify as verify_token


def _decode_base64url_to_utf8(value: str) -> str:
    normalized = value.replace("-", "+").replace("_", "/")
    padding = "=" * ((4 - (len(normalized) % 4)) % 4)
    return base64.b64decode(f"{normalized}{padding}").decode("utf-8")


def _decode_jwt_payload_untrusted(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Token must be compact JWS (three dot-separated segments).")

    payload_json = _decode_base64url_to_utf8(parts[1])
    payload = json.loads(payload_json)
    if not isinstance(payload, dict):
        raise ValueError("JWT payload must decode to a JSON object.")
    return payload


def _load_public_key_pem(pubkey_arg: str) -> str:
    if "BEGIN PUBLIC KEY" in pubkey_arg:
        return pubkey_arg

    path = Path(pubkey_arg)
    if path.exists() and path.is_file():
        return path.read_text(encoding="utf-8")

    return _decode_base64url_to_utf8(pubkey_arg)


def _format_verify_summary(claims: Any) -> str:
    if not isinstance(claims, dict):
        return "OK"

    subject = claims.get("subject")
    result = claims.get("result")

    subject_id = subject.get("id") if isinstance(subject, dict) else "unknown"
    action = claims.get("action", "unknown")
    decision = result.get("decision") if isinstance(result, dict) else "unknown"

    return "\n".join(
        [
            "OK",
            f"subject.id={subject_id}",
            f"action={action}",
            f"decision={decision}",
        ]
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trustproof", description="TrustProof CLI v0")
    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser("verify", help="Verify a signed TrustProof JWT")
    verify_parser.add_argument("jwt", help="JWT token")
    verify_parser.add_argument("--pubkey", required=True, help="Public key PEM, base64 PEM, or path")
    verify_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    inspect_parser = subparsers.add_parser("inspect", help="Inspect JWT payload without verification")
    inspect_parser.add_argument("jwt", help="JWT token")
    inspect_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "inspect":
        try:
            payload = _decode_jwt_payload_untrusted(args.jwt)
        except Exception as exc:  # noqa: BLE001
            if args.json:
                print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
            else:
                print(f"FAIL\n{exc}", file=sys.stderr)
            return 1

        if args.json:
            print(json.dumps({"ok": True, "payload": payload}, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "verify":
        try:
            public_key_pem = _load_public_key_pem(args.pubkey)
        except Exception as exc:  # noqa: BLE001
            if args.json:
                print(
                    json.dumps(
                        {
                            "ok": False,
                            "errors": [{"code": "PUBKEY_LOAD_ERROR", "message": str(exc)}],
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                )
            else:
                print(f"FAIL\nPUBKEY_LOAD_ERROR: {exc}", file=sys.stderr)
            return 1

        result = verify_token(args.jwt, public_key_pem)

        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif result.get("ok"):
            print(_format_verify_summary(result.get("claims")))
        else:
            lines = ["FAIL"]
            for error in result.get("errors", []):
                lines.append(f"{error.get('code')}: {error.get('message')}")
            print("\n".join(lines), file=sys.stderr)

        return 0 if result.get("ok") else 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
