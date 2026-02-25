from __future__ import annotations

import base64
import json
import sys

from trustproof.__main__ import main


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def test_main_inspect_with_argv(monkeypatch, capsys) -> None:
    header = {"alg": "none", "typ": "JWT"}
    payload = {"subject": {"id": "user_test"}, "action": "payout.initiate"}

    token = (
        f"{_b64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))}."
        f"{_b64url(json.dumps(payload, separators=(',', ':')).encode('utf-8'))}."
        "sig"
    )

    monkeypatch.setattr(sys, "argv", ["trustproof", "inspect", token])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert '"action": "payout.initiate"' in captured.out
