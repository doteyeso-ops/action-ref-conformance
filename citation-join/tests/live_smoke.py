#!/usr/bin/env python3
"""Unpaid live smoke against Vibes citation-join surfaces.

Does NOT mint (action-receipt is paid). Checks:
  - public-key 200
  - verify malformed body 400
  - verify fixture positive against PROD key → signature_invalid / valid=false
    (proves endpoint is up; fixture key ≠ prod)
  - verify with missing fields 400

    python3 tests/live_smoke.py
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

UA = "VibesCitationJoinSmoke/1.0 (+https://vibes-coded.com)"
BASE = "https://vibes-coded.com/api/v1/outcomes"
ROOT = Path(__file__).resolve().parents[1] / "manifest"


def http(method: str, path: str, body: dict | None = None) -> tuple[int, dict | str]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"User-Agent": UA, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def main() -> int:
    failures: list[str] = []

    st, pk = http("GET", "/action-receipt/public-key")
    if st != 200 or not isinstance(pk, dict) or "public_key_pem" not in pk:
        failures.append(f"public-key: {st}")
    else:
        print(f"[ok] public-key 200 ({pk.get('algorithm')})")

    st, bad = http("POST", "/action-receipt/verify", {"agent_id": "x"})
    if st != 400:
        failures.append(f"verify malformed want 400 got {st}")
    else:
        print("[ok] verify malformed -> 400")

    pos = json.loads((ROOT / "vectors" / "pos_raw.json").read_text(encoding="utf-8"))
    st, out = http("POST", "/action-receipt/verify", pos)
    if st != 200 or not isinstance(out, dict):
        failures.append(f"verify fixture against prod: {st}")
    else:
        # Fixture key ≠ prod → must not join_ok
        if out.get("valid") is True and out.get("signature_valid") is True:
            failures.append("fixture unexpectedly verified under prod key")
        else:
            print(
                f"[ok] verify fixture vs prod -> valid={out.get('valid')} "
                f"sig={out.get('signature_valid')} (expected false - key mismatch)"
            )

    st, mint = http(
        "POST",
        "/action-receipt",
        {
            "agent_id": "smoke",
            "action": "peer.settle",
            "payload_digest": "a" * 64,
            "nonce": "smoke-nonce-01",
        },
    )
    if st != 402:
        failures.append(f"unpaid mint want 402 got {st}")
    else:
        print("[ok] unpaid mint → 402 (paid surface; use offline vectors)")

    if failures:
        print("FAIL:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    print("\nLIVE_SMOKE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
