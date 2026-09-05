#!/usr/bin/env python3
"""Unpaid live smoke against Vibes action-ref surfaces.

Does NOT mint authenticated receipts. Checks:
  - namespace-lock: reserved decision-SKU names must 400 pre-auth on raw mint;
    error path is out["detail"]["error"] == "reserved_decision_action" (FastAPI
    nested \u2014 not flat out["error"]).

    python3 tests/live_smoke.py

Relates to: https://github.com/coinbase/agentkit/issues/1168
Confirmed by: https://github.com/coinbase/agentkit/issues/1168#issuecomment-5076953987
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

UA = "VibesActionRefSmoke/1.0 (+https://vibes-coded.com)"
BASE = "https://vibes-coded.com/api/v1/outcomes"


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

    # Namespace lock \u2014 reserved decision-SKU names must 400 pre-auth on raw mint.
    # Error path is FastAPI-nested: out["detail"]["error"] == "reserved_decision_action"
    # (not flat out["error"]).  Confirmed by doteyeso-ops in agentkit#1168 comment
    # 5076953987 (2026-07-25).  MANIFEST reject_reasons stays verify-side only;
    # this is a live-only rule.
    st, out = http("POST", "/action-receipt", {"action": "destructive-action-guard.allow"})
    if st != 400 or not (
        isinstance(out, dict)
        and out.get("detail", {}).get("error") == "reserved_decision_action"
    ):
        failures.append(
            f"namespace-lock: want 400 reserved_decision_action, got {st} {out!r}"
        )
    else:
        print("[ok] namespace-lock -> 400 reserved_decision_action (pre-auth)")

    if failures:
        for msg in failures:
            print(f"[FAIL] {msg}", file=sys.stderr)
        return 1

    print(f"\nSMOKE OK: all 1 check(s) passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
