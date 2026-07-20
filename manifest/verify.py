#!/usr/bin/env python3
"""action-ref-v1-jcs-sha256 conformance verifier (stdlib-only).

Recomputes action_ref = SHA-256(JCS(preimage)) over the frozen 4-field tuple
{action_type, agent_id, scope, timestamp} and checks each vector's expected verdict.

Two-sided by design: this same verifier reproduces giskard09/action-ref-conformance
byte-for-byte (see tests/cross_check.py). Exits non-zero unless BOTH verdicts are
observed and EVERY declared reject reason is exercised.

    python3 manifest/verify.py            # verify bundled vectors
    python3 manifest/verify.py <dir>      # verify an external manifest dir
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

# RFC 3339 UTC, millisecond precision, 'Z' zulu — the canonical timestamp grammar.
RFC3339_MS_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
TUPLE_FIELDS = ("action_type", "agent_id", "scope", "timestamp")


def jcs(obj: dict) -> bytes:
    """RFC 8785 canonical JSON for the flat ASCII tuple: sorted keys, no spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def action_ref(preimage: dict) -> str:
    return hashlib.sha256(jcs(preimage)).hexdigest()


def timestamp_ok(ts) -> bool:
    return isinstance(ts, str) and bool(RFC3339_MS_Z.match(ts))


def verify_vector(vec: dict) -> tuple[str, str | None]:
    """Return (verdict, reason). verdict in {PASS, REJECT}."""
    if "preimage" in vec:  # positive: recompute must equal declared action_ref
        pre = {k: vec["preimage"][k] for k in TUPLE_FIELDS}
        if not timestamp_ok(pre["timestamp"]):
            return "REJECT", "grammar_reject"
        return ("PASS", None) if action_ref(pre) == vec["action_ref"] else ("REJECT", "recompute_mismatch")
    # negative: reject either at the grammar gate or by digest mismatch
    payload = vec["invocation_payload"]
    if not timestamp_ok(payload.get("timestamp")):
        return "REJECT", "grammar_reject"
    tup = {k: payload[k] for k in TUPLE_FIELDS}
    return ("REJECT", "recompute_mismatch") if action_ref(tup) != vec["claimed_action_ref"] else ("PASS", None)


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).parent
    manifest = json.loads((root / "MANIFEST.json").read_text())
    verdicts_seen, reasons_seen, failures = set(), set(), []
    for entry in manifest["vectors"]:
        vec = json.loads((root / "vectors" / entry["file"]).read_text())
        verdict, reason = verify_vector(vec)
        verdicts_seen.add(verdict)
        if reason:
            reasons_seen.add(reason)
        ok = verdict == entry["expect"] and reason == entry.get("reason")
        if not ok:
            failures.append(f"{entry['file']}: got ({verdict},{reason}) want ({entry['expect']},{entry.get('reason')})")
        print(f"[{'ok' if ok else 'FAIL'}] {entry['file']}: {verdict} {reason or ''}")

    declared = set(manifest["reject_reasons"])
    problems = []
    if failures:
        problems.append(f"{len(failures)} vector(s) mismatched:\n  " + "\n  ".join(failures))
    if verdicts_seen != {"PASS", "REJECT"}:
        problems.append(f"both verdicts not observed: saw {sorted(verdicts_seen)}")
    if reasons_seen != declared:
        problems.append(f"not every reject reason exercised: saw {sorted(reasons_seen)}, declared {sorted(declared)}")
    if problems:
        print("\nNON-CONFORMANT:\n" + "\n".join(problems), file=sys.stderr)
        return 1
    print(f"\nCONFORMANT: {len(manifest['vectors'])} vectors, both verdicts, all reasons exercised.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
