#!/usr/bin/env python3
"""citation-join-v1 pipe-tuple conformance verifier.

Rules (aligned with Vibes CITATION_JOIN / action-receipt/verify):
  1. Rebuild canonical pipe preimage; verify HMAC and/or Ed25519.
  2. If JSON cites decision_ref, signature must bind it (else citation_substitution).
  3. If JSON claims receipt_type=decision, matched preimage must include rt:decision
     (else origin_mismatch).
  4. Pipe fields must not contain '|' (grammar_reject).

Fixture key in FIXTURE.json — NOT production. Live pubkey differs; rules match.

    python3 manifest/verify.py
    python3 manifest/verify.py <manifest-dir>

Requires: stdlib + cryptography (Ed25519). Exits non-zero unless PASS and REJECT
are both observed and every declared reject reason is exercised.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    print("cryptography required: pip install cryptography", file=sys.stderr)
    sys.exit(2)

RECEIPT_TYPES = frozenset({"raw", "decision"})


def build_canonical(
    *,
    agent_id: str,
    action: str,
    payload_digest: str,
    nonce: str,
    quote: str = "",
    ts: str = "",
    decision_ref: str | None = None,
    receipt_type: str | None = None,
) -> str:
    parts = [
        str(agent_id or ""),
        str(action or ""),
        str(payload_digest or ""),
        str(nonce or ""),
        str(quote or ""),
        str(ts or ""),
    ]
    rt = str(receipt_type or "").strip().lower()
    if rt:
        if rt not in RECEIPT_TYPES:
            raise ValueError("bad receipt_type")
        parts.append(f"rt:{rt}")
    ref = str(decision_ref or "").strip()
    if ref:
        parts.append(ref.replace("|", ""))
    return "|".join(parts)


def grammar_ok(vec: dict) -> bool:
    for k in ("agent_id", "action", "payload_digest", "nonce", "quote", "issued_at", "decision_ref"):
        v = vec.get(k)
        if v is None:
            continue
        if "|" in str(v):
            return False
    rt = str(vec.get("receipt_type") or "").strip().lower()
    if rt and rt not in RECEIPT_TYPES:
        return False
    return True


def verify_vector(vec: dict, *, hmac_secret: str, pub_pem: str) -> tuple[str, str | None]:
    """Return (verdict, reason). verdict in {PASS, REJECT}."""
    if not grammar_ok(vec):
        return "REJECT", "grammar_reject"

    agent_id = str(vec["agent_id"])
    action = str(vec["action"])
    payload_digest = str(vec["payload_digest"])
    nonce = str(vec["nonce"])
    quote = str(vec.get("quote") or "")
    ts = str(vec.get("issued_at") or vec.get("ts") or "")
    decision_ref = str(vec.get("decision_ref") or "").strip() or None
    receipt_type_claimed = str(vec.get("receipt_type") or "").strip().lower() or None

    candidates: list[tuple[str, bool, str | None]] = []
    if receipt_type_claimed:
        if decision_ref:
            candidates.append(
                (
                    build_canonical(
                        agent_id=agent_id,
                        action=action,
                        payload_digest=payload_digest,
                        nonce=nonce,
                        quote=quote,
                        ts=ts,
                        decision_ref=decision_ref,
                        receipt_type=receipt_type_claimed,
                    ),
                    True,
                    receipt_type_claimed,
                )
            )
        candidates.append(
            (
                build_canonical(
                    agent_id=agent_id,
                    action=action,
                    payload_digest=payload_digest,
                    nonce=nonce,
                    quote=quote,
                    ts=ts,
                    decision_ref=None,
                    receipt_type=receipt_type_claimed,
                ),
                False,
                receipt_type_claimed,
            )
        )
    if decision_ref:
        candidates.append(
            (
                build_canonical(
                    agent_id=agent_id,
                    action=action,
                    payload_digest=payload_digest,
                    nonce=nonce,
                    quote=quote,
                    ts=ts,
                    decision_ref=decision_ref,
                    receipt_type=None,
                ),
                True,
                None,
            )
        )
    candidates.append(
        (
            build_canonical(
                agent_id=agent_id,
                action=action,
                payload_digest=payload_digest,
                nonce=nonce,
                quote=quote,
                ts=ts,
                decision_ref=None,
                receipt_type=None,
            ),
            False,
            None,
        )
    )

    pub = serialization.load_pem_public_key(pub_pem.encode())
    assert isinstance(pub, Ed25519PublicKey)

    hmac_valid = False
    ed_valid = False
    citation_bound = False
    receipt_type_bound: str | None = None

    def _try_candidates(cands: list[tuple[str, bool, str | None]]) -> None:
        nonlocal hmac_valid, ed_valid, citation_bound, receipt_type_bound
        for canonical, bound, rt_bound in cands:
            if vec.get("signature") and not hmac_valid:
                expected = hmac.new(hmac_secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
                if hmac.compare_digest(expected, str(vec["signature"])):
                    hmac_valid = True
                    citation_bound = bound
                    receipt_type_bound = rt_bound
            if vec.get("ed25519_signature") and not ed_valid:
                try:
                    pub.verify(base64.b64decode(str(vec["ed25519_signature"])), canonical.encode())
                    ed_valid = True
                    citation_bound = bound or citation_bound
                    if receipt_type_bound is None:
                        receipt_type_bound = rt_bound
                except Exception:
                    pass
            if hmac_valid or ed_valid:
                return

    _try_candidates(candidates)

    # Claimed decision but only raw/legacy binding verifies → origin forge, not mere bad sig.
    if not (hmac_valid or ed_valid) and receipt_type_claimed == "decision":
        fallback: list[tuple[str, bool, str | None]] = [
            (
                build_canonical(
                    agent_id=agent_id,
                    action=action,
                    payload_digest=payload_digest,
                    nonce=nonce,
                    quote=quote,
                    ts=ts,
                    decision_ref=decision_ref,
                    receipt_type="raw",
                ),
                bool(decision_ref),
                "raw",
            ),
            (
                build_canonical(
                    agent_id=agent_id,
                    action=action,
                    payload_digest=payload_digest,
                    nonce=nonce,
                    quote=quote,
                    ts=ts,
                    decision_ref=None,
                    receipt_type="raw",
                ),
                False,
                "raw",
            ),
            (
                build_canonical(
                    agent_id=agent_id,
                    action=action,
                    payload_digest=payload_digest,
                    nonce=nonce,
                    quote=quote,
                    ts=ts,
                    decision_ref=decision_ref,
                    receipt_type=None,
                ),
                bool(decision_ref),
                None,
            ),
            (
                build_canonical(
                    agent_id=agent_id,
                    action=action,
                    payload_digest=payload_digest,
                    nonce=nonce,
                    quote=quote,
                    ts=ts,
                    decision_ref=None,
                    receipt_type=None,
                ),
                False,
                None,
            ),
        ]
        _try_candidates(fallback)
        if hmac_valid or ed_valid:
            return "REJECT", "origin_mismatch"

    if not (hmac_valid or ed_valid):
        return "REJECT", "signature_invalid"

    if decision_ref and not citation_bound:
        return "REJECT", "citation_substitution"

    if receipt_type_claimed == "decision" and receipt_type_bound != "decision":
        return "REJECT", "origin_mismatch"

    return "PASS", None


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).parent
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    fixture = json.loads((root / "FIXTURE.json").read_text(encoding="utf-8"))
    hmac_secret = fixture["hmac_secret"]
    pub_pem = fixture["public_key_pem"]

    verdicts_seen: set[str] = set()
    reasons_seen: set[str] = set()
    failures: list[str] = []

    for entry in manifest["vectors"]:
        vec = json.loads((root / "vectors" / entry["file"]).read_text(encoding="utf-8"))
        verdict, reason = verify_vector(vec, hmac_secret=hmac_secret, pub_pem=pub_pem)
        verdicts_seen.add(verdict)
        if reason:
            reasons_seen.add(reason)
        ok = verdict == entry["expect"] and reason == entry.get("reason")
        if not ok:
            failures.append(
                f"{entry['file']}: got ({verdict},{reason}) want ({entry['expect']},{entry.get('reason')})"
            )
        print(f"[{'ok' if ok else 'FAIL'}] {entry['file']}: {verdict} {reason or ''}")

    declared = set(manifest["reject_reasons"])
    problems: list[str] = []
    if failures:
        problems.append(f"{len(failures)} vector(s) mismatched:\n  " + "\n  ".join(failures))
    if verdicts_seen != {"PASS", "REJECT"}:
        problems.append(f"both verdicts not observed: saw {sorted(verdicts_seen)}")
    if reasons_seen != declared:
        problems.append(
            f"not every reject reason exercised: saw {sorted(reasons_seen)}, declared {sorted(declared)}"
        )
    if problems:
        print("\nNON-CONFORMANT:\n" + "\n".join(problems), file=sys.stderr)
        return 1
    print("\nCONFORMANT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
