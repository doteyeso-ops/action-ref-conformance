#!/usr/bin/env python3
"""Regenerate citation-join golden vectors (deterministic fixture key).

    python3 scripts/generate_vectors.py
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1] / "manifest"
VEC = ROOT / "vectors"
SEED = bytes.fromhex("11" * 32)
HMAC_SECRET = "citation-join-fixture-hmac-not-prod"
TS = "2026-07-24T16:00:00.000Z"


def canonical(**kw) -> str:
    parts = [
        kw["agent_id"],
        kw["action"],
        kw["payload_digest"],
        kw["nonce"],
        kw.get("quote") or "",
        kw.get("ts") or TS,
    ]
    if kw.get("receipt_type"):
        parts.append(f"rt:{kw['receipt_type']}")
    if kw.get("decision_ref"):
        parts.append(str(kw["decision_ref"]).replace("|", ""))
    return "|".join(parts)


def mint(pk: Ed25519PrivateKey, **kw) -> dict:
    can = canonical(**kw)
    return {
        "agent_id": kw["agent_id"],
        "action": kw["action"],
        "payload_digest": kw["payload_digest"],
        "nonce": kw["nonce"],
        "quote": kw.get("quote") or None,
        "issued_at": kw.get("ts") or TS,
        "receipt_type": kw.get("receipt_type"),
        "decision_ref": kw.get("decision_ref"),
        "signature": hmac.new(HMAC_SECRET.encode(), can.encode(), hashlib.sha256).hexdigest(),
        "ed25519_signature": base64.b64encode(pk.sign(can.encode())).decode(),
        "algorithm": "HMAC-SHA256+Ed25519",
    }


def main() -> int:
    VEC.mkdir(parents=True, exist_ok=True)
    pk = Ed25519PrivateKey.from_private_bytes(SEED)
    pub = pk.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    pos_raw = mint(
        pk,
        agent_id="gv-agent",
        action="peer.settle",
        payload_digest="a" * 64,
        nonce="gv-raw-0001",
        quote="quote-1",
        receipt_type="raw",
    )
    pos_cite = mint(
        pk,
        agent_id="gv-agent",
        action="peer.settle",
        payload_digest="b" * 64,
        nonce="gv-cite-0001",
        quote="quote-2",
        receipt_type="raw",
        decision_ref="c" * 64,
    )
    pos_dec = mint(
        pk,
        agent_id="gv-agent",
        action="destructive-action-guard.block",
        payload_digest="d" * 64,
        nonce="gv-dec-0001",
        quote="",
        receipt_type="decision",
    )

    base = mint(
        pk,
        agent_id="gv-agent",
        action="peer.settle",
        payload_digest="e" * 64,
        nonce="gv-sub-0001",
        quote="q",
        receipt_type="raw",
    )
    neg_sub = {**base, "decision_ref": "f" * 64, "attack": "citation_substitution"}

    neg_tamper = {**pos_raw, "action": "peer.settle.TAMPERED", "attack": "field_tamper_action"}

    neg_origin = {
        **pos_raw,
        "receipt_type": "decision",
        # keep action=peer.settle + rt:raw signature; only the claim flips
        "attack": "origin_mismatch",
    }

    neg_pipe = {
        "agent_id": "gv|agent",
        "action": "peer.settle",
        "payload_digest": "g" * 64,
        "nonce": "gv-pipe-0001",
        "quote": "",
        "issued_at": TS,
        "receipt_type": "raw",
        "signature": "00" * 32,
        "ed25519_signature": base64.b64encode(b"\x00" * 64).decode(),
        "attack": "pipe_delimiter",
        "note": "agent_id contains | — verifier must grammar-reject",
    }

    vectors = {
        "pos_raw.json": ("PASS", None, pos_raw),
        "pos_citation_bound.json": ("PASS", None, pos_cite),
        "pos_decision_origin.json": ("PASS", None, pos_dec),
        "neg_citation_substitution.json": ("REJECT", "citation_substitution", neg_sub),
        "neg_field_tamper_action.json": ("REJECT", "signature_invalid", neg_tamper),
        "neg_origin_mismatch.json": ("REJECT", "origin_mismatch", neg_origin),
        "neg_pipe_delimiter.json": ("REJECT", "grammar_reject", neg_pipe),
    }

    manifest = {
        "profile": "citation-join-v1-pipe-ed25519",
        "version": "1.0.0",
        "note": (
            "Vibes-Coded citation-join / action-receipt pipe-tuple conformance. "
            "Signed with FIXTURE key (not production). Live mint/verify uses Vibes prod key; "
            "rules are identical. Verify is free on prod; mint requires x402/prepaid."
        ),
        "reject_reasons": [
            "citation_substitution",
            "signature_invalid",
            "origin_mismatch",
            "grammar_reject",
        ],
        "live": {
            "public_key": "https://vibes-coded.com/api/v1/outcomes/action-receipt/public-key",
            "verify": "https://vibes-coded.com/api/v1/outcomes/action-receipt/verify",
            "mint": "https://vibes-coded.com/api/v1/outcomes/action-receipt",
            "pattern": "https://vibes-coded.com/patterns/CITATION_JOIN.md",
        },
        "vectors": [],
    }

    for fname, (expect, reason, body) in vectors.items():
        clean = {k: v for k, v in body.items() if v is not None and k != "attack"}
        if "attack" in body:
            clean["attack"] = body["attack"]
        if "note" in body:
            clean["note"] = body["note"]
        (VEC / fname).write_text(json.dumps(clean, indent=2) + "\n", encoding="utf-8")
        entry: dict = {"file": fname, "expect": expect}
        if reason:
            entry["reason"] = reason
        manifest["vectors"].append(entry)

    (ROOT / "FIXTURE.json").write_text(
        json.dumps(
            {
                "hmac_secret": HMAC_SECRET,
                "ed25519_seed_hex": SEED.hex(),
                "public_key_pem": pub,
                "warning": "Fixture only — not Vibes production signing material.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (ROOT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(manifest['vectors'])} vectors -> {VEC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
