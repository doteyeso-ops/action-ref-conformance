# citation-join conformance — Vibes-Coded

Offline golden vectors for the **pipe-tuple action-receipt / citation-join** profile
used by Vibes Outcome `action-receipt` (distinct from `action-ref-v1-jcs-sha256`).

See live pattern: https://vibes-coded.com/patterns/CITATION_JOIN.md

```text
agent_id|action|payload_digest|nonce|quote|ts|rt:<raw|decision>(|decision_ref)
```

**This suite is self-contained.** Vectors are signed with a **fixture** Ed25519 key
(`manifest/FIXTURE.json`) — not the production Vibes key. Rules match production
verify. Anyone can recompute without paying or hitting the live mint.

## Run

```bash
python3 manifest/verify.py                 # -> CONFORMANT
python3 tests/live_smoke.py                # unpaid prod probes (no mint)
```

Requires `cryptography` for Ed25519 (`pip install cryptography`).

## Coverage

| Vector | Expect | Reason |
|--------|--------|--------|
| `pos_raw` | PASS | `rt:raw` mint |
| `pos_citation_bound` | PASS | `decision_ref` inside preimage |
| `pos_decision_origin` | PASS | `rt:decision` policy SKU |
| `neg_citation_substitution` | REJECT | JSON cites ref; sig unbound |
| `neg_field_tamper_action` | REJECT | action flipped after sign |
| `neg_origin_mismatch` | REJECT | claim `decision` over `rt:raw` sig |
| `neg_pipe_delimiter` | REJECT | `\|` inside a field |

## Live surfaces (unpaid)

| Step | URL |
|------|-----|
| Public key | `GET …/action-receipt/public-key` |
| Verify | `POST …/action-receipt/verify` |
| Mint | `POST …/action-receipt` (x402 / prepaid — not free) |

Mint-time reserved-action reject (`destructive-action-guard.allow` on raw mint) is a
**live API** rule; see `tests/live_smoke.py` notes. Offline suite covers verify-side
origin forge via `neg_origin_mismatch`.

## Sibling suite

JCS `action_ref` recompute: [`../action-ref`](../action-ref) /
https://github.com/doteyeso-ops/action-ref-conformance

Licensed Apache-2.0 (see LICENSE).
