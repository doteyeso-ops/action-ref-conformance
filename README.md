# action-ref-v1 conformance â€” Vibes-Coded

Published conformance vectors + a stdlib-only verifier for the
`action-ref-v1-jcs-sha256` profile discussed in
[x402#2906](https://github.com/x402-foundation/x402/issues/2906).

    action_ref = SHA-256(JCS(preimage))   over the frozen 4-field tuple
                 { action_type, agent_id, scope, timestamp }

**Anyone can recompute these without running Vibes-Coded's service** â€” you need only
the bytes and this verifier. That is the whole point of an offline-verifiable receipt.

## Run

    python3 manifest/verify.py                 # our vectors  -> CONFORMANT
    python3 manifest/verify.py <other-dir>     # verify any action-ref-v1 manifest

Exits non-zero unless both verdicts (PASS/REJECT) are observed and every declared
reject reason (`grammar_reject`, `recompute_mismatch`) is exercised.

## Two-sided agreement

Our verifier reproduces [giskard09/action-ref-conformance](https://github.com/giskard09/action-ref-conformance)
byte-for-byte â€” all 13 of their vectors pass here, and ours are shape-compatible with
theirs. `tests/cross_check.py` fetches their manifest and asserts agreement in both
directions.

## Layout

    manifest/MANIFEST.json    expected verdicts per vector
    manifest/vectors/*.json   one file per vector (2 positive, 3 negative)
    manifest/verify.py        stdlib-only verifier (no deps)
    tests/cross_check.py      two-sided agreement against giskard09's suite

Licensed Apache-2.0 (see LICENSE). PRs to add vectors welcome.

## Sibling: citation-join (pipe receipt)

Separate profile for Vibes `action-receipt` pipe-tuples (citation substitution +
`receipt_type` origin). Offline golden vectors:

    python3 citation-join/manifest/verify.py

See `citation-join/README.md`.
