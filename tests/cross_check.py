#!/usr/bin/env python3
"""Two-sided agreement: our verifier must reproduce giskard09/action-ref-conformance.

Fetches their published manifest + vectors and asserts our verify.py agrees on every
verdict and reason. No deps beyond stdlib. Exits non-zero on any disagreement.

    python3 tests/cross_check.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/giskard09/action-ref-conformance/main/manifest"
HERE = Path(__file__).resolve().parent.parent


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=20) as r:  # noqa: S310 (trusted host)
        return r.read()


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "vectors").mkdir()
        manifest = json.loads(fetch(f"{BASE}/MANIFEST.json"))
        (root / "MANIFEST.json").write_bytes(json.dumps(manifest).encode())
        for entry in manifest["vectors"]:
            (root / "vectors" / entry["file"]).write_bytes(fetch(f"{BASE}/vectors/{entry['file']}"))
        proc = subprocess.run(
            [sys.executable, str(HERE / "manifest" / "verify.py"), str(root)],
            capture_output=True, text=True,
        )
        print(proc.stdout)
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            print("CROSS-CHECK FAILED: we do not agree with giskard09's suite", file=sys.stderr)
            return 1
        print(f"CROSS-CHECK OK: reproduced all {len(manifest['vectors'])} giskard09 vectors.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
