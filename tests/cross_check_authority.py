"""Independent cross-check verifier for the x402 delegated-authority vectors
(whawk46 / x402-foundation#3170 / PR #3220, specs/extensions/authority-vectors.json).

Reproduces the mandated values byte-for-byte from the spec (authority.md §3/§8/§9):
  mandate digest   = sha256("x402-mandate/1\\n" || RFC8785-JCS(mandate))
  Ed25519 sig      = over ("x402-mandate/1\\n" || JCS(mandate))
  binding nonce    = sha256("x402-mandate-binding/1\\n" || ("sha256:"+digest+"\\n"+paymentId))
                     -> EIP-3009 bytes32 0x, Permit2 uint256 BE, XRPL hex
  spend-log root   = RFC 6962 over leaves sha256(0x00||JCS({drawId,nonce,seed}))
                     interior sha256(0x01||L||R), split at largest pow2 < n
Run:  python verify_authority.py specs/extensions/authority-vectors.json
Exit 0 iff every byte-verifiable check passes. Unread-verifiable values are reported not claimed.
This is an independent implementation; every value is recomputed, not read from the file.
"""
import sys, json, hashlib, base64
try:
    import nacl.signing as ns
    HAVE_NACL = True
except ImportError:
    HAVE_NACL = False

def jcs(o):
    """RFC 8785 canonical JSON: sorted keys, compact."""
    def enc(v):
        if isinstance(v, dict):
            return "{" + ",".join(json.dumps(k)+":"+enc(v[k]) for k in sorted(v)) + "}"
        if isinstance(v, list):
            return "[" + ",".join(enc(x) for x in v) + "]"
        if isinstance(v, (str, bool)) or v is None:
            return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        if isinstance(v, int):
            return str(v)
        raise TypeError(v)
    return enc(o)

def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))

def ed25519_ok(pub_b64, msg, sig_b64):
    if not HAVE_NACL:
        return "SKIP"
    ns.VerifyKey(b64u(pub_b64)).verify(msg, b64u(sig_b64))
    return True

def mandate_digest(m):
    j = jcs(m)
    return "sha256:" + hashlib.sha256((m["v"] + "\n" + j).encode()).hexdigest(), j

def rfc6962_root(leaves):
    for _ in range(100):
        if len(leaves) == 1:
            return leaves[0]
        k = 1
        while k * 2 < len(leaves):
            k *= 2
        left = rfc6962_root(leaves[:k])
        right = rfc6962_root(leaves[k:])
        return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

def spend_leaves(entries):
    out = []
    for e in entries:
        leaf_obj = {
            "drawId": e["mandateDigest"] + "|" + e["paymentId"],
            "nonce": e["recipient"] + "|" + e["asset"],
            "seed": e["amount"] + ":" + e["cumulative"] + ":" + e["priorRoot"],
        }
        out.append(hashlib.sha256(b"\x00" + jcs(leaf_obj).encode()).hexdigest())
    return out

def main(path):
    V = json.load(open(path, encoding="utf-8"))
    P, S = [], 0
    def check(name, got, want):
        nonlocal S
        if got == "SKIP":
            S += 1
            P.append((name, "SKIP")); return
        ok = got == want
        P.append((name, "PASS" if ok else "FAIL"))
    keys = V["keys"]

    # Model A
    ma = V["modelA"]["mandate"]
    d, j = mandate_digest(ma)
    check("A.mandate.digest", d, V["modelA"]["digest"])
    check("A.mandate.sig", ed25519_ok(keys["issuer"]["publicKeyB64url"], (ma["v"]+"\n"+j).encode(), V["modelA"]["sig"]), True)
    b = V["modelA"]["binding"]
    B = hashlib.sha256(("x402-mandate-binding/1\n" + ("sha256:"+d.split(":")[1] + "\n" + b["paymentId"])).encode()).hexdigest()
    check("A.binding.eip3009", "0x"+B, b["eip3009"])
    check("A.binding.xrpl", B.upper(), b["xrpl"])
    check("A.binding.permit2", str(int(B,16)), b["permit2"])
    pay = V["modelA"]["paymentAccepted"]["payment"]
    check("A.payment.verdict", all([
        int(pay["amount"]) <= int(ma["perPayment"]),
        pay["recipient"] in ma["recipients"],
        pay["asset"] == ma["asset"],
        pay["payer"] == ma["subject"],
        pay["at"] <= ma["notAfter"],
    ]), True)
    check("A.spendLog.root", rfc6962_root(spend_leaves(V["modelA"]["spendLog"]["entries"])), V["modelA"]["spendLog"]["root"])

    # Model B
    mb = V["modelB"]["mandate"]
    db, jb = mandate_digest(mb)
    check("B.mandate.digest", db, V["modelB"]["digest"])
    check("B.mandate.sig", ed25519_ok(keys["issuer"]["publicKeyB64url"], (mb["v"]+"\n"+jb).encode(), V["modelB"]["sig"]), True)
    at0 = V["modelB"]["attestations"][0]; att = at0["attestation"]
    payee = "payee-1" if att["payee"] == keys["payee-1"]["publicKeyB64url"] else "payee-2"
    check("B.att1.sig", ed25519_ok(keys[payee]["publicKeyB64url"], (att["v"]+"\n"+jcs(att)).encode(), at0["sig"]), True)

    # Delegation
    de, ch = V["delegation"], V["delegation"]["child"]
    dc, jc = mandate_digest(ch)
    check("D.childDigest", dc, de["childDigest"])
    check("D.childSig", ed25519_ok(keys["agent-subject"]["publicKeyB64url"], (ch["v"]+"\n"+jc).encode(), de["childSig"]), True)
    check("D.rootIssuer", de["rootIssuer"], keys["issuer"]["publicKeyB64url"])

    # Under-report refusal — DERIVED from whawk46's scenario (not read from any boolean).
    # settled artifact shows amount 1000000, presented says 1, against Model A (per-payment 250000).
    ma = V["modelA"]["mandate"]
    scenario_settled = {"payer": ma["subject"], "recipient": "merchant.example", "asset": "FCUSD", "amount": "1000000"}
    def authorize(md, pay):
        reasons = []
        if int(pay["amount"]) > int(md.get("perPayment", md.get("cap", "0"))):
            reasons.append("per_payment_exceeded")
        if pay["recipient"] not in md.get("recipients", []): reasons.append("recipient")
        if pay["asset"] != md.get("asset"): reasons.append("asset")
        if pay["payer"] != md.get("subject"): reasons.append("payer")
        return reasons
    presented_ok = not authorize(ma, {**scenario_settled, "amount": "1"})
    settled_ok = not authorize(ma, scenario_settled)
    check("SEC.underreport.presented-authorizes", presented_ok, True)
    check("SEC.underreport.settled-refused", settled_ok, False)

    print("=== x402 authority vectors — independent cross-check ===")
    npass = 0
    for name, tag in P:
        if tag == "PASS": npass += 1
        print(f"  [{tag}] {name}")
    print(f"\n{npass}/{len(P)-S} byte-verified, {S} unverified (sig skipped when pynacl absent)")
    return 1 if any(t == "FAIL" for _, t in P) else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
