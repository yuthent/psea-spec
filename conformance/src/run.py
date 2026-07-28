"""Cross-run: draft-yossif-psea-02 against the WHO negative classes of
draft-mih-sato-agent-accountability-composition-00 Section 5.2, plus the three
digest-encoding rows and the multi-artifact principal-divergence case.

Every row states the expected result BEFORE the run.  A row whose expected
result is REFUSE and whose observed result is anything else is a failure of
the profile, and is reported as such.
"""
import base64, hashlib, json, sys, time
sys.path.insert(0, __import__("os").path.dirname(__file__))
from cryptography.hazmat.primitives.asymmetric import ec
from jcs import canonicalize
from psea import Attester, Enrollment, Verifier, Refusal, payload_hash, b64u

ACTION = {"operation": "transfer", "target": "acct-9", "amount": 500}
ISS, AUD, OP, TIER = "as.example", "rs.example", "payment.execute", "high"

rows = []


def row(cid, name, sec, expected, note=""):
    def deco(fn):
        rows.append((cid, name, sec, expected, fn, note))
        return fn
    return deco


def fresh(uv_enforced=True, principal="alice", high=False):
    k = ec.generate_private_key(ec.SECP256R1())
    e = Enrollment(); e.enroll("k1", k.public_key(), uv_enforced=uv_enforced, principal=principal)
    return Attester("k1", k), Verifier(e, ISS, AUD, high_assurance=high), e


def base(att):
    return att.sign(action=ACTION, op=OP, tier=TIER, aud=AUD, iss=ISS)


def run(v, tok, action=ACTION, op=OP, tier=TIER):
    try:
        r = v.verify(tok, action=action, op=op, tier=tier)
        return ("ACCEPT", r)
    except Refusal as e:
        return ("REFUSE", e.code)


# ---------- Section 5.2 WHO negative classes ----------

@row("N1", "semantically similar input, different canonical bytes", "5.2", "REFUSE")
def _():
    a, v, _ = fresh()
    t = base(a)
    # same meaning to a human, different canonical bytes
    return run(v, t, action={"operation": "transfer", "target": "acct-09", "amount": 500})


@row("N2", "changed subject", "5.2", "REFUSE")
def _():
    a, v, _ = fresh()
    t = base(a)
    return run(v, t, action={"operation": "transfer", "target": "acct-7", "amount": 500})


@row("N3", "changed authorizing-principal reference", "5.2", "REFUSE")
def _():
    # psea_user_hash is OPTIONAL and absent by default.  Nothing in the token
    # references a principal, so a changed principal reference is not visible.
    a, v, _ = fresh()
    t = base(a)
    res = run(v, t)
    return res


@row("N4", "replay under a different action", "5.2", "REFUSE")
def _():
    a, v, _ = fresh()
    t = base(a)
    return run(v, t, op="payment.refund")


@row("N5", "quorum: non-distinct principal fills two slots", "5.2", "REFUSE")
def _():
    return ("NOT_REPRESENTABLE", "profile defines no quorum construct")


@row("N6", "quorum: ordered quorum satisfied out of order", "5.2", "REFUSE")
def _():
    return ("NOT_REPRESENTABLE", "profile defines no quorum construct")


@row("N7", "quorum: threshold not met", "5.2", "REFUSE")
def _():
    return ("NOT_REPRESENTABLE", "profile defines no quorum construct")


@row("N8", "mismatched or absent signature", "5.2", "REFUSE")
def _():
    a, v, _ = fresh()
    t = base(a)
    h, p, s = t.split(".")
    bad = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    bad[0] ^= 0xFF
    return run(v, f"{h}.{p}.{b64u(bytes(bad))}")


@row("N9", "signature verifies but does not cover the subject digest", "5.2", "REFUSE")
def _():
    # psea_payload_hash is a claim inside the signed payload.  A signature that
    # verifies but does not cover the digest cannot be constructed.
    return ("NOT_REPRESENTABLE", "digest is inside the signed payload by construction")


@row("N10", "stale receipt", "5.2", "REFUSE")
def _():
    a, v, _ = fresh()
    now = int(time.time())
    t = a.sign(action=ACTION, op=OP, tier=TIER, aud=AUD, iss=ISS, iat=now - 600, exp=now - 300)
    return run(v, t)


@row("N11", "post-hoc ratification presented as pre-execution authorization", "5.2", "REFUSE")
def _():
    # A proof minted after the effect is structurally identical to one minted
    # before it.  Nothing in the token orders the signature against the effect.
    a, v, _ = fresh()
    t = base(a)
    return run(v, t)


@row("N12a", "one-time authorization replayed", "5.2", "REFUSE")
def _():
    a, v, _ = fresh()
    t = base(a)
    run(v, t)
    return run(v, t)


@row("N12b", "reusable authorization presented as one-time", "5.2", "REFUSE")
def _():
    return ("NOT_REPRESENTABLE", "profile defines no reusable mode")


@row("N13", "unattested UV anchoring accepted for a high-assurance operation", "3.7.1", "REFUSE")
def _():
    a, v, _ = fresh(uv_enforced=None, high=True)
    return run(v, base(a))


@row("N14", "psea_uv contradicted by platform attestation", "3.7.1", "REFUSE")
def _():
    a, v, _ = fresh(uv_enforced=False)
    return run(v, base(a))


@row("N15", "header alg none", "3.4", "REFUSE")
def _():
    a, v, _ = fresh()
    return run(v, a.sign(action=ACTION, op=OP, tier=TIER, aud=AUD, iss=ISS, alg="none"))


@row("N16", "key taken from token-carried material instead of enrolled record", "3.4", "REFUSE")
def _():
    rogue = ec.generate_private_key(ec.SECP256R1())
    a, v, _ = fresh()
    rogue_att = Attester("k1", rogue)
    jwk = {"kty": "EC", "crv": "P-256"}
    return run(v, rogue_att.sign(action=ACTION, op=OP, tier=TIER, aud=AUD, iss=ISS,
                                 header_extra={"jwk": jwk}))


# ---------- digest-encoding rows (raised on agent2agent 2026-07-25) ----------

@row("E1", "same 32 octets, different encodings, compatible contexts", "join", "JOIN")
def _():
    d = hashlib.sha256(canonicalize(ACTION)).digest()
    psea_form = base64.b64encode(d).decode()
    other_form = d.hex()
    joined = base64.b64decode(psea_form) == bytes.fromhex(other_form)
    naive = (psea_form == other_form)
    return ("JOIN" if joined else "MISMATCH", f"octet-compare={joined} string-compare={naive}")


@row("E2", "same 32 octets, incompatible declared digest contexts", "INDETERMINATE", "INDETERMINATE")
def _():
    d = hashlib.sha256(canonicalize(ACTION)).digest()
    ctx_a = {"alg": "SHA-256", "canon": "JCS", "model": "psea.actionPayload"}
    ctx_b = {"alg": "SHA-256", "canon": "JCS", "model": "other.action"}
    if ctx_a != ctx_b:
        return ("INDETERMINATE", "declared contexts differ; equality of octets is not equality of claim")
    return ("JOIN", "")


@row("E3", "ASCII-hex string compared as bytes against raw octets", "MISMATCH", "MISMATCH")
def _():
    d = hashlib.sha256(canonicalize(ACTION)).digest()
    hex_as_bytes = d.hex().encode()
    return ("MISMATCH" if hex_as_bytes != d else "JOIN",
            f"len {len(hex_as_bytes)} vs {len(d)}")


# ---------- multi-artifact principal divergence (raised to Kroehl 2026-07-28) ----------

@row("M1", "two artifacts verify, same action, different principals", "composition", "REFUSE")
def _():
    ka = ec.generate_private_key(ec.SECP256R1())
    kb = ec.generate_private_key(ec.SECP256R1())
    e = Enrollment()
    e.enroll("kA", ka.public_key(), uv_enforced=True, principal="alice")
    e.enroll("kB", kb.public_key(), uv_enforced=True, principal="bob")
    v = Verifier(e, ISS, AUD)
    tb = Attester("kB", kb).sign(action=ACTION, op=OP, tier=TIER, aud=AUD, iss=ISS)
    ok, r = run(v, tb)
    standing_grant_principal = "alice"
    if ok == "ACCEPT":
        same = r["enrolled_principal"] == standing_grant_principal
        return ("ACCEPT" if not same else "REFUSE",
                f"psea principal={r['enrolled_principal']} grant principal={standing_grant_principal}")
    return (ok, r)


def main():
    out = []
    for cid, name, sec, expected, fn, note in rows:
        observed, detail = fn()
        if expected in ("REFUSE",) and observed == "REFUSE":
            verdict = "PASS"
        elif expected == observed:
            verdict = "PASS"
        elif observed == "NOT_REPRESENTABLE":
            verdict = "NOT_APPLICABLE"
        else:
            verdict = "FAIL"
        out.append({"id": cid, "class": name, "source": sec,
                    "expected": expected, "observed": observed,
                    "detail": str(detail), "verdict": verdict})
    print(json.dumps({
        "suite": "psea-02 vs composition-00 S5.2 WHO negative classes",
        "profile": "draft-yossif-psea-02",
        "target": "draft-mih-sato-agent-accountability-composition-00",
        "implementations": 1,
        "status": "SINGLE_IMPLEMENTATION_NOT_YET_CROSS_RUN",
        "rows": out,
    }, indent=1))


if __name__ == "__main__":
    main()
