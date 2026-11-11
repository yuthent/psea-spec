"""Composition set: draft-yossif-psea-03 evidence inside a decision receipt
(draft-gruszka-audit-decision-receipts-05).

Every vector states two expected results BEFORE the run: what the reference
PSEA Verifier alone decides (psea_verifier), and what the composition with the
approval record decides (composition).  run.py only reads the committed
fixtures; gen.py produced them.

  python3 run.py            print the result JSON
  python3 run.py --check    also compare it with results/dr-results.json
"""
import base64, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))
from cryptography.hazmat.primitives.asymmetric import ec
from jcs import canonicalize
from psea import Enrollment, Verifier, Refusal, b64u_dec

RESULTS = os.path.join(HERE, "results", "dr-results.json")


def load(rel):
    with open(os.path.join(HERE, rel), encoding="utf-8") as fh:
        return json.load(fh)


def load_bytes(rel):
    with open(os.path.join(HERE, rel), "rb") as fh:
        return fh.read()


def public_key(jwk):
    x = int.from_bytes(b64u_dec(jwk["x"]), "big")
    y = int.from_bytes(b64u_dec(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def build_enrollment(rec):
    """Map the fixture onto the reference Enrollment.

    The reference Enrollment takes a kid, a public key, a UV-enforcement flag,
    a principal and the Section 3.14 lifecycle state.  The fixture conveys no
    UV-enforcement property, so uv_enforced is None (anchoring "asserted"),
    with the Verifier's default high_assurance=False.
    """
    e = Enrollment()
    e.enroll(rec["kid"], public_key(rec["public_jwk"]), uv_enforced=None,
             principal=rec["subject"], state=rec["state"])
    return e


def psea_verify(verifier, token, action, ctx):
    try:
        verifier.verify(token, action=action, op=ctx["op"], tier=ctx["tier"],
                        now=ctx["now"])
        return "ACCEPT", "VERIFIED"
    except Refusal as e:
        return "REFUSE", e.code


def token_claims(token):
    return json.loads(b64u_dec(token.split(".")[1]))


def compose(psea_observed, enrollment, approval, action_bytes, token):
    """The composition decision, and only this.

    Accept only if the PSEA Verifier accepted the proof and all four hold:
      1. enrollment state is active
      2. enrollment subject == approval approver (principal.id)
      3. SHA-256(action bytes) == approval actionDigest == decoded psea_payload_hash
      4. proof jti == approvalId (correlation agreed with the decision-receipts side)
    At-most-once is not checked here.  Replay is refused by the PSEA Verifier's
    own state, and that refusal reaches this column through psea_observed.
    """
    failed = []
    if psea_observed != "ACCEPT":
        failed.append("psea_verifier_refused")
    if enrollment["state"] != "active":
        failed.append(f"enrollment_state={enrollment['state']}")
    if enrollment["subject"] != approval["approver"]:
        failed.append("subject!=approver")
    claims = token_claims(token)
    action_hex = hashlib.sha256(action_bytes).hexdigest()
    proof_hex = base64.b64decode(claims["psea_payload_hash"]).hex()
    if not (action_hex == approval["actionDigest"]["sha256"] == proof_hex):
        failed.append("action_digest_mismatch")
    if claims["jti"] != approval["approvalId"]:
        failed.append("jti!=approvalId")
    return ("REFUSE", ",".join(failed)) if failed else ("ACCEPT", "all_checks_hold")


def verdict(expected, observed):
    if observed == "NOT_REPRESENTABLE":
        return "NOT_APPLICABLE"
    return "PASS" if expected == observed else "FAIL"


def main():
    spec = load("vectors.json")
    ctx = spec["context"]
    action_bytes = load_bytes(ctx["action"])
    action = json.loads(action_bytes)
    if canonicalize(action) != action_bytes:
        sys.exit("action bytes are not RFC 8785 canonical")
    approval_bytes = load_bytes(ctx["approval"])
    approval = json.loads(approval_bytes)
    if canonicalize(approval) != approval_bytes:
        sys.exit("approval record bytes are not RFC 8785 canonical: "
                 + ctx["approval"])

    rows = []
    for vec in spec["vectors"]:
        enrollment = load(vec["enrollment"])
        verifier = Verifier(build_enrollment(enrollment), ctx["iss"], ctx["aud"])
        for rel in vec["presentations"]:
            token = load(rel)["token"]
            p_obs, p_detail = psea_verify(verifier, token, action, ctx)
        c_obs, c_detail = compose(p_obs, enrollment, approval, action_bytes, token)
        exp = vec["expected"]
        row = {
            "id": vec["id"],
            "differs": vec["differs"],
            "psea_verifier": {"expected": exp["psea_verifier"], "observed": p_obs,
                              "detail": p_detail,
                              "verdict": verdict(exp["psea_verifier"], p_obs)},
            "composition": {"expected": exp["composition"], "observed": c_obs,
                            "detail": c_detail,
                            "verdict": verdict(exp["composition"], c_obs)},
        }
        rows.append(row)

    out = json.dumps({
        "set": spec["set"],
        "profile": "draft-yossif-psea-03",
        "counterpart": "draft-gruszka-audit-decision-receipts-05",
        "correlation": "jti -> approvalId (agreed with the decision-receipts side)",
        "status": "SINGLE_IMPLEMENTATION_NOT_YET_CROSS_RUN",
        "rows": rows,
    }, indent=1) + "\n"
    sys.stdout.write(out)

    if "--check" in sys.argv[1:]:
        with open(RESULTS, encoding="utf-8") as fh:
            if fh.read() != out:
                sys.exit("result differs from results/dr-results.json")
        sys.stderr.write("result identical to results/dr-results.json\n")


if __name__ == "__main__":
    main()
