"""Generate the fixtures of the PSEA -03 / decision-receipt composition set.

Run once.  Every proof is produced by the reference Attester in
conformance/src/psea.py; none is written by hand.  ECDSA signatures are
randomized, so a second generation produces different tokens: the committed
files are the vectors, and run.py only reads them.

Refuses to run if the key file already exists, so the committed key and proofs
cannot be replaced by accident.
"""
import base64, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))
from cryptography.hazmat.primitives.asymmetric import ec
from psea import Attester, b64u
from jcs import canonicalize

KID = "dr-test-es256-2026-11"
ISS, AUD, OP, TIER = "as.example", "rs.example", "payment.execute", "high"
IAT = 1794208809
EXP = IAT + 300
APPROVAL_ID = "BgVXFoeczie5vAc-"
ACTION_PATH = os.path.join(HERE, "action", "action.json")
GENERATED_WITH = "conformance/src/psea.py Attester (psea-spec e402b79)"


def write(rel, obj):
    path = os.path.join(HERE, rel)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


def coord(n):
    return b64u(n.to_bytes(32, "big"))


def public_jwk(priv):
    nums = priv.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": coord(nums.x), "y": coord(nums.y)}


def thumbprint(jwk):
    """RFC 7638: SHA-256 over the required members in lexicographic order."""
    req = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    data = json.dumps(req, separators=(",", ":"), sort_keys=True).encode()
    return b64u(hashlib.sha256(data).digest())


def sign(priv, action, jti):
    att = Attester(KID, priv)
    return att.sign(action=action, op=OP, tier=TIER, aud=AUD, iss=ISS,
                    jti=jti, iat=IAT, exp=EXP)


def main():
    key_path = os.path.join(HERE, "keys", "test-es256.jwk")
    if os.path.exists(key_path):
        sys.exit("keys/test-es256.jwk exists; refusing to regenerate the set")

    with open(ACTION_PATH, "rb") as fh:
        action_bytes = fh.read()
    action = json.loads(action_bytes)

    priv = ec.generate_private_key(ec.SECP256R1())
    pub = public_jwk(priv)
    tp = thumbprint(pub)
    write("keys/test-es256.jwk", {
        "_label": "TEST ONLY. Generated for this vector set. The private part is "
                  "published on purpose so anyone can re-sign. Never trust it.",
        "kid": KID,
        **pub,
        "d": coord(priv.private_numbers().private_value),
    })

    for name, state, subject in (("active", "active", "alice"),
                                 ("subject-mismatch", "active", "bob"),
                                 ("revoked", "revoked", "alice"),
                                 ("suspended", "suspended", "alice")):
        write(f"enrollment/{name}.json", {
            "_label": "Test fixture, not a normative format. PSEA -03 does not "
                      "define the enrollment ceremony (Section 3.13.3).",
            "enrollment_id": f"enr-dr-{name}",
            "kid": KID,
            "public_jwk": pub,
            "jwk_thumbprint_rfc7638": tp,
            "state": state,
            "subject": subject,
        })

    write("approval/approval-A.json", {
        "_label": "Approval-record fields of "
                  "draft-gruszka-audit-decision-receipts-05 (approver, "
                  "actionDigest, approvalId). Correlation jti -> approvalId "
                  "agreed with the decision-receipts side.",
        "approver": "alice",
        "actionDigest": {"sha256": hashlib.sha256(action_bytes).hexdigest()},
        "approvalId": APPROVAL_ID,
    })

    rogue = ec.generate_private_key(ec.SECP256R1())
    changed = dict(action, amount=action["amount"] + 1)
    proofs = (
        ("v1", priv, action, APPROVAL_ID,
         "Enrolled key, the set's action bytes, jti equal to approvalId."),
        ("c4-wrong-key", rogue, action, APPROVAL_ID,
         "Same kid and claims as v1, signed by a key that is not the enrolled "
         "key. That key was ephemeral and is not retained."),
        ("c5-other-jti", priv, action, "dr-other-approval-event",
         "Enrolled key, the set's action bytes, jti not equal to approvalId."),
        ("c6-other-action", priv, changed, APPROVAL_ID,
         "Enrolled key, signed over the set's action with amount changed "
         "from 500 to 501."),
    )
    for name, k, act, jti, note in proofs:
        write(f"proofs/{name}.json", {
            "note": note,
            "generated_with": GENERATED_WITH,
            "signed_action_jcs": canonicalize(act).decode("utf-8"),
            "token": sign(k, act, jti),
        })


if __name__ == "__main__":
    main()
