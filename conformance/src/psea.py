"""Reference Attester and Verifier for draft-yossif-psea-03.

Implements only what the draft states normatively.  Where the draft is silent
the verifier refuses rather than guessing, per Section 3.13.2 (fail-closed).
"""
import base64, hashlib, json, re, time
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from jcs import canonicalize, NonConformingPayload

TYP = "psea-proof+jwt"
PROOF_VERSION = "1"
EAT_PROFILE = "https://datatracker.ietf.org/doc/draft-yossif-psea/"

# 2^53-1, the schema's declared maximum for psea_counter.
MAX_SAFE_INTEGER = 9007199254740991

# Patterns transcribed from the Section 3.5 JSON Schema, verbatim.
P_JTI = r"^[A-Za-z0-9._-]+$"
P_UEID = r"^[A-Za-z0-9_-]{44}$"
P_B64_STD_DIGEST = r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$"
P_B64URL_DIGEST = r"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"
P_HEX64 = r"^[0-9a-f]{64}$"

# Section 3.5, the declared claim set.  This table is a transcription of the
# JSON Schema block in draft-yossif-psea-03 Section 3.5 and is the whole of what
# the Verifier enforces about claim shape; keeping it as data rather than as
# scattered `if` statements is what makes it checkable against the draft.
#
# The schema sets additionalProperties: false, so the declared set is exhaustive:
# a claim outside it is a refusal, not an ignorable extension.  An empty spec
# ({}) is the schema's empty schema -- any JSON value is valid.
#
# psea_signals_hash is declared OPTIONAL by the profile but is deliberately not
# emitted by the Attester below -- the reference carries no auxiliary transport
# document for it to commit to, and inventing one would put a claim on the wire
# that no part of this harness appraises.
CLAIM_SCHEMA = {
    "jti": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": P_JTI},
    "aud": {"type": "string", "minLength": 1, "maxLength": 256},
    "iss": {"type": "string", "minLength": 1, "maxLength": 128},
    "iat": {"type": "integer", "minimum": 0},
    "exp": {"type": "integer", "minimum": 0},
    "ueid": {"type": "string", "pattern": P_UEID},
    "eat_nonce": {"type": "string"},
    "submods": {"type": "object",
                "properties": {"psea-device-state": {"type": "object"}}},
    "eat_profile": {"type": "string", "enum": [EAT_PROFILE]},
    "psea_tier": {"type": "string", "minLength": 1, "maxLength": 128},
    "psea_op": {"type": "string", "minLength": 1, "maxLength": 128},
    "psea_counter": {"type": "integer", "minimum": 0, "maximum": MAX_SAFE_INTEGER},
    "psea_payload_hash": {"type": "string", "pattern": P_B64_STD_DIGEST},
    "psea_chain_prev": {"type": "string", "pattern": P_HEX64},
    "psea_uv": {"type": "object",
                "required": ["verified", "method"],
                "properties": {"verified": {"type": "boolean"},
                               "method": {"type": "string"}}},
    "psea_proof_version": {"type": "string", "enum": [PROOF_VERSION]},
    "psea_caller_package": {"type": "string", "minLength": 1, "maxLength": 256},
    "psea_sdk_version": {"type": "string", "maxLength": 64},
    "psea_signals_hash": {"type": "string", "pattern": P_B64_STD_DIGEST},
    "psea_user_hash": {"type": "string", "pattern": P_B64URL_DIGEST},
    "psea_chain_pending": {},
    "psea_last_confirmed_head": {},
    "psea_rp_context_hash": {},
}

DECLARED_CLAIMS = frozenset(CLAIM_SCHEMA)

REQUIRED_CLAIMS = frozenset({
    "jti", "aud", "iss", "iat", "exp", "ueid", "eat_profile", "psea_tier",
    "psea_op", "psea_counter", "psea_payload_hash", "psea_uv",
    "psea_proof_version",
})

# These two carry an enum in the schema above, but a violation of it is reported
# through the dedicated refusal codes the profile already uses (Section 3.1 for
# the profile identifier, Section 3.15 for the version) rather than through the
# generic SCHEMA_ENUM code.  Their declared *type* is still checked generically.
_ENUM_REPORTED_ELSEWHERE = frozenset({"eat_profile", "psea_proof_version"})


class _Omit:
    """Sentinel for claims_override: remove the claim rather than set it."""

    def __repr__(self):
        return "OMIT"


OMIT = _Omit()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def eat_ueid(device_id: str, iss: str) -> str:
    """RFC 9711 Sec 4.2.1 RAND-type UEID.

    base64url (no padding) of the 33 octets
    0x01 || SHA-256(JCS({"deviceId": <deviceId>, "iss": <iss>})).

    The two inputs are encoded as a canonical JSON object (RFC 8785, via the
    canonicalizer this harness already uses for psea_payload_hash) rather than
    concatenated.  Through -02 the derivation was SHA-256(deviceId || iss), a
    bare concatenation of two variable-length strings and therefore ambiguous:
    ("acme", "corp.example") and ("acmecorp", ".example") hashed identically,
    so two deployments the pairwise derivation exists to separate could share
    one ueid.  Per-issuer by construction, so the same device yields a distinct
    ueid per iss.  The leading 0x01 is the RAND type tag.
    """
    inputs = canonicalize({"deviceId": device_id, "iss": iss})
    return b64u(b"\x01" + hashlib.sha256(inputs).digest())


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def payload_hash(action: dict) -> str:
    """psea_payload_hash: SHA-256 over JCS bytes, STANDARD base64 with padding."""
    return base64.b64encode(hashlib.sha256(canonicalize(action)).digest()).decode()


class Enrollment:
    """Relying-party-held enrolled record.  Keys resolve from here only."""

    def __init__(self):
        self._keys = {}
        self._attest = {}
        self._principal = {}

    def enroll(self, kid, pubkey, uv_enforced=None, principal=None):
        # uv_enforced: True/False if the platform attestation conveys a
        # UV-enforcement property, None if the attestation surface cannot.
        self._keys[kid] = pubkey
        self._attest[kid] = uv_enforced
        self._principal[kid] = principal

    def key(self, kid):
        return self._keys.get(kid)

    def uv_enforced(self, kid):
        return self._attest.get(kid)

    def principal(self, kid):
        return self._principal.get(kid)


class Attester:
    def __init__(self, kid, privkey, device_id=None):
        self.kid = kid
        self.priv = privkey
        # The reference models no hardware, so the device identifier the ueid
        # commits to defaults to the kid.  Only its stability matters here.
        self.device_id = device_id if device_id is not None else kid
        self.counter = 0

    def sign(self, *, action, op, tier, aud, iss, uv=True, uv_method="biometric",
             jti=None, iat=None, exp=None, user_hash=None, counter=None,
             override_payload_hash=None, header_extra=None, alg="ES256",
             typ=TYP, proof_version=PROOF_VERSION, claims_override=None,
             raw_payload=None):
        """Sign a proof.

        claims_override and raw_payload exist so the suite can construct the
        malformed tokens a Verifier has to refuse.  claims_override merges into
        the claim set, with the OMIT sentinel removing a claim; raw_payload
        replaces the serialized payload entirely, which is the only way to put
        a repeated member name on the wire.  A conforming Attester uses neither.
        """
        self.counter += 1
        hdr = {"alg": alg, "typ": typ, "kid": self.kid}
        if header_extra:
            hdr.update(header_extra)
        now = int(time.time())
        body = {
            "iss": iss, "aud": aud,
            "iat": iat if iat is not None else now,
            "exp": exp if exp is not None else now + 300,
            "jti": jti or b64u(hashlib.sha256(repr((action, self.counter)).encode()).digest()[:12]),
            "ueid": eat_ueid(self.device_id, iss),
            "eat_profile": EAT_PROFILE,
            "psea_op": op,
            "psea_tier": tier,
            "psea_payload_hash": override_payload_hash or payload_hash(action),
            "psea_counter": counter if counter is not None else self.counter,
            "psea_uv": {"verified": uv, "method": uv_method},
            "psea_proof_version": proof_version,
        }
        if user_hash is not None:
            body["psea_user_hash"] = user_hash
        if claims_override:
            for k, val in claims_override.items():
                if val is OMIT:
                    body.pop(k, None)
                else:
                    body[k] = val
        h = b64u(json.dumps(hdr, separators=(",", ":")).encode())
        payload_bytes = (raw_payload if raw_payload is not None
                         else json.dumps(body, separators=(",", ":")).encode())
        p = b64u(payload_bytes)
        signing_input = f"{h}.{p}".encode()
        if alg == "none":
            return f"{h}.{p}."
        der = self.priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{h}.{p}.{b64u(sig)}"


class Refusal(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class _DuplicateMember(Exception):
    """Raised by the parse hook; converted to a Refusal by the caller."""

    def __init__(self, name):
        super().__init__(name)
        self.name = name


def _reject_duplicate_members(pairs):
    """json object_pairs_hook: refuse a repeated member name.

    json.loads keeps the last of a repeated name and discards the earlier ones
    silently, so a producer and a Verifier reading the same bytes with different
    parsers can disagree about what was signed.  RFC 8259 Section 4 says names
    SHOULD be unique and that behaviour is unpredictable when they are not;
    unpredictable is not something a Verifier may resolve by guessing.  Applied
    to the protected header and the payload, and recursively to nested objects.
    """
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise _DuplicateMember(k)
        seen.add(k)
    return dict(pairs)


def _type_matches(value, declared):
    if declared == "string":
        return isinstance(value, str)
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "object":
        return isinstance(value, dict)
    if declared == "integer":
        # bool is a subclass of int in Python, but a JSON boolean is not a JSON
        # integer.  A float is refused outright rather than accepted when its
        # fractional part is zero: Section 2.5 restricts payload numbers to JSON
        # integers, and src/jcs.py refuses floats on the same ground.
        return isinstance(value, int) and not isinstance(value, bool)
    raise Refusal("SCHEMA_INTERNAL", f"unknown declared type {declared!r}")


def _type_name(value):
    return "boolean" if isinstance(value, bool) else type(value).__name__


def _validate_value(where, value, spec):
    """Enforce one node of the Section 3.5 schema.  Every failure is a Refusal."""
    if "type" in spec and not _type_matches(value, spec["type"]):
        raise Refusal("SCHEMA_TYPE",
                      f"{where}: expected {spec['type']}, got {_type_name(value)}")

    if "enum" in spec and value not in spec["enum"]:
        raise Refusal("SCHEMA_ENUM", f"{where}: {value!r} not among declared values")

    if isinstance(value, str):
        if "minLength" in spec and len(value) < spec["minLength"]:
            raise Refusal("SCHEMA_MIN_LENGTH",
                          f"{where}: length {len(value)} below declared minimum "
                          f"{spec['minLength']}")
        if "maxLength" in spec and len(value) > spec["maxLength"]:
            raise Refusal("SCHEMA_MAX_LENGTH",
                          f"{where}: length {len(value)} above declared maximum "
                          f"{spec['maxLength']}")
        # fullmatch, not match: Python's "$" also matches immediately before a
        # trailing newline, so re.match would accept a 44-character ueid with a
        # "\n" glued on the end.  Every pattern here is anchored in the schema
        # and must hold over the whole string.
        if "pattern" in spec and re.fullmatch(spec["pattern"], value) is None:
            raise Refusal("SCHEMA_PATTERN", f"{where}: does not match declared pattern")

    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in spec and value < spec["minimum"]:
            raise Refusal("SCHEMA_MINIMUM",
                          f"{where}: {value} below declared minimum {spec['minimum']}")
        if "maximum" in spec and value > spec["maximum"]:
            raise Refusal("SCHEMA_MAXIMUM",
                          f"{where}: {value} above declared maximum {spec['maximum']}")

    if isinstance(value, dict):
        for member in spec.get("required", ()):
            if member not in value:
                raise Refusal("SCHEMA_MISSING_MEMBER", f"{where}.{member}")
        for member, sub in spec.get("properties", {}).items():
            if member in value:
                _validate_value(f"{where}.{member}", value[member], sub)


def validate_claim_set(body):
    """Section 3.5, the whole of it, over an already-parsed payload.

    additionalProperties: false first, then the REQUIRED list, then the declared
    type / pattern / enum / range / sub-member constraints of every claim
    present.  Runs before any claim is given meaning, so no later stage has to
    defend itself against a claim of the wrong shape.
    """
    if not isinstance(body, dict):
        raise Refusal("SCHEMA_TYPE", f"payload: expected object, got {_type_name(body)}")

    unknown = sorted(set(body) - DECLARED_CLAIMS)
    if unknown:
        raise Refusal("SCHEMA_UNKNOWN_CLAIM", ", ".join(unknown))

    missing = sorted(REQUIRED_CLAIMS - set(body))
    if missing:
        raise Refusal("SCHEMA_MISSING_CLAIM", ", ".join(missing))

    for name in sorted(body):
        spec = CLAIM_SCHEMA[name]
        if name in _ENUM_REPORTED_ELSEWHERE:
            spec = {k: v for k, v in spec.items() if k != "enum"}
        _validate_value(name, body[name], spec)


class Verifier:
    """Section 3.4 header hardening, 3.5 claim set, 3.7.1 UV anchoring,
    3.13.2 fail-closed."""

    def __init__(self, enrollment: Enrollment, expected_iss, expected_aud,
                 high_assurance=False):
        self.enr = enrollment
        self.iss = expected_iss
        self.aud = expected_aud
        self.high_assurance = high_assurance
        self.seen_jti = set()
        self.last_counter = {}

    def verify(self, token: str, *, action: dict, op: str, tier: str, now=None):
        """Section 3.13.2, fail-closed: anything that is not an explicit accept
        is a refusal.

        An unexpected exception is converted to a refusal rather than allowed to
        propagate.  A reference that raises where it should refuse has failed
        open -- the caller sees a crash, not a verdict, and a crash is not a
        rejection.  Refusal itself passes through untouched.
        """
        try:
            return self._verify(token, action=action, op=op, tier=tier, now=now)
        except Refusal:
            raise
        except Exception as e:
            raise Refusal("INTERNAL_REFUSAL", f"{type(e).__name__}: {e}") from e

    def _verify(self, token: str, *, action: dict, op: str, tier: str, now=None):
        now = now if now is not None else int(time.time())
        parts = token.split(".")
        if len(parts) != 3:
            raise Refusal("MALFORMED", "not three parts")
        h_b64, p_b64, s_b64 = parts

        try:
            hdr = json.loads(b64u_dec(h_b64), object_pairs_hook=_reject_duplicate_members)
            body = json.loads(b64u_dec(p_b64), object_pairs_hook=_reject_duplicate_members)
        except _DuplicateMember as e:
            raise Refusal("DUPLICATE_MEMBER", e.name)
        except Exception as e:
            raise Refusal("MALFORMED", str(e))
        if not isinstance(hdr, dict):
            raise Refusal("MALFORMED", "header is not a JSON object")

        # --- Section 3.4 header hardening ---
        if hdr.get("alg") != "ES256":
            raise Refusal("HEADER_ALG", f"alg={hdr.get('alg')!r}, only ES256 conforms")
        if hdr.get("typ") != TYP:
            raise Refusal("HEADER_TYP", f"typ={hdr.get('typ')!r}")
        if "crit" in hdr:
            raise Refusal("HEADER_CRIT", "unrecognized crit parameter")
        if hdr.get("b64") is False:
            raise Refusal("HEADER_B64", "b64:false rejected")
        # jwk/jku/x5u are ignored, never used for key resolution.
        kid = hdr.get("kid")
        if not kid:
            raise Refusal("HEADER_KID", "absent")

        pub = self.enr.key(kid)
        if pub is None:
            raise Refusal("UNENROLLED_KEY", f"kid={kid!r} not in enrolled record")

        # --- signature ---
        if not s_b64:
            raise Refusal("SIG_ABSENT")
        raw = b64u_dec(s_b64)
        if len(raw) != 64:
            raise Refusal("SIG_MALFORMED", f"{len(raw)} bytes")
        r = int.from_bytes(raw[:32], "big"); s = int.from_bytes(raw[32:], "big")
        try:
            pub.verify(asym_utils.encode_dss_signature(r, s),
                       f"{h_b64}.{p_b64}".encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise Refusal("SIG_INVALID")

        # --- Section 3.5 claim set ---
        # Runs on the payload only after the signature over it verifies, and
        # before any claim is given meaning.  additionalProperties: false makes
        # the declared set exhaustive, so an undeclared claim is a refusal
        # rather than something a Verifier may ignore; the profile is
        # deliberately lock-step rather than ignore-unknown.  The declared
        # types, patterns, enums, ranges and required sub-members are enforced
        # here too, so every stage below reads a claim whose shape is already
        # established rather than one it has to defend itself against.
        validate_claim_set(body)
        if body.get("eat_profile") != EAT_PROFILE:
            raise Refusal("EAT_PROFILE_MISMATCH", repr(body.get("eat_profile")))

        # --- version ---
        if body.get("psea_proof_version") != PROOF_VERSION:
            raise Refusal("UNKNOWN_VERSION", repr(body.get("psea_proof_version")))

        # --- cross-replay binding ---
        if body.get("iss") != self.iss:
            raise Refusal("ISS_MISMATCH")
        if body.get("aud") != self.aud:
            raise Refusal("AUD_MISMATCH")
        if body.get("psea_op") != op:
            raise Refusal("OP_MISMATCH", f"token={body.get('psea_op')!r} requested={op!r}")
        if body.get("psea_tier") != tier:
            raise Refusal("TIER_MISMATCH")

        # --- freshness ---
        if body.get("exp") is None or now >= body["exp"]:
            raise Refusal("EXPIRED")
        if body.get("iat") is None or body["iat"] > now + 60:
            raise Refusal("IAT_FUTURE")

        # --- one-time use ---
        jti = body.get("jti")
        if not jti:
            raise Refusal("JTI_ABSENT")
        if jti in self.seen_jti:
            raise Refusal("JTI_REPLAY")
        ctr = body.get("psea_counter")
        if ctr is None:
            raise Refusal("COUNTER_ABSENT")
        if kid in self.last_counter and ctr <= self.last_counter[kid]:
            raise Refusal("COUNTER_NOT_MONOTONIC")

        # --- Section 3.7.1 user verification ---
        uv = body.get("psea_uv")
        if not isinstance(uv, dict):
            raise Refusal("UV_ABSENT")
        if uv.get("verified") is not True:
            raise Refusal("UV_NOT_VERIFIED")
        attested = self.enr.uv_enforced(kid)
        if attested is False:
            raise Refusal("UV_CONTRADICTED_BY_ATTESTATION")
        anchoring = "attested" if attested is True else "asserted"
        if anchoring == "asserted" and self.high_assurance:
            raise Refusal("UV_UNATTESTED_HIGH_ASSURANCE")

        # --- Section 3.13.2 action binding, fail-closed ---
        try:
            recomputed = payload_hash(action)
        except NonConformingPayload as e:
            raise Refusal("PAYLOAD_NON_CONFORMING", str(e))
        if body.get("psea_payload_hash") != recomputed:
            raise Refusal("DIGEST_MISMATCH")

        self.seen_jti.add(jti)
        self.last_counter[kid] = ctr

        return {
            "result": "VERIFIED",
            "uv_anchoring": anchoring,
            "principal_ref": body.get("psea_user_hash"),
            "enrolled_principal": self.enr.principal(kid),
            "digest_b64_std": body["psea_payload_hash"],
            "digest_octets": base64.b64decode(body["psea_payload_hash"]),
        }
