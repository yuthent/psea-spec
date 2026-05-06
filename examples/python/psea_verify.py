#!/usr/bin/env python3
"""
PSEA reference verifier — Python.

Verify-only. Implements the algorithms in `spec/tier-definitions.md`.
Walks ../../test-vectors/ and reports PASS/FAIL per vector.

No private-key code. No signing. Reads only public keys from the test-keys
fixture.

Usage:
    pip install cryptography
    python3 psea_verify.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test-vectors"

NOW = 1_733_280_000_000  # match bootstrap-vectors.py
MAX_CLOCK_SKEW_MS = 30_000
BIOMETRIC_FRESHNESS_MS = 30_000


# ---------------------------------------------------------------------------
# Helpers


def jcs(obj: Any) -> bytes:
    """RFC 8785 JSON Canonicalization (minimal)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return urlsafe_b64decode(s + pad)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_public_key(b64u_uncompressed: str) -> ec.EllipticCurvePublicKey:
    raw = b64u_decode(b64u_uncompressed)
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("expected 65-byte uncompressed P-256 public key")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def verify_es256_raw(pub: ec.EllipticCurvePublicKey, msg: bytes,
                     raw_sig: bytes) -> bool:
    if len(raw_sig) != 64:
        return False
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    der = encode_dss_signature(r, s)
    try:
        pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Verifier registry (loaded from test-keys.json)


@dataclass
class Registry:
    keys: dict
    devices: dict          # deviceId -> dict from verifierRegistry
    pubkeys: dict          # deviceId -> EllipticCurvePublicKey
    fixed_now_ms: int

    @classmethod
    def load(cls, p: Path) -> "Registry":
        raw = json.loads(p.read_text(encoding="utf-8"))
        pubkeys = {}
        for did, entry in raw["verifierRegistry"].items():
            pubkeys[did] = load_public_key(entry["publicKey"])
        return cls(keys=raw, devices=raw["verifierRegistry"],
                   pubkeys=pubkeys, fixed_now_ms=raw["fixedTimestampMs"])


# ---------------------------------------------------------------------------
# Per-tier verifiers


RISK_TIER_MIN = {"LOW": "P", "MEDIUM": "S", "HIGH": "E", "CRITICAL": "A"}
TIER_RANK = {"P": 0, "S": 1, "E": 2, "A": 3}


def insufficient_tier(tier: str, action_class: str) -> bool:
    return TIER_RANK[tier] < TIER_RANK[RISK_TIER_MIN[action_class]]


def verify_tier_p(reg: Registry, vec: dict) -> str:
    body = vec["proofToken"]["body"]
    if insufficient_tier("P", vec["actionClass"]):
        return "REJECT_INSUFFICIENT_TIER"
    did = body["deviceId"]
    if did not in reg.devices:
        return "REJECT_UNKNOWN_DEVICE"
    if body["trustStateHash"] != reg.devices[did]["trustStateHash"]:
        return "REJECT_STATE_DRIFT"
    if abs(reg.fixed_now_ms - body["timestamp"]) > MAX_CLOCK_SKEW_MS:
        return "REJECT_TIMESTAMP_OUT_OF_RANGE"
    return "ACCEPT"


def verify_tier_s(reg: Registry, vec: dict) -> str:
    body = vec["proofToken"]["body"]
    if insufficient_tier("S", vec["actionClass"]):
        return "REJECT_INSUFFICIENT_TIER"

    expected_hash = sha256_hex(jcs(vec["input"]["actionRequest"]))
    if body["actionHash"] != expected_hash:
        return "REJECT_ACTION_BINDING"

    sess = vec["input"]["deviceState"].get("session")
    if not sess or sess.get("id") != body["sessionId"]:
        return "REJECT_UNKNOWN_SESSION"

    did = body["deviceId"]
    pub = reg.pubkeys.get(did)
    if pub is None:
        return "REJECT_UNKNOWN_DEVICE"

    sig = b64u_decode(vec["proofToken"]["signature"])
    if not verify_es256_raw(pub, jcs(body), sig):
        return "REJECT_BAD_SIGNATURE"

    return "ACCEPT"


def verify_tier_e_common(reg: Registry, vec: dict, *, allow_test: bool = False) -> str:
    body  = vec["proofToken"]["body"]
    state = vec["input"]["deviceState"]

    expected_hash = sha256_hex(jcs(vec["input"]["actionRequest"]))
    if body["actionHash"] != expected_hash:
        return "REJECT_ACTION_BINDING"

    did = body["deviceId"]
    pub = reg.pubkeys.get(did)
    if pub is None:
        return "REJECT_UNKNOWN_DEVICE"

    sig = b64u_decode(vec["proofToken"]["signature"])
    if not verify_es256_raw(pub, jcs(body), sig):
        return "REJECT_BAD_SIGNATURE"

    if body["counter"] <= state["counter"]:
        return "REJECT_REPLAY"

    body_no_chain = {k: v for k, v in body.items() if k != "chainEntry"}
    expected_entry = sha256_hex(bytes.fromhex(state["chainHead"]) + jcs(body_no_chain))
    if body["chainEntry"] != expected_entry:
        return "REJECT_CHAIN_BROKEN"
    if body["chainPrev"] != state["chainHead"]:
        return "REJECT_CHAIN_BROKEN"

    bio = body.get("biometric")
    if bio is None:
        return "REJECT_BIOMETRIC"
    age = body["timestamp"] - bio["freshness"]["capturedAt"]
    if age < 0 or age > BIOMETRIC_FRESHNESS_MS:
        return "REJECT_BIOMETRIC"

    att = body["attestation"]
    if att["source"] == "test" and not allow_test:
        return "REJECT_ATTESTATION"
    if att["notAfter"] < reg.fixed_now_ms:
        return "REJECT_ATTESTATION"
    if att["packageBinding"]["enforcement"] == "client-claim" \
            and state.get("tenantPolicy") in ("REGULATED", "STANDARD"):
        # Production policies forbid client-claim
        return "REJECT_ATTESTATION"

    return "ACCEPT"


def verify_tier_e(reg: Registry, vec: dict) -> str:
    if insufficient_tier("E", vec["actionClass"]):
        return "REJECT_INSUFFICIENT_TIER"
    return verify_tier_e_common(reg, vec)


def verify_tier_a(reg: Registry, vec: dict) -> str:
    if insufficient_tier("A", vec["actionClass"]):
        return "REJECT_INSUFFICIENT_TIER"

    state = vec["input"]["deviceState"]
    if not state.get("networkReachable") or not state.get("authorizeEndpointHealthy"):
        return "REJECT_OFFLINE_AUTHORITATIVE_BLOCKED"

    inner = verify_tier_e_common(reg, vec)
    if inner != "ACCEPT":
        return inner

    body = vec["proofToken"]["body"]
    blocked = state.get("blockedActionTypes", [])
    action_type = vec["input"]["actionRequest"].get("actionType")
    if action_type in blocked:
        return "REJECT_POLICY_DENY"

    if state.get("auditLogHealthy", True) is False:
        return "REJECT_AUDIT_FAILURE"

    return "ACCEPT"


VERIFIERS = {"P": verify_tier_p, "S": verify_tier_s,
             "E": verify_tier_e, "A": verify_tier_a}


# ---------------------------------------------------------------------------
# Test runner


def run_one(reg: Registry, vec_path: Path) -> tuple[bool, str, str]:
    vec  = json.loads(vec_path.read_text(encoding="utf-8"))
    tier = vec["proofToken"]["header"]["tier"]
    actual = VERIFIERS[tier](reg, vec)
    expected = vec["expected"]["result"]
    return (actual == expected, actual, expected)


def main() -> int:
    if not VECTORS.exists():
        print(f"FATAL: {VECTORS} missing — run tools/bootstrap-vectors.py first",
              file=sys.stderr)
        return 2
    reg = Registry.load(VECTORS / "keys" / "test-keys.json")

    files = sorted(VECTORS.glob("tier-*/*.json"))
    if not files:
        print("FATAL: no test vectors found", file=sys.stderr)
        return 2

    pass_count = fail_count = 0
    for f in files:
        ok, actual, expected = run_one(reg, f)
        marker = "PASS" if ok else "FAIL"
        rel = f.relative_to(ROOT).as_posix()
        if ok:
            pass_count += 1
            print(f"  [{marker}] {rel}  ({actual})")
        else:
            fail_count += 1
            print(f"  [{marker}] {rel}  expected={expected} actual={actual}")

    print(f"\n{pass_count} passed, {fail_count} failed, {len(files)} total")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
