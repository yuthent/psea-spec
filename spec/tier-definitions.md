# PSEA Tier Definitions

> Formal definition of the four PSEA enforcement tiers — Passive (P), Silent (S),
> Explicit (E), and Authoritative (A) — including their cryptographic preconditions,
> payload structure, and verification logic.
>
> Companion to **draft-yossif-psea-01**, §"Core Principles of PSEA".

This document is normative for the public PSEA model. It does not prescribe the
choice of biometric modality, device-attestation provider, or transport. Any
implementation that satisfies the preconditions, payload contract, and verifier
algorithm in this document is a conforming implementation.

---

## 1. Conventions and Notation

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in
this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174).

ABNF (RFC 5234) is used to describe payload grammar. Pseudocode uses a
Python-ish style with explicit type annotations for clarity.

Symbols used throughout:

| Symbol | Meaning |
|--------|---------|
| `H(x)` | SHA-256 of byte string `x` |
| `JCS(x)` | RFC 8785 JSON Canonicalization Scheme of object `x` |
| `Sig_K(x)` | ECDSA-P256 signature over `H(x)` using private key `K` |
| `K_d` | Device-bound private key (non-exportable) |
| `K_a` | Per-action private key, biometric-gated |
| `t_now` | Current monotonic time on the trust-anchor device, milliseconds |
| `n_d` | Monotonic per-device action counter (uint64) |
| `chain_n` | Hash-chain head at action `n` |

---

## 2. Tier Summary

| Tier | Code | Biometric | Verifier checks | Use Case |
|------|------|-----------|-----------------|----------|
| **Passive** | P | none | structural only | risk signal, fraud scoring |
| **Silent** | S | session-cached | structural + session signature | low-friction confirmations |
| **Explicit** | E | fresh per action | structural + signature + chain | standard transactions |
| **Authoritative** | A | fresh per action | structural + signature + chain + sync authorize | high-value, regulated |

The tier set is exhaustive and totally ordered: `P < S < E < A` by enforcement
strength. A verifier MUST reject a proof whose declared tier is lower than the
risk class associated with the requested action.

---

## 3. Common Preconditions (all tiers)

Before any tier can produce a valid proof, the device MUST have completed
enrollment and be in one of the trust states defined in
[`state-transitions.md`](./state-transitions.md). Specifically:

```
PRE_COMMON ::=
  device_state ∈ { ENROLLED, ENROLLED_DEGRADED }
  AND device_attestation_chain.verified == TRUE
  AND device_attestation.not_expired == TRUE
  AND tamper_signal.elevated == FALSE
  AND replay_guard.counter_monotonic == TRUE
```

If `PRE_COMMON` does not hold, the device MUST refuse to issue a proof at any
tier and SHOULD surface a `TRUST_REVOKED` or `ATTESTATION_EXPIRED` error to the
relying application.

---

## 4. Tier P — Passive

### 4.1 Semantics

A Passive proof asserts only that the requesting device is currently in a
trusted state. It carries no human-presence claim and no per-action signature.
Passive proofs are intended for **risk scoring and fraud telemetry** — they
MUST NOT be used to authorize a sensitive action.

### 4.2 Preconditions

```
PRE_P ::= PRE_COMMON
```

### 4.3 Payload

```abnf
P-Proof   = tier "|" device-id "|" timestamp "|" trust-state-hash
tier      = "P"
device-id = 32HEXDIG          ; H(device_public_key) hex
timestamp = 1*DIGIT            ; t_now, ms
trust-state-hash = 64HEXDIG    ; H(JCS(trust_state_snapshot))
```

There is **no signature** at tier P. Integrity is established only by the
relying server cross-checking the claimed `device-id` and `trust-state-hash`
against its stored value for the device.

### 4.5 Verifier Pseudocode

```python
def verify_passive(p: PassiveProof, action_class: RiskClass) -> Result:
    if action_class > RiskClass.LOW:
        return Result.REJECT_INSUFFICIENT_TIER
    if not server_known_device(p.device_id):
        return Result.REJECT_UNKNOWN_DEVICE
    if not server_trust_state_matches(p.device_id, p.trust_state_hash):
        return Result.REJECT_STATE_DRIFT
    if abs(t_now() - p.timestamp) > MAX_CLOCK_SKEW_MS:
        return Result.REJECT_TIMESTAMP_OUT_OF_RANGE
    return Result.ACCEPT
```

---

## 5. Tier S — Silent (session-cached)

### 5.1 Semantics

A Silent proof is signed by a session-bound key whose unlock was gated by a
biometric event at session start. The biometric is cached for the lifetime of a
single session — typically minutes, never crossing process boundaries.

Silent proofs are appropriate for **batched low-friction confirmations** where
the user has already presented a biometric for the parent flow.

### 5.2 Preconditions

```
PRE_S ::= PRE_COMMON
       AND session.biometric_unlocked_at + SESSION_TTL > t_now
       AND session.action_index <= SESSION_MAX_ACTIONS
       AND session.process_id == current_process_id
```

`SESSION_TTL` and `SESSION_MAX_ACTIONS` are implementation-defined; verifiers
MUST honor the value supplied in the verifier registry for the tenant.

### 5.3 Payload

```abnf
S-Proof   = tier "|" device-id "|" session-id "|" action-hash "|" timestamp "|" signature
tier      = "S"
session-id = 32HEXDIG          ; opaque ephemeral session identifier
action-hash = 64HEXDIG         ; H(JCS(action_request))
signature  = base64url         ; ECDSA-P256 over H(payload-without-sig)
```

### 5.5 Verifier Pseudocode

```python
def verify_silent(p: SilentProof, action_request: ActionRequest,
                  action_class: RiskClass) -> Result:
    if action_class > RiskClass.MEDIUM:
        return Result.REJECT_INSUFFICIENT_TIER
    if not pre_common_for(p.body.device_id):
        return Result.REJECT_PRECONDITION
    expected_action_hash = hex(H(JCS(action_request)))
    if p.body.action_hash != expected_action_hash:
        return Result.REJECT_ACTION_BINDING
    pubkey = lookup_session_pubkey(p.body.session_id)
    if pubkey is None:
        return Result.REJECT_UNKNOWN_SESSION
    if not ECDSA_P256.verify(pubkey, H(JCS(p.body)), b64u_decode(p.signature)):
        return Result.REJECT_BAD_SIGNATURE
    return Result.ACCEPT
```

A verifier MUST also enforce a per-session monotonic action index if the
deployment requires defense against intra-session replay. The index MAY be
delivered out-of-band in a session-batch envelope (see
[`/api-contracts/openapi.yaml`](../api-contracts/openapi.yaml)).

---

## 6. Tier E — Explicit

### 6.1 Semantics

An Explicit proof requires a **fresh biometric event** at the moment of action
approval. The signing key is non-exportable and biometric-gated; an attacker
cannot produce a valid Explicit proof without coercing a live presentation
attack against the trust-anchor device.

Explicit proofs MAY be queued for asynchronous server sync. The action
completes locally on biometric success; the server-side counter and hash chain
catch up later.

### 6.2 Preconditions

```
PRE_E ::= PRE_COMMON
      AND biometric_assertion.fresh == TRUE
      AND biometric_assertion.timestamp + BIOMETRIC_FRESHNESS > t_now
      AND replay_guard.counter == n_d
      AND chain_n.head_known == TRUE
```

`BIOMETRIC_FRESHNESS` is implementation-defined; verifiers MUST honor the
value supplied in the verifier registry for the tenant.

### 6.3 Payload

The payload is a structured JSON object as defined in
[`proof-token-format.md`](./proof-token-format.md). Its key fields:

```abnf
E-Body =
  "tier"            ":" %s"E"
  "deviceId"        ":" hex32
  "actionHash"      ":" hex64
  "biometricRef"    ":" biometric-block
  "attestationRef"  ":" attestation-ref
  "counter"         ":" 1*DIGIT
  "chainPrev"       ":" hex64
  "chainEntry"      ":" hex64
  "timestamp"       ":" 1*DIGIT

E-Proof = E-Body "+" jws-signature
```

`chainEntry = H(chainPrev || JCS(E-Body without chainEntry))`

### 6.5 Verifier Pseudocode

```python
def verify_explicit(p: ExplicitProof, action_request: ActionRequest,
                    action_class: RiskClass) -> Result:
    if action_class > RiskClass.HIGH:
        return Result.REJECT_INSUFFICIENT_TIER
    if p.body["actionHash"] != hex(H(JCS(action_request))):
        return Result.REJECT_ACTION_BINDING
    pubkey = lookup_device_pubkey(p.body["deviceId"])
    if pubkey is None:
        return Result.REJECT_UNKNOWN_DEVICE
    if not jws_verify(pubkey, p.body, p.signature):
        return Result.REJECT_BAD_SIGNATURE
    if p.body["counter"] <= server_counter(p.body["deviceId"]):
        return Result.REJECT_REPLAY
    expected_entry = hex(H(server_chain_head(p.body["deviceId"])
                          + JCS_without(p.body, "chainEntry")))
    if p.body["chainEntry"] != expected_entry:
        return Result.REJECT_CHAIN_BROKEN
    if not biometric_ref_acceptable(p.body["biometricRef"]):
        return Result.REJECT_BIOMETRIC
    advance_server_counter(p.body["deviceId"], p.body["counter"])
    advance_server_chain(p.body["deviceId"], p.body["chainEntry"])
    return Result.ACCEPT
```

If the server-side check fails with `REJECT_REPLAY`, `REJECT_CHAIN_BROKEN`, or
`REJECT_BAD_SIGNATURE`, the verifier MUST raise a fraud alert and SHOULD
trigger a trust-state transition to `TAMPERED` for the affected device (see
[`state-transitions.md`](./state-transitions.md)).

---

## 7. Tier A — Authoritative

### 7.1 Semantics

An Authoritative proof is functionally a Tier E proof with two additional
requirements:

1. **Synchronous server authorization** — the relying server returns the
   final `APPROVED` / `DENIED` decision *before* the action is executed
   client-side. There is no async path.
2. **Full audit trail** — the verifier MUST persist the entire proof body
   plus signature in append-only storage, with an external Merkle anchor (e.g.,
   periodic hash anchoring to a transparency log).

### 7.2 Preconditions

```
PRE_A ::= PRE_E
      AND network.reachable == TRUE
      AND server_authorize_endpoint.healthy == TRUE
```

A device that fails `network.reachable` MUST NOT issue a Tier A proof. The
relying application MUST surface `OFFLINE_AUTHORITATIVE_BLOCKED` to the user
and offer no fallback to a lower tier without explicit human selection.

### 7.3 Payload

Identical to Tier E, with `tier = "A"` and an additional `authorizationId`
field returned by the server in the synchronous response. Full schema in
[`proof-token-format.md`](./proof-token-format.md).

### 7.5 Verifier Pseudocode

The Authoritative verifier runs every check from §6.5 plus:

```python
def verify_authoritative_extras(p: AuthoritativeProof) -> Result:
    if not policy_allows_action(p.body["actionHash"], p.body["deviceId"]):
        return Result.REJECT_POLICY_DENY
    if not audit_log.append_atomic(p.body, p.signature):
        return Result.REJECT_AUDIT_FAILURE
    if not merkle_anchor.schedule(p.body["chainEntry"]):
        return Result.REJECT_ANCHOR_FAILURE
    return Result.ACCEPT
```

A failure of `audit_log.append_atomic` MUST cause the synchronous response to
be `DENIED` — an action that cannot be audited cannot be authorized.

---

## 8. Negotiation and Tier Mapping

Risk classes map to minimum acceptable tiers as follows:

| Risk class | Minimum tier |
|-----------|--------------|
| LOW       | P            |
| MEDIUM    | S            |
| HIGH      | E            |
| CRITICAL  | A            |

A relying party MAY choose to require a higher tier than the minimum, but MUST
NOT accept a lower tier than the table specifies.

When the relying party's policy is unspecified, the verifier MUST default to
**A** (the strictest tier). This default is chosen because the failure mode of
under-enforcement (unauthorized execution) is strictly worse than the failure
mode of over-enforcement (legitimate user friction).

---

## 9. Conformance Checklist

A conforming PSEA verifier MUST:

- [ ] Reject any proof that fails `PRE_COMMON` for its claimed device.
- [ ] Implement all four tiers' verification algorithms exactly as specified.
- [ ] Enforce the risk-class → tier mapping in §8.
- [ ] Default to Tier A when policy is unspecified.
- [ ] Surface tier-specific rejection codes (no generic "AUTH_FAILED").
- [ ] Pass every reference test vector in
      [`/test-vectors/`](../test-vectors/).

