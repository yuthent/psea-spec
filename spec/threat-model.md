# PSEA Threat Model

> STRIDE-style threat model: threats addressed, threats explicitly out of
> scope, and assumptions about the trust-anchor device.
>
> Companion to **draft-yossif-psea-00**, §"The Broken Assumption of Sessions"
> and §"The Authority Gap".

---

## 1. Scope and Method

This document follows the STRIDE taxonomy (Spoofing, Tampering, Repudiation,
Information Disclosure, Denial of Service, Elevation of Privilege) applied to
the four data-flow boundaries that exist in any PSEA deployment:

```
  ┌──────────────┐   (1)    ┌──────────────┐   (2)    ┌──────────────┐
  │     User     │ <──────► │  Trust-Anchor │ <──────► │   Verifier   │
  │  (presence)  │  bio     │    Device     │  proof   │   (server)   │
  └──────────────┘          └──────┬───────┘          └──────┬───────┘
                                   │ (3) attestation         │
                                   ▼                         │ (4) audit
                            ┌──────────────┐                 ▼
                            │ Platform OS  │          ┌──────────────┐
                            │ (Android/iOS)│          │ Audit / Log  │
                            └──────────────┘          └──────────────┘
```

Boundaries:

1. **User ↔ Device** — biometric capture, liveness, intent.
2. **Device ↔ Verifier** — proof transport, replay, ordering.
3. **Device ↔ OS** — attestation, key isolation, anti-tamper.
4. **Verifier ↔ Audit** — append-only ledger, anchoring, retention.

For every threat, this document records: *category*, *boundary*,
*description*, *mitigation in the PSEA model*, and *residual risk*.

---

## 2. Trust-Anchor Device Assumptions

PSEA's security guarantees depend on the trust-anchor device honoring these
properties. If any of them is false on a given device, that device is outside
the PSEA threat model and SHOULD NOT be enrolled.

| # | Assumption                                                                 |
|---|----------------------------------------------------------------------------|
| A1| Hardware-backed key storage exists (Android Keystore TEE/StrongBox, Apple Secure Enclave, TPM 2.0, or equivalent). |
| A2| The OS provides a verified boot chain that resists modification. |
| A3| The biometric subsystem is implemented in a TEE / Secure Enclave with a hardware sensor not directly addressable from user space. |
| A4| The OS provides device attestation (Android Key Attestation or iOS App Attest) signed by a vendor root the verifier can pin. |
| A5| A monotonic counter usable as a freshness/replay anchor is available. |
| A6| The trust-anchor implementation runs as an application whose binary signature is bound to the attested cert chain. |

Devices that do not meet A1–A6 (jailbroken, custom ROM without verified boot,
emulator, devices with broken keystore implementations) SHOULD be rejected at
enrollment with `ATTESTATION_NOT_TRUSTWORTHY`.

---

## 3. STRIDE Threats Addressed

### 3.1 Spoofing (S)

#### S1 — Replay of a captured proof
- **Boundary:** 2
- **Threat:** Attacker captures a previously valid Tier E/A proof and
  re-submits it.
- **Mitigation:** Monotonic per-device `counter` + hash chain (`chainPrev`,
  `chainEntry`) verified server-side. A replay regresses the counter or
  breaks the chain; the verifier rejects with `REJECT_REPLAY` and raises a
  fraud alert.
- **Residual risk:** None for in-band replay against the same verifier.
  Cross-tenant or cross-verifier replay is impossible by construction
  (per-device key + verifier-pinned attestation nonce).

#### S2 — Forged biometric (presentation attack)
- **Boundary:** 1
- **Threat:** Attacker presents a photo, mask, recording, or deepfake.
- **Mitigation:** PSEA delegates liveness to the platform biometric
  subsystem (Android BiometricPrompt with Class 3, Apple Face ID, WebAuthn
  user-verification) and records the modality + liveness method in the
  proof. Presentation attacks at the platform level are out of scope of
  this spec but are bounded by the platform's certified anti-spoofing
  mechanisms.
- **Residual risk:** Bounded by platform liveness defenses. PSEA
  contributes by *binding* the biometric event to a specific action, so
  even a successful presentation attack only authorizes the one action,
  not a session.

#### S3 — Impersonation via session theft
- **Boundary:** 2
- **Threat:** Attacker steals a session cookie / bearer token.
- **Mitigation:** Tier E and Tier A do not rely on session state. A stolen
  session cannot produce a Tier E or A proof because it cannot exercise
  the biometric-gated key on the trust-anchor device.
- **Residual risk:** An attacker who has stolen a session can still see
  data accessible via the session (read paths). PSEA does not protect
  read paths — see §4 (out of scope).

#### S4 — Cloned device
- **Boundary:** 3
- **Threat:** Attacker extracts key material and clones it to another
  device.
- **Mitigation:** Hardware-backed keys (A1) are non-exportable. A cloned
  device would have to forge fresh attestation, which fails verifier-side
  pinning. If the original device is later used, the chain on one of the
  two will break, triggering `serverRevoke`.
- **Residual risk:** A nation-state attacker who can break the secure
  element is out of scope.

### 3.2 Tampering (T)

#### T1 — Modified trust-anchor application
- **Boundary:** 3
- **Threat:** Attacker modifies the SDK binary or repackages it.
- **Mitigation:** `packageBinding.enforcement = "strict-cert-chain"` ties
  the package id to the cert chain extension that the platform vouches for.
  A modified or repackaged binary fails attestation.
- **Residual risk:** Sandbox tenants accept `client-claim` and rely on
  audit-log surveillance instead of cert-chain enforcement (see
  `proof-token-format.md` §3.1).

#### T2 — Hooking / dynamic instrumentation (Frida, Xposed)
- **Boundary:** 3
- **Threat:** Attacker attaches a runtime instrumentation framework and
  hooks the trust-anchor process to bypass biometric or capture key
  material.
- **Mitigation:** Trust-anchor implementations MUST run anti-tamper checks
  on every issuance attempt; positive detection raises `tamperDetected`
  and transitions the device to `TAMPERED` (`state-transitions.md` §4.3).
- **Residual risk:** Anti-tamper is a defense in depth, not a defense in
  full. The hardware-backed key still cannot be extracted, so even a hook
  cannot forge a valid signature off-device.

#### T3 — Tampered chain (out-of-order issuance)
- **Boundary:** 2/3
- **Threat:** Attacker reorders or omits proofs to mask an action.
- **Mitigation:** Hash chain (`chainPrev`, `chainEntry`) is verified
  server-side. Any reordering or omission breaks the chain and triggers
  `REJECT_CHAIN_BROKEN` plus `serverRevoke`.
- **Residual risk:** If the verifier itself is compromised, chain
  enforcement collapses — see T4.

#### T4 — Tampered audit ledger
- **Boundary:** 4
- **Threat:** Insider modifies the verifier's audit log to remove
  evidence of an action.
- **Mitigation:** Periodic Merkle anchoring of `chainEntry` to a
  transparency log or independent witness (e.g., RFC 9162 CT log,
  Sigstore Rekor, blockchain anchor). The anchor cadence is policy and
  SHOULD be ≤ 1 hour for regulated tenants.
- **Residual risk:** Actions taken inside the anchor window can still be
  partially obscured. The anchor cadence must be tuned to the regulatory
  evidence requirement.

### 3.3 Repudiation (R)

#### R1 — User claims they never approved an action
- **Boundary:** 1
- **Threat:** A user disputes a Tier E or Tier A action.
- **Mitigation:** Each Tier E/A proof carries a fresh biometric assertion
  bound to the action hash, signed by the device-bound key. The proof is
  by construction non-repudiable: the user could only have produced it if
  they (a) presented a live biometric, (b) on the enrolled device,
  (c) specifically for this action.
- **Residual risk:** None at the cryptographic level. The user can still
  claim coercion — that is a legal, not a technical, concern.

#### R2 — Operator claims an action was never authorized
- **Boundary:** 4
- **Threat:** An operator denies that a recorded action was ever served
  to the verifier.
- **Mitigation:** Audit log entries are append-only, signed with the
  verifier's key, and anchored externally (T4).
- **Residual risk:** Same as T4.

### 3.4 Information Disclosure (I)

#### I1 — Biometric template leakage
- **Boundary:** 3
- **Threat:** Attacker exfiltrates biometric templates from the device.
- **Mitigation:** PSEA does not transmit biometric templates. The
  `BiometricBlock` carries only platform-issued *attestations* of a
  successful biometric event (e.g., Android `BiometricPrompt`'s
  `CryptoObject` ref or WebAuthn `userVerified` flag). Templates remain
  in the secure subsystem (A3).
- **Residual risk:** Platform-level vulnerabilities in the biometric
  subsystem are out of scope.

#### I2 — PII in proof token
- **Boundary:** 2
- **Threat:** A malicious or buggy issuer includes PII in `actionHash`
  pre-image or `policy.actionType`.
- **Mitigation:** This spec does not put PII anywhere in the proof token.
  Implementations MUST use opaque action hashes (already-hashed) and
  MUST NOT embed user identifiers, phone numbers, addresses, or document
  numbers in `policy.actionType`.
- **Residual risk:** Implementer discipline. Verifiers SHOULD reject
  `actionType` values that look like raw PII (heuristic check on length
  and pattern).

#### I3 — Cross-tenant correlation
- **Boundary:** 2
- **Threat:** Same device produces proofs across tenants; an attacker
  correlates `deviceId`.
- **Mitigation:** `deviceId = H(device_public_key)`. Implementations MAY
  derive a separate device key per tenant via a per-tenant salt during
  enrollment. When done, `deviceId` is per-tenant and cannot be used to
  correlate.
- **Residual risk:** Implementations that share a single `K_d` across
  tenants accept the correlation risk.

### 3.5 Denial of Service (D)

#### D1 — Verifier flooding
- **Boundary:** 2
- **Threat:** Attacker floods `/verify` with invalid proofs.
- **Mitigation:** Per-`deviceId` rate limiting on the verifier, with
  back-pressure into the trust-anchor SDK. Repeated failures trigger
  `serverRevoke`.
- **Residual risk:** A botnet of legitimately enrolled devices can still
  produce DoS pressure. Tenants SHOULD apply WAF / per-tenant quotas.

#### D2 — Counter exhaustion
- **Boundary:** 3
- **Threat:** Attacker forces a device to burn through its counter
  (e.g., by spamming silent issuance attempts).
- **Mitigation:** `counter` is a uint64. Even at 1,000 issuances/sec it
  takes ~585 million years to exhaust. The practical concern is the
  per-session (Tier S) action ceiling: SESSION_MAX_ACTIONS = 128 caps the
  blast radius.
- **Residual risk:** Negligible.

#### D3 — Synchronous Tier-A unavailability
- **Boundary:** 2
- **Threat:** Verifier `/authorize` becomes unreachable; legitimate
  Tier-A actions cannot complete.
- **Mitigation:** Tier A is *deliberately* unavailable when the verifier
  is unreachable — the alternative would be a security regression. The
  trust-anchor device MUST surface `OFFLINE_AUTHORITATIVE_BLOCKED` and
  SHOULD NOT silently downgrade to Tier E.
- **Residual risk:** Operational. Tenants SHOULD provision the
  `/authorize` endpoint with high availability targets.

### 3.6 Elevation of Privilege (E)

#### E1 — Tier downgrade attack
- **Boundary:** 2
- **Threat:** Attacker (man-in-the-middle on the relying app, not the
  signed proof) substitutes a Tier P proof for a request that requires
  Tier A.
- **Mitigation:** The verifier holds the policy; `header.tier` is
  cryptographically bound into the signed body. A swap to a different
  proof cannot match the action hash that the verifier independently
  computes.
- **Residual risk:** None at the cryptographic level. RP-side bugs that
  accept any tier are an implementer concern; the conformance checklist
  in `tier-definitions.md` §9 forbids this.

#### E2 — Privilege escalation through session re-binding
- **Boundary:** 2
- **Threat:** Attacker takes a Tier S session token from one device and
  uses it on another.
- **Mitigation:** Session signing key is non-exportable and lives only in
  the originating device's keystore. A different device cannot produce
  the matching signature.
- **Residual risk:** Same as S4 (cloned device).

---

## 4. Threats Explicitly Out of Scope

PSEA is a *narrow* model — it addresses execution-time authority
verification and nothing else. The following threats are real but are not
within the scope of this specification:

| #  | Threat                                | Why out of scope |
|----|---------------------------------------|------------------|
| O1 | Identity proofing / KYC               | PSEA assumes a separately verified identity. Customers bring their own KYC or use the in-person enrollment path. |
| O2 | Account recovery                      | Recovery is a policy decision per relying party. PSEA only mandates that recovery cannot reuse revoked key material. |
| O3 | Phishing of the user                  | A user who consents to authorize a malicious action consents to authorize it. PSEA proves the user did approve — it cannot prove the user *understood*. |
| O4 | Coercion / duress                     | Out of cryptographic scope. Implementations MAY add duress codes; this spec does not require them. |
| O5 | Read-path access control              | PSEA proves the user authorized a *write*. Read-path authorization is the relying party's session/RBAC concern. |
| O6 | Endpoint malware reading user inputs  | If the device is fully compromised, the user's intent itself is compromised. Hardware-backed key isolation limits the blast radius but does not eliminate it. |
| O7 | Social engineering of the operator    | A malicious operator who issues `serverRevoke` against a legitimate device, or who modifies tenant policy, is outside the scope of a device-side spec. |
| O8 | Side-channel attacks on the secure element | Bounded by A1/A3. Defenses are the platform vendor's responsibility. |
| O9 | Network-level metadata analysis       | An attacker who can observe traffic timing learns "user did some PSEA-protected action" but not the content. PSEA does not attempt to hide the existence of the protocol. |
| O10| Pre-enrollment attacks                | Until a device transitions out of `UNTRUSTED`, PSEA makes no claim. Pre-enrollment is the relying party's onboarding problem. |

A relying party that needs to defend against O1–O10 MUST use additional
controls; PSEA composes with them but does not replace them.

---

## 5. Residual-Risk Summary

| Threat ID | Residual after PSEA | Recommended compensating control |
|-----------|---------------------|----------------------------------|
| S2 | Bounded by platform liveness | Use Class-3 biometrics; reject `liveness.method = passive` for high-risk RPs. |
| S4 | Bounded by hardware key isolation | Pin attestation roots; monitor for chain breaks. |
| T2 | Bounded by hardware key isolation | Anti-tamper SDK + telemetry on tamper signals. |
| T4 | Bounded by anchor cadence | ≤ 1 h external Merkle anchor for regulated tenants. |
| I3 | Per-tenant key derivation optional | Use per-tenant salt at enrollment when correlation matters. |
| O1–O10 | Out of scope | Combine PSEA with KYC, RBAC, fraud monitoring, etc. |

---

## 6. Open Questions and Future Work

- **Multi-user devices.** This version assumes one human per trust-anchor
  device. Shared-device flows (clinical workstations, kiosks) require an
  extension that binds proofs to a specific human within a device. A
  future minor revision will define a `humanId` block.
- **Post-quantum signatures.** This version mandates ES256. A migration
  path to a hybrid scheme (ES256 + ML-DSA) is planned for v2.
- **Federated verification.** Cross-tenant proof acceptance (e.g., one
  bank's PSEA proof honored by another's verifier) is not in v1.
