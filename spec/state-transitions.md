# PSEA Trust State Machine

> Formal state machine for PSEA trust states, allowed transitions, and the
> trigger conditions that drive each transition.
>
> Companion to **draft-yossif-psea-00**, §"Device-Bound Trust" and §"Human
> Presence Assurance".

---

## 1. State Set

A PSEA-conforming trust-anchor device occupies exactly one of the following
states at any given time:

| State                | Meaning                                                         |
|----------------------|-----------------------------------------------------------------|
| `UNTRUSTED`          | Initial state. No enrollment has been completed. No proofs may be issued. |
| `ENROLLING`          | Enrollment in progress. A nonce + attestation chain are in flight to the verifier; no proofs may be issued. |
| `ENROLLED`           | Fully trusted. All four tiers may be issued. |
| `ENROLLED_DEGRADED`  | Trusted but with elevated risk signals (e.g., near-expiry attestation, brief tamper signal that cleared). Tier P, S, E may be issued; Tier A blocked until elevated to `ENROLLED`. |
| `TAMPERED`           | Active tamper signal detected (root, hook, debugger, signature mismatch, broken hash chain). All issuance blocked. Recovery requires re-enrollment from a clean state. |
| `REVOKED`            | Server has revoked trust for this device. All issuance blocked. Re-enrollment requires a new device key — old keys cannot be reused. |

Only `UNTRUSTED` is the legal initial state. Only `REVOKED` is terminal in the
sense that no transition out of it preserves the original device-bound key
material.

---

## 2. Transition Diagram

```
                    ┌─────────────┐
                    │  UNTRUSTED  │  <───── factory/reset
                    └──────┬──────┘
                           │ enrollStart()
                           ▼
                    ┌─────────────┐
            ┌─────► │  ENROLLING  │
            │       └──────┬──────┘
            │              │ enrollComplete(attestation, nonce)
            │              │
            │              ▼
            │       ┌─────────────┐    riskUp     ┌──────────────────┐
            │       │  ENROLLED   │ ────────────► │ ENROLLED_DEGRADED│
            │       └──────┬──────┘ ◄──────────── └──────┬───────────┘
            │              │       riskCleared            │
            │              │                              │
            │ enrollRetry  │ tamperDetected               │ tamperDetected
            │ (only from   │                              │
            │  ENROLLING)  ▼                              ▼
            │       ┌─────────────┐                ┌────────────┐
            └────── │  TAMPERED   │ <───────────── │ TAMPERED   │
                    └──────┬──────┘                └────────────┘
                           │ serverRevoke
                           ▼
                    ┌─────────────┐
                    │   REVOKED   │  (terminal for original key)
                    └─────────────┘
```

ASCII rendering — the canonical machine-readable form is in §6.

---

## 3. Transition Table

Each row is `(from-state, event) → to-state`. Events not listed for a state
MUST be ignored (no state change) and SHOULD generate a structured log entry.

| # | From                | Event                       | To                  | Trigger condition |
|---|---------------------|-----------------------------|---------------------|-------------------|
| 1 | `UNTRUSTED`         | `enrollStart`               | `ENROLLING`         | User initiates enrollment; client generates `K_d`. |
| 2 | `ENROLLING`         | `enrollComplete`            | `ENROLLED`          | Server verified attestation chain + nonce; counter set to 0. |
| 3 | `ENROLLING`         | `enrollFail`                | `UNTRUSTED`         | Attestation rejected, nonce expired, or user cancelled. |
| 4 | `ENROLLING`         | `tamperDetected`            | `TAMPERED`          | Tamper check fired during enrollment. |
| 5 | `ENROLLED`          | `riskUp`                    | `ENROLLED_DEGRADED` | One or more degraded-risk conditions in §4.2. |
| 6 | `ENROLLED`          | `tamperDetected`            | `TAMPERED`          | Tamper conditions in §4.3. |
| 7 | `ENROLLED`          | `serverRevoke`              | `REVOKED`           | Verifier returned `TRUST_REVOKED` on any sync. |
| 8 | `ENROLLED_DEGRADED` | `riskCleared`               | `ENROLLED`          | All degraded conditions resolved + grace window passed. |
| 9 | `ENROLLED_DEGRADED` | `tamperDetected`            | `TAMPERED`          | Tamper detected while degraded. |
| 10| `ENROLLED_DEGRADED` | `serverRevoke`              | `REVOKED`           | Verifier revoked. |
| 11| `TAMPERED`          | `userResetWithReEnroll`     | `ENROLLING`         | Device-local recovery flow with a freshly generated `K_d`. |
| 12| `TAMPERED`          | `serverRevoke`              | `REVOKED`           | Verifier revoked while in TAMPERED. |
| 13| `REVOKED`           | `userResetWithNewKey`       | `UNTRUSTED`         | Device wiped, key material rotated, new enrollment cycle begins. |

---

## 4. Trigger Conditions (normative)

### 4.1 `riskCleared`

A device leaves `ENROLLED_DEGRADED` only when **all** of the following hold:

- No tamper signal observed for at least `RISK_CLEAR_WINDOW_MS`
  (implementation-defined).
- Device attestation has been refreshed within the last `ATTEST_REFRESH_MS`
  (implementation-defined).
- The hash chain on `K_d` is unbroken since the last successful sync.
- Clock skew between the trust-anchor device and the verifier is within
  `MAX_CLOCK_SKEW_MS` (implementation-defined).

### 4.2 `riskUp` conditions (any one triggers)

- Device attestation expires within `ATTEST_NEAR_EXPIRY_MS`
  (implementation-defined).
- Verifier returned a soft warning code (`SOFT_WARN`) on the last sync.
- Brief tamper signal that cleared within `TAMPER_TRANSIENT_MS`
  (implementation-defined).
- Network reachability has been intermittent (implementation-defined
  threshold over an implementation-defined window).

### 4.3 `tamperDetected` conditions

Implementation-defined tamper signals SHOULD include at minimum: rooting /
jailbreak detection, dynamic instrumentation or debugger detection,
application binary integrity mismatch against the value carried in the
device attestation, and hash-chain integrity violations on the device's
signing key.

### 4.4 `serverRevoke`

The verifier MAY return `TRUST_REVOKED` for any of:

- `chainEntry` does not match the expected `H(chainPrev || JCS(body))`.
- `counter` regression detected.
- `attestation.notAfter < now`.
- Operator-initiated revocation via the `/revoke` endpoint
  (`/api-contracts/openapi.yaml`).
- Repeated `REJECT_BIOMETRIC` outcomes above a per-tenant threshold.

The trust-anchor device MUST treat the next sync that returns
`TRUST_REVOKED` as a hard failure and transition to `REVOKED` immediately.

---

## 6. Machine-Readable Form

```yaml
# psea-trust-state-machine.yaml
states:
  - { name: UNTRUSTED, initial: true }
  - { name: ENROLLING }
  - { name: ENROLLED }
  - { name: ENROLLED_DEGRADED }
  - { name: TAMPERED }
  - { name: REVOKED, terminal_for_key: true }

transitions:
  - { from: UNTRUSTED,         on: enrollStart,           to: ENROLLING }
  - { from: ENROLLING,         on: enrollComplete,        to: ENROLLED }
  - { from: ENROLLING,         on: enrollFail,            to: UNTRUSTED }
  - { from: ENROLLING,         on: tamperDetected,        to: TAMPERED }
  - { from: ENROLLED,          on: riskUp,                to: ENROLLED_DEGRADED }
  - { from: ENROLLED,          on: tamperDetected,        to: TAMPERED }
  - { from: ENROLLED,          on: serverRevoke,          to: REVOKED }
  - { from: ENROLLED_DEGRADED, on: riskCleared,           to: ENROLLED }
  - { from: ENROLLED_DEGRADED, on: tamperDetected,        to: TAMPERED }
  - { from: ENROLLED_DEGRADED, on: serverRevoke,          to: REVOKED }
  - { from: TAMPERED,          on: userResetWithReEnroll, to: ENROLLING }
  - { from: TAMPERED,          on: serverRevoke,          to: REVOKED }
  - { from: REVOKED,           on: userResetWithNewKey,   to: UNTRUSTED }
```

This file is the authoritative machine-readable form. Implementations SHOULD
load it directly rather than re-derive from prose.

---

## 7. Invariants

A conforming implementation MUST preserve all of the following invariants:

- **I1** — Exactly one current state per trust-anchor device.
- **I2** — Transitions are atomic: no event partially updates state.
- **I3** — `REVOKED` is terminal *for the original key*; recovery requires a
  newly generated `K_d`.

Verifiers SHOULD audit-log every state transition with `(deviceId, fromState,
toState, event, timestamp, evidenceRef)`.
