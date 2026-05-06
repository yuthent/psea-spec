# PSEA Reference Test Vectors

Twenty deterministic test vectors — five per tier (P, S, E, A) — used by every
conforming PSEA verifier to demonstrate compliance.

## Layout

```
test-vectors/
├── keys/
│   └── test-keys.json            # public verifier registry (no private material)
├── tier-p/                       # five Tier-P vectors
├── tier-s/                       # five Tier-S vectors
├── tier-e/                       # five Tier-E vectors
└── tier-a/                       # five Tier-A vectors
```

## Vector schema

Every vector is a JSON document with this shape:

```jsonc
{
  "id":          "E-001-happy",
  "description": "...what the vector exercises...",
  "actionClass": "LOW | MEDIUM | HIGH | CRITICAL",
  "input": {
    "deviceState":         { /* what the verifier already knows */ },
    "biometricAssertion":  null | { /* BiometricBlock */ },
    "actionRequest":       { /* opaque RP-defined */ }
  },
  "proofToken": { "header": {...}, "body": {...}, "signature": "base64url" },
  "expected": { "result": "ACCEPT" | "REJECT_<CODE>", "...": "..." }
}
```

## Reject codes

| Code                                | Meaning                                                  |
|-------------------------------------|----------------------------------------------------------|
| `REJECT_INSUFFICIENT_TIER`          | Proof tier below the action class minimum (see tier-definitions §8). |
| `REJECT_UNKNOWN_DEVICE`             | `deviceId` is not in the verifier's enrolled-device registry. |
| `REJECT_STATE_DRIFT`                | `trustStateHash` does not match server's stored value.   |
| `REJECT_TIMESTAMP_OUT_OF_RANGE`     | `timestamp` outside the allowed clock skew.              |
| `REJECT_UNKNOWN_SESSION`            | Session referenced is unknown / expired (Tier S).        |
| `REJECT_ACTION_BINDING`             | `actionHash` does not match `H(JCS(actionRequest))`.     |
| `REJECT_BAD_SIGNATURE`              | Signature does not verify under the expected public key. |
| `REJECT_REPLAY`                     | `counter` regression (Tier E/A).                         |
| `REJECT_CHAIN_BROKEN`               | `chainPrev` or `chainEntry` does not match the chain.    |
| `REJECT_BIOMETRIC`                  | Biometric assertion failed freshness or modality checks. |
| `REJECT_ATTESTATION`                | Attestation source not allowed by tenant policy, or expired. |
| `REJECT_POLICY_DENY`                | Action type disallowed for the device under tenant policy (Tier A). |
| `REJECT_AUDIT_FAILURE`              | Audit-log append could not complete (Tier A).            |
| `REJECT_OFFLINE_AUTHORITATIVE_BLOCKED` | Tier A requires synchronous server authorization but network unavailable. |

## Status

Vectors are pre-generated and committed for spec v1.0. They are immutable.
Additional vectors require a normative spec proposal — see CONTRIBUTING.md.

## Verifying

The reference verifiers in [`/examples/`](../examples/) consume these vectors
and report PASS/FAIL per vector. See:

- [`examples/typescript/`](../examples/typescript/) — Node 22+
- [`examples/python/`](../examples/python/) — Python 3.10+

## Public verifier registry

`keys/test-keys.json` ships only public keys and the verifier-side state
required to validate the committed vectors. No private key material is
published.
