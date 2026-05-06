# PSEA Proof Token Format

> Canonical structure of a PSEA proof token: device-attestation block,
> biometric-assertion block, hash-chain entry, and signature envelope. Includes
> JSON Schema and CBOR encoding examples.
>
> Companion to **draft-yossif-psea-00**, §"Cryptographic Proof".

---

## 1. Overview

A PSEA proof token is a structured document that binds together the four
elements required by the model:

1. **Device attestation** — proof that the issuing device is genuine and
   running an unmodified trust-anchor implementation.
2. **Biometric assertion** — proof that a real human was physically present
   at the moment of issuance (where the tier requires it).
3. **Hash chain entry** — proof that the action is part of an unbroken
   monotonic ordering, providing replay and reordering resistance.
4. **Signature envelope** — proof that the body has not been altered since
   issuance, signed by a non-exportable device-bound key.

Two equivalent on-the-wire encodings are defined:

- **JSON / JWS** — canonicalized via RFC 8785 (JCS), signed as JWS Compact
  Serialization (RFC 7515). Used by HTTP / REST transports.
- **CBOR / COSE_Sign1** — canonicalized via RFC 8949 deterministic encoding,
  signed as COSE_Sign1 (RFC 9052). Used by constrained / NFC / BLE transports.

A verifier MUST accept either encoding and treat them as semantically
identical. An issuer MUST emit one encoding per proof, never both.

---

## 2. Top-Level Structure

```
PseaProof
├── header
│   ├── version            ; integer, currently 1
│   ├── tier               ; "P" | "S" | "E" | "A"
│   ├── algorithm          ; "ES256" (ECDSA P-256 + SHA-256)
│   └── encoding           ; "JWS" | "COSE_Sign1"
├── body
│   ├── deviceId           ; hex(SHA-256(device_public_key))
│   ├── actionHash         ; hex(SHA-256(JCS(action_request)))
│   ├── timestamp          ; uint64, Unix ms on trust-anchor device
│   ├── counter            ; uint64, monotonic, per-device  (E, A only)
│   ├── chainPrev          ; hex(SHA-256), previous chain head  (E, A only)
│   ├── chainEntry         ; hex(SHA-256), this entry's hash    (E, A only)
│   ├── attestation        ; AttestationBlock
│   ├── biometric          ; BiometricBlock         (S, E, A only)
│   └── policy             ; PolicyHints  (optional)
└── signature              ; bytes (compact serialization)
```

Tier P omits `counter`, `chainPrev`, `chainEntry`, `biometric`, and
`signature`. Tier S omits `chainPrev` and `chainEntry`. Tiers E and A include
every field.

---

## 3. Block Specifications

### 3.1 AttestationBlock

```
AttestationBlock
├── source                 ; "android-key" | "android-play-integrity"
│                          ;   | "ios-app-attest" | "tpm" | "test"
├── chain                  ; array of base64url-encoded X.509 / CBOR certs
├── nonce                  ; base64url, server-issued at enrollment
├── notBefore              ; uint64, ms — earliest valid use time
├── notAfter               ; uint64, ms — expiration
└── packageBinding
    ├── value              ; reverse-DNS bundle / package id
    └── enforcement        ; "strict-cert-chain" | "client-claim"
                           ; "strict-cert-chain" REQUIRED for production tenants
```

Notes:

- `source = "test"` is reserved for test vectors and MUST be rejected by any
  production verifier whose policy does not enable test mode.
- Verifiers MAY accept `packageBinding.enforcement = "client-claim"` only when
  operating in sandbox/test mode for that tenant; production verifiers MUST
  require `strict-cert-chain`. Each acceptance of a client-claim
  packageBinding SHOULD be audited.

### 3.2 BiometricBlock

```
BiometricBlock
├── modality               ; "face" | "fingerprint" | "passkey-uv" | "iris"
├── liveness
│   ├── method             ; "passive" | "active-challenge" | "platform"
│   └── score              ; 0.0..1.0 — implementation-specific
├── freshness
│   ├── capturedAt         ; uint64, ms on trust-anchor device
│   └── windowMs           ; uint32, max age accepted at issuance time
├── sessionRef             ; opaque, present only when tier == "S"
└── platformAttestation    ; opaque blob, format determined by `modality`
                           ;   • Android BiometricPrompt CryptoObject ref
                           ;   • iOS LAContext evaluation result
                           ;   • WebAuthn `userVerified=true` assertion
```

Notes:

- `liveness.score` is informational. The verifier MUST NOT use it as the sole
  acceptance criterion.
- For Tier S, `freshness.capturedAt` MAY refer to the session-start biometric.
  For Tiers E and A, it MUST refer to a biometric event captured no earlier
  than `windowMs` before `body.timestamp`. Recommended `windowMs` ≤ 30000.

### 3.3 ChainEntry (Tiers E, A)

`chainEntry` is a 32-byte field that binds this proof to the previous chain
head. Verifiers MUST recompute and compare per the algorithm in
[tier-definitions.md §6.5](./tier-definitions.md). The construction inputs and
ordering are normative for verifiers; this document does not specify the
issuer-side derivation.

The very first proof from a device after enrollment uses `chainPrev =
0x0000…00` (32 zero bytes). Subsequent proofs use the previous proof's
`chainEntry`.

Verifiers MUST track `chainPrev` per `deviceId`. A mismatch indicates either
(a) replay of a stale proof, (b) a forked / cloned device, or (c) a missed
proof (e.g., crashed before sync). All three MUST be treated as fraud
signals — the device SHOULD be transitioned to `TAMPERED` until investigated.

### 3.4 PolicyHints (optional)

```
PolicyHints
├── requestedTier          ; "P" | "S" | "E" | "A" — what RP asked for
├── actionType             ; opaque string — RP-defined
├── jurisdiction           ; ISO 3166-1 alpha-2 country code
└── retention              ; "ephemeral" | "audit" | "regulated"
```

`PolicyHints` is advisory metadata to assist verifier-side audit storage and
jurisdiction routing. It is NOT a security boundary; a verifier MUST NOT relax
any other check based on its contents.

---

## 4. Canonicalization

### 4.1 JSON / JWS encoding

Bodies are canonicalized using **RFC 8785 (JCS)** before hashing. Specifically:

1. UTF-8 encoding.
2. Object members sorted lexicographically by Unicode code point.
3. Numbers serialized per RFC 8785 §3.2.2.4 (no exponential, no leading zeros).
4. No insignificant whitespace.

The JWS protected header is:

```json
{"alg": "ES256", "typ": "PSEA+JWS", "kid": "<deviceId>"}
```

The JWS compact serialization output is:

```
base64url(header) "." base64url(JCS(body)) "." base64url(signature)
```

### 4.2 CBOR / COSE_Sign1 encoding

Bodies are encoded using **RFC 8949 deterministic encoding rules**:

1. Smallest possible integer encoding.
2. Definite-length maps and arrays only.
3. Map keys sorted by length-then-bytewise.
4. No tags except where explicitly defined here.

The COSE_Sign1 protected header carries:

```cbor
{1: -7, 3: "PSEA+CBOR", 4: <deviceId-bytes>}
```

Where `1 = alg (ES256)`, `3 = content_type`, `4 = kid`.

---

## 5. JSON Schema (Draft 2020-12)

The full normative schema is published at
[`/api-contracts/openapi.yaml`](../api-contracts/openapi.yaml) under the
`components.schemas` map. A self-contained version is reproduced here for
implementer convenience.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/yuthent/psea-spec/spec/proof-token-format.md",
  "title": "PseaProof",
  "type": "object",
  "required": ["header", "body"],
  "properties": {
    "header": {
      "type": "object",
      "required": ["version", "tier", "algorithm", "encoding"],
      "properties": {
        "version":   { "type": "integer", "const": 1 },
        "tier":      { "type": "string", "enum": ["P", "S", "E", "A"] },
        "algorithm": { "type": "string", "const": "ES256" },
        "encoding":  { "type": "string", "enum": ["JWS", "COSE_Sign1"] }
      },
      "additionalProperties": false
    },
    "body": {
      "type": "object",
      "required": ["deviceId", "actionHash", "timestamp", "attestation"],
      "properties": {
        "deviceId":   { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "actionHash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "timestamp":  { "type": "integer", "minimum": 0 },
        "counter":    { "type": "integer", "minimum": 0 },
        "chainPrev":  { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "chainEntry": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "attestation": { "$ref": "#/$defs/AttestationBlock" },
        "biometric":   { "$ref": "#/$defs/BiometricBlock"   },
        "policy":      { "$ref": "#/$defs/PolicyHints"      }
      },
      "allOf": [
        {
          "if":   { "properties": { "$tier": { "const": "E" } } },
          "then": { "required": ["counter", "chainPrev", "chainEntry", "biometric"] }
        },
        {
          "if":   { "properties": { "$tier": { "const": "A" } } },
          "then": { "required": ["counter", "chainPrev", "chainEntry", "biometric"] }
        }
      ],
      "additionalProperties": false
    },
    "signature": { "type": "string" }
  },
  "$defs": {
    "AttestationBlock": {
      "type": "object",
      "required": ["source", "chain", "nonce", "notBefore", "notAfter", "packageBinding"],
      "properties": {
        "source": {
          "type": "string",
          "enum": ["android-key", "android-play-integrity",
                   "ios-app-attest", "tpm", "test"]
        },
        "chain":     { "type": "array", "items": { "type": "string" } },
        "nonce":     { "type": "string" },
        "notBefore": { "type": "integer" },
        "notAfter":  { "type": "integer" },
        "packageBinding": {
          "type": "object",
          "required": ["value", "enforcement"],
          "properties": {
            "value":       { "type": "string" },
            "enforcement": { "type": "string",
                             "enum": ["strict-cert-chain", "client-claim"] }
          }
        }
      }
    },
    "BiometricBlock": {
      "type": "object",
      "required": ["modality", "liveness", "freshness"],
      "properties": {
        "modality": {
          "type": "string",
          "enum": ["face", "fingerprint", "passkey-uv", "iris"]
        },
        "liveness": {
          "type": "object",
          "required": ["method", "score"],
          "properties": {
            "method": {
              "type": "string",
              "enum": ["passive", "active-challenge", "platform"]
            },
            "score": { "type": "number", "minimum": 0, "maximum": 1 }
          }
        },
        "freshness": {
          "type": "object",
          "required": ["capturedAt", "windowMs"],
          "properties": {
            "capturedAt": { "type": "integer", "minimum": 0 },
            "windowMs":   { "type": "integer", "minimum": 1, "maximum": 60000 }
          }
        },
        "sessionRef":          { "type": "string" },
        "platformAttestation": { "type": "string" }
      }
    },
    "PolicyHints": {
      "type": "object",
      "properties": {
        "requestedTier": { "type": "string", "enum": ["P", "S", "E", "A"] },
        "actionType":    { "type": "string" },
        "jurisdiction":  { "type": "string", "pattern": "^[A-Z]{2}$" },
        "retention":     { "type": "string",
                           "enum": ["ephemeral", "audit", "regulated"] }
      }
    }
  }
}
```

---

## 6. Worked Example — Tier E proof (JSON / JWS)

### 6.1 Body (pre-canonicalization)

```json
{
  "tier": "E",
  "deviceId": "8f2b1c0e9d4a5f6e7c8b9a0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f",
  "actionHash": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
  "counter": 42,
  "chainPrev": "0000000000000000000000000000000000000000000000000000000000000000",
  "chainEntry": "9b1f3c5e7a2d4b6c8e0f1a3b5d7e9f1c2a4b6d8e0f2a4b6d8e0f1a3c5e7b9d0f",
  "timestamp": 1733280000000,
  "attestation": {
    "source": "android-key",
    "chain": ["MIIB…", "MIIC…"],
    "nonce": "Vk9Z…",
    "notBefore": 1733000000000,
    "notAfter":  1764536000000,
    "packageBinding": {
      "value": "com.example.banking",
      "enforcement": "strict-cert-chain"
    }
  },
  "biometric": {
    "modality": "face",
    "liveness": { "method": "active-challenge", "score": 0.97 },
    "freshness": { "capturedAt": 1733279997000, "windowMs": 30000 },
    "platformAttestation": "BPK…"
  }
}
```

### 6.2 Canonicalized body (JCS)

```
{"actionHash":"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
"attestation":{"chain":["MIIB…","MIIC…"],"nonce":"Vk9Z…","notAfter":17645…
```

(elided — full JCS output is deterministic; implementers reproduce by feeding
the JSON above through any RFC 8785 library)

### 6.4 JWS Compact Serialization

```
eyJhbGciOiJFUzI1NiIsInR5cCI6IlBTRUErSldTIiwia2lkIjoiOGYyYjFjMGU…}
.<base64url-jcs-body>
.<base64url-signature>
```

---

## 7. Worked Example — Tier S proof (CBOR / COSE_Sign1)

```cbor
84                  / array(4) — COSE_Sign1                  /
  43                / bstr(3)  — protected header            /
    A3              /   map(3)                               /
      01 26         /     1: -7   (alg ES256)                /
      03 69 50…     /     3: "PSEA+CBOR"                     /
      04 58 20 …    /     4: <deviceId 32 bytes>             /
  A0                / map(0) — unprotected header            /
  58 …              / bstr(N) — payload (CBOR-encoded body)  /
  58 40 …           / bstr(64) — signature                   /
```

The payload is the deterministic-CBOR encoding of the same body fields shown
in §6.1, with `tier = "S"` and `biometric.sessionRef` populated instead of
`platformAttestation`.

---

## 8. Test Vector Cross-Reference

The reference [`/test-vectors/`](../test-vectors/) directory contains the
following encodings:

| Tier | Vectors | Encoding |
|------|---------|----------|
| P    | 5       | JSON     |
| S    | 5       | JSON     |
| E    | 5       | JSON     |
| A    | 5       | JSON     |

Implementations that need CBOR test vectors can derive them deterministically
by re-encoding the canonical body via any RFC 8949 deterministic encoder; the
signing input MUST be the encoded payload bytes.

---

## 9. Versioning

`header.version` is an integer and currently MUST equal `1`. A future revision
of this specification MAY introduce version `2`. Verifiers MUST reject
unknown versions with `UNSUPPORTED_VERSION`. They MUST NOT attempt to
"best-effort" parse a future version.
