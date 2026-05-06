# PSEA Reference Verifier — TypeScript

> Reference verifier for the PSEA specification. Not the Yuthent implementation.

A minimal Node.js / TypeScript implementation of the PSEA verifier with
**zero npm dependencies**. Loads every vector under `../../test-vectors/`,
runs the algorithm specified in
[`spec/tier-definitions.md`](../../spec/tier-definitions.md), and reports
PASS / FAIL per vector.

## Scope

- **Verify only.** No private keys. No signing.
- All four tiers (P, S, E, A) end-to-end against the canonical vectors.
- ~250 lines of TS. Uses only `node:crypto` and `node:fs`.

## Requirements

- Node ≥ 22 (uses `--experimental-strip-types` to run `.ts` directly with
  no build step)

## Run

```sh
cd examples/typescript
node --experimental-strip-types psea-verify.ts
# or
npm run verify
```

Expected output:

```
  [PASS] test-vectors/tier-p/P-001-happy.json  (ACCEPT)
  ...
  20 passed, 0 failed, 20 total
```

A non-zero exit code indicates one or more vectors did not match their
expected verification result.

## What the script does

1. Loads `test-vectors/keys/test-keys.json` to get the verifier's known
   device registry and the corresponding public keys.
2. For every JSON file under `test-vectors/tier-*/`, dispatches to the
   tier-specific verifier (`verifyTierP/S/E/A`).
3. Each tier verifier follows the pseudocode in
   [`spec/tier-definitions.md`](../../spec/tier-definitions.md) §4–§7
   exactly: precondition checks, action-binding hash, ECDSA-P256 signature
   verification, counter monotonicity, hash chain reconstruction, biometric
   freshness, and attestation policy.
4. The actual result is compared with the vector's `expected.result`.

## Notes on the implementation

- **JCS:** A minimal RFC 8785 implementation is included inline. It handles
  the test-vector inputs (UTF-8 strings, integers, booleans, nested
  objects/arrays). For production use, prefer a vetted JCS library that
  also handles RFC 8785's number-formatting rules for floats.
- **ECDSA:** Public keys are re-encoded as SubjectPublicKeyInfo (SPKI) and
  raw `R||S` signatures are re-encoded as DER for `node:crypto`.
- **No timing leaks:** Verifiers SHOULD use constant-time comparators for
  hash equality in production; this reference uses `===` for clarity.

## License

MIT — see [`../../LICENSE`](../../LICENSE).
