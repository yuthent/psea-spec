# PSEA Reference Verifier — Python

> Reference verifier for the PSEA specification. Not the Yuthent implementation.

A minimal, dependency-light Python implementation of the PSEA verifier. It
loads every vector under `../../test-vectors/`, runs the algorithm specified
in [`spec/tier-definitions.md`](../../spec/tier-definitions.md), and reports
PASS / FAIL per vector.

## Scope

- **Verify only.** No private keys. No signing. No production logic.
- Implements the four tiers (P, S, E, A) end-to-end against the canonical
  test vectors.
- ~250 lines of Python. Intended to be readable in one sitting.

## Requirements

- Python ≥ 3.10
- `cryptography` ≥ 41.0

## Install

```sh
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install cryptography
```

## Run

```sh
cd examples/python
python3 psea_verify.py
```

Expected output:

```
  [PASS] test-vectors/tier-a/A-001-happy.json  (ACCEPT)
  ...
  20 passed, 0 failed, 20 total
```

A non-zero exit code indicates one or more vectors did not match their
expected verification result.

## What the script does

1. Loads `test-vectors/keys/test-keys.json` to get the verifier's known
   device registry and the corresponding public keys.
2. For every JSON file under `test-vectors/tier-*/`, it dispatches to the
   tier-specific verifier (`verify_tier_p/s/e/a`).
3. Each tier verifier follows the pseudocode in
   [`spec/tier-definitions.md`](../../spec/tier-definitions.md) §4–§7
   exactly: precondition checks, action-binding hash, ECDSA-P256 signature
   verification, counter monotonicity, hash chain reconstruction, biometric
   freshness, and attestation policy.
4. The actual result is compared with the vector's `expected.result`.

## License

MIT — see [`../../LICENSE`](../../LICENSE).
