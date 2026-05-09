# Post-Session Execution Assurance (PSEA) — Specification

Reference specification for the **PSEA** security model: cryptographic proof of
authority at the moment a sensitive action is executed, independent of any
session.

This repository is the technical artifact cited by the IETF Internet-Draft
**`draft-yossif-psea-01`**. It defines the public PSEA model in enough detail
that a third-party can build a conforming verifier without referencing any
proprietary implementation.

## What's here

| Path                                                                                  | Purpose |
|---------------------------------------------------------------------------------------|---------|
| [`docs/ietf/draft-yossif-psea-01.txt`](docs/ietf/draft-yossif-psea-01.txt)                         | The IETF Internet-Draft (informational). |
| [`docs/psea-post-session-execution-assurance-v1.0.pdf`](docs/psea-post-session-execution-assurance-v1.0.pdf) | Whitepaper, narrative form. |
| [`spec/tier-definitions.md`](spec/tier-definitions.md)                                | Formal definition of the four enforcement tiers (P/S/E/A) with ABNF and pseudocode. |
| [`spec/proof-token-format.md`](spec/proof-token-format.md)                            | Proof token structure: attestation block, biometric block, hash chain, signature envelope. JSON Schema + CBOR notes. |
| [`spec/state-transitions.md`](spec/state-transitions.md)                              | Trust state machine: `UNTRUSTED → ENROLLING → ENROLLED → ENROLLED_DEGRADED → TAMPERED → REVOKED`. |
| [`spec/threat-model.md`](spec/threat-model.md)                                        | STRIDE threat model — addressed threats, out-of-scope threats, trust-anchor assumptions. |
| [`api-contracts/openapi.yaml`](api-contracts/openapi.yaml)                            | OpenAPI 3.0 contract for `/enroll`, `/attest`, `/verify`, `/revoke`. |
| [`test-vectors/`](test-vectors/)                                                       | 20 deterministic reference vectors — 5 per tier. |
| [`examples/python/`](examples/python/)                                                 | Python reference verifier (verify-only). |
| [`examples/typescript/`](examples/typescript/)                                        | Node 22 TypeScript reference verifier (zero deps). |
| [`tools/bootstrap-vectors.py`](tools/bootstrap-vectors.py)                            | Regenerates the test vectors deterministically (RFC 6979 ECDSA). |

## Quick start

Verify that the reference vectors round-trip cleanly:

```sh
# Python
pip install cryptography
python3 examples/python/psea_verify.py
# → 20 passed, 0 failed, 20 total

# TypeScript (Node 22+)
node --experimental-strip-types examples/typescript/psea-verify.ts
# → 20 passed, 0 failed, 20 total
```

## Core principles (one-line summary each)

1. **Execution-time proof** — authority is verified at the moment of action, not at login.
2. **Human presence assurance** — a real human is demonstrated, not assumed.
3. **Device-bound trust** — proof is tied to a specific, attested device.
4. **Cryptographic proof** — independently verifiable, replay-resistant signatures.
5. **Connectivity independence** — proof generation does not require real-time network.

Full text in [`docs/ietf/draft-yossif-psea-01.txt`](docs/ietf/draft-yossif-psea-01.txt), §"Core Principles of PSEA".

## Non-goals

- Replacing authentication
- Hardening sessions
- Acting as MFA or Zero Trust
- Identity proofing or KYC

## Conformance

A verifier is **conforming** if and only if it passes every test vector in
[`test-vectors/`](test-vectors/) under the algorithms specified in
[`spec/tier-definitions.md`](spec/tier-definitions.md). Both reference
verifiers in [`examples/`](examples/) are themselves conforming and exist as
executable specifications.

## Status

- IETF draft: `draft-yossif-psea-01` (informational, individual submission)
- Spec version: **1.0**
- Last updated: 2026-05-04

## Citation

If you use or reference this specification, please cite as documented in
[`CITATION.cff`](CITATION.cff).

## Contributing & Security

- Contribution process: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security report channel: [`SECURITY.md`](SECURITY.md)

## License

MIT — see [`LICENSE`](LICENSE). Test vectors, OpenAPI document, and reference
verifiers are all MIT-licensed and may be used in any conforming implementation.

## Reference

- Canonical URL: <https://yuthent.com/psea>
- IETF draft: <https://datatracker.ietf.org/doc/draft-yossif-psea/>
