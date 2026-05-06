# Security Policy

## Scope

This repository contains the **specification** of the PSEA model, reference
test vectors, an OpenAPI contract, and minimal verify-only reference
implementations. It does **not** contain production code, signing keys, or
any deployable verifier.

Reports in scope:

- Errors in the formal specification (`spec/*.md`) that could lead an
  implementer to build an unsound verifier.
- Mistakes in test vectors that mask a real bug (e.g., a happy-path vector
  that should reject under a closer reading of the spec).
- Errors in `examples/python/` or `examples/typescript/` that could be
  copy-pasted into a production deployment.
- Vulnerabilities in the OpenAPI contract that would force a conforming
  implementer into an insecure design.

Out of scope:

- Vulnerabilities in any specific deployment of PSEA — report those to the
  deploying organization.
- Issues in third-party libraries used only by the test vectors generator
  (`ecdsa` in `tools/bootstrap-vectors.py`).

## Reporting a vulnerability

Send a private report to **security@yuthent.com** with:

1. A short description of the issue.
2. The file and section affected (`spec/<file>.md §X.Y`).
3. A proof or worked example, if applicable.
4. Your preferred attribution (or "anonymous").

We will acknowledge within **72 hours** and aim to publish a fix or errata
within **30 days** for spec-level issues.

For high-impact issues that affect the public verification model (e.g., a
flaw that lets an attacker construct an `ACCEPT` proof without a fresh
biometric event), we will:

- Coordinate a private fix.
- Publish a CVE-style advisory.
- Bump the spec version.
- Announce on the PSEA mailing list and on the IETF draft thread.

## PGP

If you require encrypted communication, request a PGP key in your initial
email and we will respond out-of-band.

## Hall of Fame

Reporters who responsibly disclose accepted issues are credited in the
release notes for the version that ships the fix, unless they request
anonymity.
