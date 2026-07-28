# Security Policy

## Scope

This repository contains the **specification** of the PSEA Token Profile
(IETF Internet-Draft `draft-yossif-psea-02`). It does **not** contain
production code, signing keys, or any deployable system.

Reports in scope:

- Errors in the draft (`drafts/draft-yossif-psea/draft-yossif-psea-02.*`) that could lead an
  implementer to build an unsound Attester or Verifier — for example, a flaw
  that would let an attacker construct an accepted proof without a genuine,
  fresh user-verification event, or that breaks the action-payload or
  cross-replay binding.
- Ambiguities in the normative text that admit an insecure but
  spec-compliant implementation.

Out of scope:

- Vulnerabilities in any specific *deployment* of PSEA — report those to the
  deploying organization.
- Issues in third-party libraries or platforms a deployment chooses to use.

## Reporting a vulnerability

Send a private report to **security@yuthent.com** with:

1. A short description of the issue.
2. The draft section affected (e.g., `draft-yossif-psea-02 §3.x`).
3. A proof or worked example, if applicable.
4. Your preferred attribution (or "anonymous").

We will acknowledge within **72 hours** and aim to publish a fix or errata
within **30 days** for spec-level issues.

For high-impact issues that affect the soundness of the profile, we will:

- Coordinate a private fix.
- Publish an advisory.
- Roll the draft revision (and, where applicable, the wire-format version).
- Note the issue on the IETF draft thread.

## PGP

If you require encrypted communication, request a PGP key in your initial email
and we will respond out-of-band.

## Hall of Fame

Reporters who responsibly disclose accepted issues are credited in the revision
that ships the fix, unless they request anonymity.
