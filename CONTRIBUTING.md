# Contributing to PSEA-Spec

Thank you for considering a contribution. This repository defines the public
**Post-Session Execution Assurance** model — it is a *specification* repo
first and a *code* repo second. Contributions are welcome from implementers,
cryptographers, security engineers, and standards reviewers.

## What we accept

| Type                                                              | Where                                | Notes |
|-------------------------------------------------------------------|--------------------------------------|-------|
| Spec clarifications, errata                                       | `spec/*.md`                          | Open an issue first if the change is normative. |
| Additional reference test vectors                                 | `test-vectors/`                      | Additional test vectors require a normative spec proposal (see issue process); the spec maintainer regenerates vectors out-of-tree to preserve determinism. |
| Conforming verifier implementations in additional languages       | `examples/<lang>/`                    | Must pass every existing vector and include a README. |
| Threat-model additions                                            | `spec/threat-model.md`               | Use STRIDE classification. |
| OpenAPI improvements                                              | `api-contracts/openapi.yaml`         | Backward-compatible only — wire-breaking changes need a version bump. |
| IETF draft updates                                                | `docs/draft-yossif-psea-*.md`        | Coordinated with the document author. |

## What we do **not** accept

- Code or vectors that depend on private credentials, vendor SDKs, or
  third-party SaaS.
- Changes that introduce new external runtime dependencies in
  `examples/python/` or `examples/typescript/` — both reference verifiers
  intentionally use only their language's standard library (plus
  `cryptography` for Python).
- Implementation details specific to Yuthent or any other vendor — this
  repo is the *public model* only.
- Breaking changes to test vectors without a corresponding spec version
  bump.

## Workflow

1. **Open an issue** describing the proposed change. For normative changes
   to `spec/`, briefly state the section and the rationale.
2. **Fork** and create a topic branch.
3. **Make the change**, then run both reference verifiers locally:

   ```sh
   pip install cryptography
   python3 examples/python/psea_verify.py
   node --experimental-strip-types examples/typescript/psea-verify.ts
   ```

   Both must report `20 passed, 0 failed, 20 total`.
4. Test vectors are immutable for spec v1.0 and are not regenerated in-tree.
   Proposals that would change vectors require a normative spec proposal —
   see issue process. Do not hand-edit JSON vectors.
5. **Commit message convention** — every commit MUST reference the section
   of `draft-yossif-psea-01` it implements:

   ```
   Implements §"Core Principles of PSEA": tier-definitions for P/S/E/A
   ```

6. **Open a PR** against `main`. Include:
   - A short summary of the change
   - The IETF section(s) the change relates to
   - Any verifier-output diff that resulted

## Conformance test

Any PR that touches `spec/`, `test-vectors/`, `api-contracts/`, or
`examples/` MUST keep the conformance run green:

```
20 passed, 0 failed, 20 total
```

If a change is intentionally vector-affecting, regenerate vectors, update
both reference verifiers, and document the rationale in the PR.

## Code of Conduct

This project follows the [Contributor Covenant
v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Be respectful and assume good faith. Flag unacceptable behavior through the
channel in [`SECURITY.md`](SECURITY.md).

## Sign-off

By contributing you agree your contributions are licensed under the MIT
license used by this repository (see [`LICENSE`](LICENSE)).
