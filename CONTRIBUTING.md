# Contributing to the PSEA Token Profile

Thank you for considering a contribution. This repository hosts the IETF
Internet-Draft **`draft-yossif-psea-02`** (the *PSEA Token Profile*). The draft
itself is the authoritative specification; contributions are improvements to
that draft and its supporting material.

Contributions are welcome from implementers, cryptographers, security
engineers, and standards reviewers.

## What we accept

| Type | Where | Notes |
|------|-------|-------|
| Specification clarifications and errata | `docs/ietf/draft-yossif-psea-02.{xml,txt,html}` | Open an issue first for any normative change; cite the affected section. The `.xml` is the xml2rfc source — text/HTML are regenerated from it. |
| Review comments on the protocol | issue tracker | Interoperability, security, and clarity feedback are especially valuable. |
| Editorial / typo fixes | the draft source | Straightforward PRs welcome. |

## What we do **not** accept

- Material that reintroduces removed, out-of-scope concerns: product tiers,
  device trust-state machines, enrollment/verification deployment APIs, or
  vendor/device registries. The profile is intentionally a **pure token
  profile**.
- Anything that requires a bilateral agreement, a vendor SDK, a shared secret,
  or membership in a registry to interoperate. PSEA must remain buildable from
  the draft alone.
- Implementation details specific to Yuthent or any other vendor — this repo is
  the **public protocol** only.

## Workflow

1. **Open an issue** describing the proposed change. For normative changes,
   state the draft section and the rationale.
2. **Fork** and create a topic branch.
3. **Edit the draft source** (`draft-yossif-psea-02.xml`) and regenerate the
   text/HTML renderings with `xml2rfc`.
4. **Open a PR** against `main`, including a short summary and the draft
   section(s) the change relates to.

Normative changes are coordinated with the document author and tracked toward
IETF process (the draft notes an intent to request dispatch toward a working
group).

## Code of Conduct

This project follows the
[Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Be respectful and assume good faith. Report unacceptable behavior through the
channel in [`SECURITY.md`](SECURITY.md).

## Sign-off

By contributing you agree your contributions are licensed under the MIT license
used by this repository (see [`LICENSE`](LICENSE)).
