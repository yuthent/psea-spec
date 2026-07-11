# PSEA Token Profile

In one sentence: PSEA is an open, vendor-neutral token profile for producing compact cryptographic evidence that a present, user-verified human approved a specific named action at the moment it was executed. Any independent party can verify that evidence from the draft alone, without a shared SDK, a registry, or a vendor's permission.

**An EAT profile for action-bound, user-verification-gated transaction-confirmation evidence.**

This repository is the home of the IETF Internet-Draft
**`draft-yossif-psea-02`** — the *PSEA Token Profile*. The draft itself is the
authoritative, normative specification. Everything an independent party needs
to build a conforming implementation is in the draft.

> **Authoritative spec:**
> [`docs/ietf/draft-yossif-psea-02.txt`](docs/ietf/draft-yossif-psea-02.txt)
> (plain text) ·
> [`docs/ietf/draft-yossif-psea-02.html`](docs/ietf/draft-yossif-psea-02.html)
> (rendered)

## What PSEA is

PSEA defines an **Entity Attestation Token (EAT) profile** ([RFC 9711](https://www.rfc-editor.org/rfc/rfc9711))
for proving that **a present, user-verified human approved a specific named
action at the moment of execution**. It is the per-action,
cryptographically action-bound *Evidence* that "step-up" and
transaction-confirmation flows have always needed but that deployed
authentication standards leave unspecified.

A PSEA proof is a compact **JWS** ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515))
signed with **ES256** (ECDSA on P-256 with SHA-256), carrying a canonical JSON
payload and the `eat_profile` claim `urn:ietf:params:psea:eat-profile:1`. Its
media type is `application/psea+jwt`.

The profile is **device-agnostic and self-contained**: it names no vendor,
mandates no SDK, and assumes no particular authenticator. It binds *what is
signed* to *what the Verifier executes* (What-You-Sign-Is-What-You-Execute). It
does **not** claim to solve the What-You-See-Is-What-You-Sign problem (a
compromised display), and it does not, by itself, prove a specific human
identity — both are explicitly out of scope and documented as such in the
draft.

## Anti-cartel posture (read this)

PSEA is designed so that **no gatekeeper is required to participate**:

- **Build from the draft alone.** Any independent party can implement a
  conforming Attester or Verifier directly from `draft-yossif-psea-02`. No
  reference SDK, no shared secret, and no proprietary library is needed.
- **No bilateral agreement, no vendor blessing.** Conformance is defined by the
  normative text of the draft, not by membership, certification, registration
  with any company, or a contract with the author. Two parties who have never
  communicated can interoperate by each following the draft.
- **Open formats end-to-end.** The encoding (canonical JSON + compact JWS), the
  signature algorithm (ES256), the claim set, and the profile identifier are
  all open and fully specified. The attestation/evidence the profile carries is
  conveyed through open, standard mechanisms (EAT/RFC 9711 claims), not a
  closed format.
- **No central registry of devices, tenants, or issuers.** There is no
  vendor-operated allow-list that a participant must be admitted to.

The goal is a protocol a second, wholly independent implementer can adopt
without asking anyone's permission.

## The claim set, accurately

A PSEA proof payload carries standard EAT/JWT claims plus the profile's
`psea_*` claims. Summarized (see draft §3 for the normative definitions and the
JSON Schema):

| Claim | Role |
|-------|------|
| `iss` | Issuer (the Attester / authenticator authority). |
| `aud` | **Audience** — the intended Verifier. |
| `iat` | Issued-at time. |
| `ueid` | **Pairwise, per-issuer** entity identifier (RFC 9711 RAND type, tag `0x01`). The same device yields a *distinct* `ueid` per issuer; it is not a global device identifier. |
| `eat_profile` | REQUIRED. `urn:ietf:params:psea:eat-profile:1`. |
| `psea_payload_hash` | Binds the proof to the exact action payload being authorized. |
| `psea_op` | Operation / authority-context discriminator (the named action). |
| `psea_tier` | **Opaque** capability / assurance-level indicator. It is a free string scoped by the deployment — **not** a fixed product tier. |
| `psea_counter` | Monotonic per-context counter for replay resistance. |
| `psea_uv` | User-verification claim `{ "verified": bool, "method": string }` — REQUIRED. |
| `psea_proof_version` | Wire-format version. Conforming implementations at this revision emit `"1"`. |
| `psea_chain_prev` | OPTIONAL. Deployment-optional hash-chain link with **strict-equality** verification; omitted entirely when the chain layer is not enabled. |

**Cross-replay binding.** A proof is bound against replay across contexts by
the combination **`psea_tier + psea_op + aud + iss`**: a Verifier rejects any
proof whose signed values for these do not match what it expects for the
operation it is executing.

## What this profile deliberately does **not** include

To keep the protocol clean and unencumbered, the following are **not** part of
PSEA and are **not** in this repository:

- No `P` / `S` / `E` / `A` product tiers (`psea_tier` is an opaque string, not
  an enumerated product level).
- No device trust-state machine (no enrollment/`ENROLLED`/`TAMPERED`/`REVOKED`
  lifecycle in the protocol).
- No `/enroll` · `/attest` · `/verify` · `/revoke` product/deployment API.
- No vendor, tenant, or device registry.
- No chain "gap-tolerance" machinery (the optional chain is strict-equality
  only).

These were earlier-revision or product/deployment concerns; they are out of
scope of the pure token profile and live (if at all) in a deploying
organization's own product, not in the standard.

## Repository contents

| Path | Purpose |
|------|---------|
| [`docs/ietf/draft-yossif-psea-02.txt`](docs/ietf/draft-yossif-psea-02.txt) / [`.html`](docs/ietf/draft-yossif-psea-02.html) | **Authoritative specification.** |
| `docs/ietf/draft-yossif-psea-02.xml` | xml2rfc source for the draft. |
| `docs/ietf/draft-yossif-psea-00.*`, `draft-yossif-psea-01.*` | **Historical revisions only.** These were the earlier *Informational* PSEA security-model drafts; they are superseded by `-02` and are retained for provenance. They do **not** describe the current protocol. |
| [`CITATION.cff`](CITATION.cff) | How to cite this work. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to propose changes. |
| [`SECURITY.md`](SECURITY.md) | How to report a security issue in the spec. |
| [`LICENSE`](LICENSE) | License (MIT). |

## Relationship to other standards

PSEA is an **EAT profile** (RFC 9711) carried as a JWS (RFC 7515). It
**complements OAuth 2.0 Step-Up Authentication** by supplying the per-action,
action-bound Evidence that a step-up flow can require, rather than re-using a
session or an authentication event as a stand-in for transaction approval.

## Status

- Internet-Draft: **`draft-yossif-psea-02`** (intended status: Standards Track;
  individual submission — not yet adopted by any IETF working group, does not
  represent IETF consensus).
- Wire-format version: **`"1"`** (`psea_proof_version`).

## Citation

See [`CITATION.cff`](CITATION.cff).

## Reference

- IETF Datatracker: <https://datatracker.ietf.org/doc/draft-yossif-psea/>
- Model overview: [Post-Session Execution Assurance (PSEA)](https://yuthent.com/psea)
- Implementation: [Yuthent, Execution Authority Infrastructure](https://yuthent.com) implements this profile. Per the anti-cartel posture above, PSEA is an open model; any party may implement it, and this listing is informational, not an endorsement.

## License

MIT — see [`LICENSE`](LICENSE).
