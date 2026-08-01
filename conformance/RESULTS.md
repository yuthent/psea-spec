# PSEA conformance run against the WHO negative classes

**Profile under test:** draft-yossif-psea-02
**Target class list:** draft-mih-sato-agent-accountability-composition-00, Section 5.2
**Date:** 2026-07-28
**Status:** SINGLE IMPLEMENTATION. This is not a cross-run.

Section 7 of the composition draft requires that a conformance vector freeze
only after at least two independent implementations recompute it. One
implementation has run these vectors. The results below are therefore a
starting position for a cross-run, not a conformance claim.

The reference Verifier implements only what draft-yossif-psea-02 states
normatively — Section 3.4 header hardening, Section 3.5 claim set, Section
3.7.1 user-verification anchoring, Section 3.13.2 fail-closed action binding.
Where the draft is silent the implementation refuses rather than guessing.

Every row's expected result was stated before the run.

## Summary

23 pass, 3 fail, 5 not applicable, 31 rows total.

The three failures are properties the profile does not have. They are reported
as failures rather than as absences because a relying party that assumes
otherwise is wrong in a way the document does not currently warn it about.

The ten S rows were added after a review of the reference by Iman Schrock
(EMILIA Protocol) on agent2agent, 2026-07-31. They did not change which rows
fail: claim shape is orthogonal to the principal-reference, ordering and
composition gaps that N3, N11 and M1 record.

## Failures

| ID | Class | Expected | Observed | Refusal code |
|---|---|---|---|---|
| N3 | changed authorizing-principal reference | REFUSE | ACCEPT | — |
| N11 | post-hoc ratification presented as pre-execution authorization | REFUSE | ACCEPT | — |
| M1 | two artifacts verify, same action, different principals | REFUSE | ACCEPT | psea principal=bob grant principal=alice |

**N3 — changed authorizing-principal reference.**
psea_user_hash is OPTIONAL (Section 3.8) and absent by default. A token
carrying no principal reference cannot detect that the reference changed.
The profile does not claim to identify a named human, so this is consistent
with the abstract, but it means PSEA does not satisfy the WHO producer
requirement in Section 5.2 to state the authorizing principal identifier.

**N11 — post-hoc ratification presented as pre-execution authorization.**
A proof minted after the effect is byte-for-byte indistinguishable in kind
from one minted before it. iat records when the token was signed, not the
order of the signature against the effect. No signature alone carries this.
Closing it requires an ordering input outside the artifact — a transparency
anchor or an equivalent. This is a limit of the claim class, not of this
profile: every candidate for per-action human authority has it.

**M1 — two artifacts verify, same action, different principals.**
Not from Section 5.2. Constructed while reviewing the AAE row from Lars
Kroehl on agent2agent. A relying party accepting a standing grant and a
per-action proof for one action performs two independent key-to-principal
resolutions — DID-to-principal for AAE, kid-to-principal for PSEA. Both
succeed. Nothing requires them to resolve to the same human. The run confirms
PSEA accepts a proof from an authenticator enrolled to a principal other than
the one holding the standing grant, because the question is outside its scope.
A naive composition authorises an action no single human both mandated and
approved. This is the enrollment dependency of
draft-yossif-enrollment-problem-00 appearing twice in one decision with two
different shapes.

## Not applicable

| ID | Class | Expected | Observed | Refusal code |
|---|---|---|---|---|
| N5 | quorum: non-distinct principal fills two slots | REFUSE | NOT_REPRESENTABLE | profile defines no quorum construct |
| N6 | quorum: ordered quorum satisfied out of order | REFUSE | NOT_REPRESENTABLE | profile defines no quorum construct |
| N7 | quorum: threshold not met | REFUSE | NOT_REPRESENTABLE | profile defines no quorum construct |
| N9 | signature verifies but does not cover the subject digest | REFUSE | NOT_REPRESENTABLE | digest is inside the signed payload by construction |
| N12b | reusable authorization presented as one-time | REFUSE | NOT_REPRESENTABLE | profile defines no reusable mode |

N5, N6 and N7 are quorum classes; the profile defines no quorum construct at
this revision. N12b requires a reusable-authorization mode the profile does
not define. N9 is not constructible: psea_payload_hash is a claim inside the
signed payload, so a signature that verifies but does not cover the digest
cannot be built.

## Passes

| ID | Class | Expected | Observed | Refusal code |
|---|---|---|---|---|
| N1 | semantically similar input, different canonical bytes | REFUSE | REFUSE | DIGEST_MISMATCH |
| N2 | changed subject | REFUSE | REFUSE | DIGEST_MISMATCH |
| N4 | replay under a different action | REFUSE | REFUSE | OP_MISMATCH |
| N8 | mismatched or absent signature | REFUSE | REFUSE | SIG_INVALID |
| N10 | stale receipt | REFUSE | REFUSE | EXPIRED |
| N12a | one-time authorization replayed | REFUSE | REFUSE | JTI_REPLAY |
| N13 | unattested UV anchoring accepted for a high-assurance operation | REFUSE | REFUSE | UV_UNATTESTED_HIGH_ASSURANCE |
| N14 | psea_uv contradicted by platform attestation | REFUSE | REFUSE | UV_CONTRADICTED_BY_ATTESTATION |
| N15 | header alg none | REFUSE | REFUSE | HEADER_ALG |
| N16 | key taken from token-carried material instead of enrolled record | REFUSE | REFUSE | SIG_INVALID |
| E1 | same 32 octets, different encodings, compatible contexts | JOIN | JOIN | octet-compare=True string-compare=False |
| E2 | same 32 octets, incompatible declared digest contexts | INDETERMINATE | INDETERMINATE | declared contexts differ; equality of octets is not equality |
| E3 | ASCII-hex string compared as bytes against raw octets | MISMATCH | MISMATCH | len 64 vs 32 |
| S1 | ueid does not match the declared pattern | REFUSE | REFUSE | SCHEMA_PATTERN: ueid |
| S2 | psea_uv missing the required method member | REFUSE | REFUSE | SCHEMA_MISSING_MEMBER: psea_uv.method |
| S3 | psea_counter below the declared minimum | REFUSE | REFUSE | SCHEMA_MINIMUM: psea_counter |
| S4 | psea_counter as a string rather than an integer | REFUSE | REFUSE | SCHEMA_TYPE: psea_counter |
| S5 | jti not a string | REFUSE | REFUSE | SCHEMA_TYPE: jti |
| S6 | psea_user_hash does not match the declared pattern | REFUSE | REFUSE | SCHEMA_PATTERN: psea_user_hash |
| S7 | psea_signals_hash does not match the declared pattern | REFUSE | REFUSE | SCHEMA_PATTERN: psea_signals_hash |
| S8 | submods not an object | REFUSE | REFUSE | SCHEMA_TYPE: submods |
| S9 | exp not an integer | REFUSE | REFUSE | SCHEMA_TYPE: exp |
| S10 | repeated JSON member name in the payload | REFUSE | REFUSE | DUPLICATE_MEMBER: psea_counter |

## Section 3.5 claim-shape rows

S1–S10 were contributed by Iman Schrock / EMILIA Protocol, from a review of
`src/psea.py` at commit `a138e64` on agent2agent, 2026-07-31.

Every one of them carries a valid ES256 signature over a well-formed JWS whose
payload declares exactly the claims the profile declares. What is wrong is the
*shape* of one claim. Before these rows existed the Verifier checked presence
and the `additionalProperties: false` allowlist and nothing about the declared
types, patterns, ranges or required sub-members — so **all ten were accepted**,
and S9 raised an uncaught `TypeError` out of `verify()`.

S9 is the worst of the ten and is worth stating separately. Section 3.13.2
requires the Verifier to fail closed. An exception is not a refusal: the caller
receives a crash rather than a verdict, and a caller that treats "no exception"
as the accept condition will do the opposite of what the section requires. The
Verifier now converts any unexpected exception into an `INTERNAL_REFUSAL`.

S10 is not a claim-shape defect but a parse-layer one. `json.loads` keeps the
last of a repeated member name and discards the earlier ones silently, so a
producer and a Verifier reading the same signed bytes with different parsers
can disagree about what was signed. The signature covers both copies and
settles nothing between them. Detection is at parse, for the protected header
and the payload alike.

## Digest-encoding rows

E1, E2 and E3 are not in Section 5.2 — they are the three rows proposed on
agent2agent on 2026-07-25 and adopted by Mikhail Sergeev into the WEXP vector
set. They are included here so the two sets can be compared directly.

E1 confirms the false-negative direction is real: psea_payload_hash is
normatively standard base64 with padding, and a string comparison against a
hex-encoded row reports a mismatch on identical octets. Octet comparison
joins; string comparison does not.

E3 confirms the opposite bug is distinguishable: a 64-character hex string
compared as bytes against the 32 raw octets is a genuine mismatch of
different lengths, and an implementation that normalizes in the wrong
direction would pass E1 and fail here.

## Reproducing

    python3 src/run.py

Requires `cryptography`. No network access. The suite generates fresh keys per
row, so tokens are not fixtures and cannot be replayed between runs.

## What a second implementation would establish

These vectors are stated in terms of the profile, not of an implementation.
An independent implementation recomputing them would establish whether the
refusal codes above follow from the specification or from choices this
implementation made where the specification is silent. The three failures are
the rows where that distinction matters least — they fail for reasons stated
in the document — and the passes are where it matters most.
