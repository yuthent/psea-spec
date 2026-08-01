# PSEA conformance harness

A reference Attester and Verifier for **draft-yossif-psea-03**, and a vector
suite that runs the profile against the WHO negative classes of
draft-mih-sato-agent-accountability-composition-00, Section 5.2.

The suite exists to answer one question honestly: which of the negative cases
that a WHO-slot profile is required to reject does PSEA actually reject, and
which does it not. Every row states its expected result before the run, and a
row whose expected result is REFUSE and whose observed result is anything else
is reported as a **failure of the profile**, not smoothed into an absence.

## Scope: only what the draft states normatively

The reference Verifier implements the rules listed below, and only those. The
right-hand column is the claim, not the left: a section named here is **not**
asserted to be implemented in full, only to the extent the row states. A draft
section absent from the table is not implemented at all. Every row is a claim
about the harness rather than about the profile.

| Draft section | What is implemented |
|---|---|
| Section 3.4 | JOSE header hardening — `alg`/`typ` pinning, `crit` and `b64:false` rejection, and key resolution from the enrolled record only, never from token-carried `jwk`/`jku`/`x5u` |
| Section 3.5 | JWS payload claim set — the declared set is exhaustive (`additionalProperties: false`), so an undeclared claim is refused rather than ignored; the thirteen REQUIRED claims must be present; and for every claim present, the declared **type, pattern, enum, minimum, maximum and required sub-members** are enforced. `src/psea.py` carries the schema as a table (`CLAIM_SCHEMA`) transcribed from the draft, so what the code enforces can be read against Section 3.5 side by side |
| Parse layer | A repeated JSON member name is refused, in the protected header and in the payload alike. Not a Section 3.5 rule — the schema cannot express it, because by the time a schema sees an object the duplicate has already been resolved by the parser |
| Section 3.7.1 | User-verification claim anchoring — `psea_uv.verified == true` required; cross-checked against attested UV-enforcement where the enrolment record conveys it; refused for high-assurance operations where it does not |
| Section 3.13.2 | Fail-closed action binding — re-canonicalize, SHA-256, byte-compare against `psea_payload_hash`, refuse on mismatch or missing payload |

Section 3.5 was added to the harness after an audit found the Verifier ignoring
undeclared claims and omitting two REQUIRED ones (`ueid`, `eat_profile`) that
the reference Attester never emitted, while comparing `psea_proof_version`
against the integer `1` where the schema declares the string `"1"`. Attester and
Verifier were corrected together in one change. No recorded row moved, because
no row in the suite exercised any of those paths — which is itself the finding:
a harness cannot detect a defect in a rule it does not implement.

That first pass implemented **presence and the allowlist, and nothing about
claim shape** — which is the same finding a second time. A review of the
reference by Iman Schrock (EMILIA Protocol) on agent2agent, 2026-07-31, found
nine claims of the wrong type, pattern or range being accepted, and one wrongly
typed `exp` raising an uncaught `TypeError` out of `verify()` rather than
refusing. Under Section 3.13.2 the exception is the worse of the two: an
exception is not a refusal. The declared shape is now enforced, any unexpected
exception is converted to a refusal, and the ten cases are rows S1–S10.
**Negative cases contributed by Iman Schrock / EMILIA Protocol.**

The Attester emits the thirteen REQUIRED claims and nothing else. It does not
emit `psea_signals_hash`, which the profile declares OPTIONAL: the reference
carries no auxiliary transport document for that claim to commit to, and putting
a claim on the wire that no part of this harness appraises would misrepresent
the coverage above.

**Where the draft is silent, the implementation refuses rather than guessing.**
That is deliberate. A harness that invents behaviour to fill a specification gap
reports its own choices back as though they were properties of the profile.

### What the table does not say

The table above says what is implemented. It says nothing beyond that, and the
two limits below are the ones most likely to be read into it by mistake.

**Replay state is in-memory and process-local.** The finalized-`jti` set and the
per-key counter high-water map are ordinary Python objects on a single
`Verifier` instance in a single process. They demonstrate that the check exists
and that a replayed `jti` or a non-advancing counter is refused. **Nothing about
atomicity, durability, or cross-node enforcement follows from any row in this
suite.** Section 3.10 requires the counter compare-and-advance and the `jti`
finalization to be one atomic step; Section 6.5 requires a sharded deployment to
serialize all submissions for a given (Attester, counter scope) to a single
authority, to keep the `jti` finalization index globally consistent across
nodes, and to protect that state against rollback so a restore or failover
cannot lower a high-water mark or forget a finalized `jti`. This harness
demonstrates none of those. A single-process dictionary is atomic and durable
for free and so proves nothing about a deployment where neither is free — which
is exactly where a horizontally-scaled Verifier fails.

**Coverage is exactly the table.** A draft section absent from it is not
implemented — not partially, not incidentally. In particular the harness does
not implement the enrollment lifecycle trust gate (Section 3.14), the chain
layer's linkage check (Section 3.12.3), caller-identity binding (Section
3.13.5), or `eat_nonce` challenge correlation, and no row here bears on any of
them.

`src/jcs.py` implements the RFC 8785 integers-only subset the profile restricts
the action payload to; a float in a payload is a profile violation and is
rejected rather than serialized.

## Result: 23 pass, 3 fail, 5 not applicable (31 rows)

The three failures are properties the profile does not have:

- **N3 — changed authorizing-principal reference.** `psea_user_hash` is OPTIONAL
  (Section 3.8) and absent by default, so a token carrying no principal
  reference cannot detect that the reference changed. This is consistent with
  the abstract, which does not claim to identify a named human — but it means
  PSEA does not satisfy the Section 5.2 producer requirement to state the
  authorizing principal identifier.
- **N11 — post-hoc ratification presented as pre-execution authorization.** A
  proof minted after the effect is indistinguishable in kind from one minted
  before it. `iat` records when the token was signed, not the order of the
  signature against the effect. Closing this needs an ordering input from
  outside the artifact.
- **M1 — two artifacts verify, same action, different principals.** Not from
  Section 5.2. A relying party accepting both a standing grant and a per-action
  proof performs two independent key-to-principal resolutions, and nothing
  requires them to resolve to the same human. PSEA accepts a proof from an
  authenticator enrolled to a principal other than the one holding the grant,
  because the question is outside its scope.

The five not-applicable rows are not passes. N5, N6 and N7 are quorum classes
and the profile defines no quorum construct at this revision; N12b requires a
reusable-authorization mode it does not define; N9 is not constructible, because
`psea_payload_hash` sits inside the signed payload by construction.

Rows S1–S10 are the Section 3.5 claim-shape cases and all pass. They did not
change which rows fail: claim shape is orthogonal to the principal-reference,
ordering and composition gaps above.

Full per-row detail, including the passing rows, the three digest-encoding rows
and the ten claim-shape rows, is in [RESULTS.md](RESULTS.md). The recorded run
is in [results/psea-02-selfrun.json](results/psea-02-selfrun.json).

[`interop-aae/`](interop-aae/) holds the PSEA side of a candidate two-way
cross-run with draft-kroehl-agentic-trust-aae — one action, two proofs from
different principals, three composition cases — and is **not frozen**.

## This is ONE implementation

**Nothing here is a conformance claim.** Section 7 of
draft-mih-sato-agent-accountability-composition-00 states:

> A conformance vector freezes only after it has been recomputed by at least
> two independent implementations.

One implementation has run these vectors. That is a starting position for a
cross-run and no more. Until a second, independently written implementation
recomputes them, the refusal codes below cannot be distinguished from choices
this implementation made where the specification is silent — which is precisely
what a cross-run is for.

The three failures are the rows where that distinction matters least; they fail
for reasons stated in the document itself. The passing rows are where it matters
most.

## Running it

    cd conformance
    python3 -m pip install -r requirements.txt
    python3 src/run.py       # report the rows
    python3 src/check.py     # assert they still match the recorded state

Output is a JSON report on stdout. The single dependency is
[`cryptography`](https://pypi.org/project/cryptography/); there are no others,
and the suite needs no network access.

The suite generates fresh keys per row and stamps `iat`/`exp` at run time, so
tokens are not fixtures and cannot be replayed between runs. Consequently the
JSON output is **not** byte-reproducible across runs — the per-row verdicts are
the stable surface, not the bytes.

`src/run.py` reports; it does not judge. It exits 0 whatever the rows do,
because the three failures above are known and expected — so on its own it
cannot tell you that a row flipped.

`src/check.py` is the regression gate, and is what CI runs. It executes the
suite in-process and asserts the verdict counts, the failing row set, and every
row's refusal code against `results/psea-02-selfrun.json`, exiting 1 with a diff
if any of them moved. The expected state is a single dict at the top of that
file. It must be updated deliberately when the profile changes; re-baselining it
to make a red build go green discards the only signal this suite produces.
