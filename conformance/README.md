# PSEA conformance harness

A reference Attester and Verifier for **draft-yossif-psea-02**, and a vector
suite that runs the profile against the WHO negative classes of
draft-mih-sato-agent-accountability-composition-00, Section 5.2.

The suite exists to answer one question honestly: which of the negative cases
that a WHO-slot profile is required to reject does PSEA actually reject, and
which does it not. Every row states its expected result before the run, and a
row whose expected result is REFUSE and whose observed result is anything else
is reported as a **failure of the profile**, not smoothed into an absence.

## Scope: only what the draft states normatively

The reference Verifier implements only what draft-yossif-psea-02 states
normatively:

| Draft section | What is implemented |
|---|---|
| Section 3.4 | JOSE header hardening — `alg`/`typ` pinning, `crit` and `b64:false` rejection, and key resolution from the enrolled record only, never from token-carried `jwk`/`jku`/`x5u` |
| Section 3.7.1 | User-verification claim anchoring — `psea_uv.verified == true` required; cross-checked against attested UV-enforcement where the enrolment record conveys it; refused for high-assurance operations where it does not |
| Section 3.13.2 | Fail-closed action binding — re-canonicalize, SHA-256, byte-compare against `psea_payload_hash`, refuse on mismatch or missing payload |

**Where the draft is silent, the implementation refuses rather than guessing.**
That is deliberate. A harness that invents behaviour to fill a specification gap
reports its own choices back as though they were properties of the profile.

`src/jcs.py` implements the RFC 8785 integers-only subset the profile restricts
the action payload to; a float in a payload is a profile violation and is
rejected rather than serialized.

## Result: 13 pass, 3 fail, 5 not applicable (21 rows)

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

Full per-row detail, including the passing rows and the three digest-encoding
rows, is in [RESULTS.md](RESULTS.md). The recorded run is in
[results/psea-02-selfrun.json](results/psea-02-selfrun.json).

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
