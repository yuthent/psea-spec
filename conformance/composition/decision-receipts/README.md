# Composition set: PSEA -03 evidence inside a decision receipt

Vectors for a draft-yossif-psea-03 proof carried as evidence in an approval
record of draft-gruszka-audit-decision-receipts-05.

The main suite in `conformance/` tests what a PSEA Verifier decides on its
own. This set tests the cases where the two layers disagree: a PSEA Verifier
accepts a proof that the composition with the approval record must refuse, or
it refuses for a reason the composition inherits. The set uses the Verifier in
`conformance/src/` as it is and adds no rule to it.

## The two columns

Every vector states two expected results before the run.

| Column | Who decides | What it checks |
|---|---|---|
| `psea_verifier` | The reference Verifier in `conformance/src/psea.py` | Everything that Verifier implements: header, signature under the enrolled key, Section 3.14 enrollment state, Section 3.5 claim set, iss/aud/op/tier, freshness, jti and counter replay, UV anchoring, action binding |
| `composition` | `compose()` in `run.py` | ACCEPT only if `psea_verifier` is ACCEPT **and** all four hold: (1) enrollment state is `active`; (2) enrollment `subject` equals the approval `approver` (principal.id); (3) SHA-256 of the action bytes equals the approval `actionDigest` and equals the decoded `psea_payload_hash`; (4) proof `jti` equals `approvalId` |

`compose()` performs no other check. Where the composition refuses because the
PSEA Verifier refused, its detail says `psea_verifier_refused` (C2, C3, C4, C6,
C7), alongside any of its own checks that also fail.

## Vectors

| id | What differs | psea_verifier | composition |
|---|---|---|---|
| DR-V1 | Nothing; all consistent | ACCEPT | ACCEPT |
| DR-C1 | Enrollment subject `bob`, approval approver `alice`; proof valid. This is the N3 class (changed authorizing-principal reference) | ACCEPT | REFUSE |
| DR-C2 | Enrollment state `revoked` | REFUSE (`ENROLLMENT_NOT_ACTIVE`) | REFUSE |
| DR-C3 | Enrollment state `suspended` | REFUSE (`ENROLLMENT_NOT_ACTIVE`) | REFUSE |
| DR-C4 | Proof signed by a key that is not the enrolled key, same kid | REFUSE | REFUSE |
| DR-C5 | Valid proof, same subject and action, `jti` differs from `approvalId` | ACCEPT | REFUSE |
| DR-C6 | Proof over the action with one value changed (amount 501) | REFUSE | REFUSE |
| DR-C7 | The DR-V1 proof presented a second time to the same Verifier; the second presentation is recorded | REFUSE | REFUSE |

No vector is NOT_REPRESENTABLE.

### C2 and C3: Section 3.14

Section 3.14 of draft-yossif-psea-03 states that a conforming Verifier MUST
keep an enrollment lifecycle with at least the states active, suspended and
revoked, and MUST reject any proof whose enrollment is not active. The first
version of this set found that the reference Verifier did not implement this
and accepted both. The reference now does (rows N17 and N18 of the main
suite), and both vectors are refused by the PSEA Verifier itself.

### C7: replay

The second refusal comes from the reference Verifier's existing jti and
counter state (`JTI_REPLAY`). This set adds no at-most-once mechanism.
The decision-receipt side's own at-most-once check is out of scope here.

## Fixtures

- `action/action.json`: the action bytes, exactly
  `{"amount":500,"operation":"transfer","target":"acct-9"}` with no trailing
  newline. Already RFC 8785 canonical; `run.py` refuses to run if they are not.
  SHA-256 `c4edf63992f8497519a4296d3559c37077f7abb3f6951985f82af7a510de902f`.
- `keys/test-es256.jwk`: a P-256 key generated for this set only, kid
  `dr-test-es256-2026-11`. **Test only.** The private part `d` is published on
  purpose so that anyone can re-sign. Never trust this key for anything.
- `enrollment/*.json`: an enrollment record with enrollment id, kid, public
  JWK, RFC 7638 thumbprint, state and subject. **This is a test fixture, not a
  normative format.** PSEA -03 leaves the enrollment ceremony out of scope
  (Section 3.13.3). The reference `Enrollment` receives kid, key, subject
  and state. The fixture carries no UV-enforcement property, so
  UV anchoring is "asserted" and the Verifier runs with its default
  `high_assurance=False`. UV anchoring is not what this set tests.
- `approval/approval-A.json`: the approval-record fields `approver`,
  `actionDigest` and `approvalId` of draft-gruszka-audit-decision-receipts-05.
- `proofs/*.json`: PSEA -03 proofs produced by the reference Attester in
  `conformance/src/psea.py` via `gen.py`. None was written by hand. All share
  iat 1794208809 and exp 1794209109. `run.py` verifies at a fixed time inside
  that window (`vectors.json`, `context.now`), so the result does not depend on
  the clock. The C4 signing key was ephemeral and was not kept.

## Correlation: PROVISIONAL

The approval event is joined to the proof as `jti -> approvalId`. The
counterpart has not confirmed which approval-record field correlates with
`jti` or `psea_counter`. C5 depends on that choice. If the correlation
changes, C5 and its fixtures change with it.

## Integration contract (PSEA side, draft)

What the vectors assume today at the boundary between a PSEA proof and an
approval record. A draft for agreement with the decision-receipts side. It is
not a normative part of either document.

### Enrollment record trust

The vectors take the enrollment record (kid, public key, state, subject) as
given. It is a test fixture. How a deployment establishes that record, and that
the key really belongs to the subject, is out of scope for PSEA -03 (Section
3.13.3) and is the open problem stated in draft-yossif-enrollment-problem.
Every vector depends on it. DR-C2 and DR-C3 exercise its state; DR-C4 exercises
its key binding.

### Subject mapping

The enrollment `subject` must equal the approval `approver`, which is the
`principal.id`. The PSEA proof carries no principal, so only the composition
check sees a mismatch. Exercised by DR-C1.

### Action digest correspondence

SHA-256 over the RFC 8785 action bytes must equal the approval `actionDigest`
and must equal the decoded `psea_payload_hash`. The values are compared as
octets: `actionDigest` is hex, `psea_payload_hash` is standard base64 with
padding. Exercised by DR-C6.

### Approval-event correlation

`jti -> approvalId`. **PROVISIONAL**, to be agreed with the decision-receipts
side. Exercised by DR-C5.

### Rejection behaviour

| Vector | Refused by | Code |
|---|---|---|
| DR-V1 | nobody | accepted |
| DR-C1 | composition check | `subject!=approver` |
| DR-C2 | PSEA verifier | `ENROLLMENT_NOT_ACTIVE` (composition also: `enrollment_state=revoked`) |
| DR-C3 | PSEA verifier | `ENROLLMENT_NOT_ACTIVE` (composition also: `enrollment_state=suspended`) |
| DR-C4 | PSEA verifier | `SIG_INVALID` |
| DR-C5 | composition check | `jti!=approvalId` |
| DR-C6 | PSEA verifier | `DIGEST_MISMATCH` (composition also: `action_digest_mismatch`) |
| DR-C7 | PSEA verifier | `JTI_REPLAY` on the second presentation |

## Out of scope

- Outcome receipts and the decision receipt itself, including the citation of
  the PSEA token in `inputSnapshot`.
- The decision-receipt side's at-most-once check.
- The enrollment ceremony, and whether the enrolled subject is a specific
  person. PSEA -03 does not, by itself, prove a specific human identity.

## Running

```
cd conformance/composition/decision-receipts
python3 run.py --check
( cd results && sha256sum -c dr-results.sha256 )
```

`run.py --check` exits non-zero if the result differs from
`results/dr-results.json`. `gen.py` produced the fixtures once. It refuses to
run while `keys/test-es256.jwk` exists, because ECDSA signatures are
randomized and regenerating would replace every proof.

Status: single implementation, not yet cross-run.
