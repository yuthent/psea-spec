# PSEA / AAE interop fixture — candidate, NOT frozen

`psea-fixture-v0.json` is the **PSEA side** of a proposed two-way cross-run
between draft-yossif-psea-02 and
[draft-kroehl-agentic-trust-aae-00](https://www.ietf.org/archive/id/draft-kroehl-agentic-trust-aae-00.txt)
(*Agent Authorization Envelope (AAE): A Machine-Evaluable Authorization
Structure for Autonomous AI Agents*, L. K. Kroehl).

It encodes one action, two independently-signed PSEA proofs over that action,
and three composition cases. The AAE side is Kroehl's to encode; nothing here
speaks for it.

**This fixture is a candidate. It is not frozen and is not a conformance
claim.** Section 7 of draft-mih-sato-agent-accountability-composition-00 states
that *"a conformance vector freezes only after it has been recomputed by at
least two independent implementations."* One implementation has produced these
values. Until a second recomputes them, the expected results below are a
proposal for discussion, not an agreed vector set. The `@version` field is
`PSEA-AAE-INTEROP-v0` for that reason.

## The join key

The two profiles join on a shared action digest:

    join key = SHA-256( JCS(RFC 8785) canonical form of the action payload )

| Field | Value |
|---|---|
| Octets (hex) | `d6583cbc62c1278311ad311a586da207189693a98143f773a8fc960ae59ac606` |
| PSEA wire encoding | standard base64 **with** padding |
| PSEA wire value | `1lg8vGLBJ4MRrTEaWG2iBxiWk6mBQ/dzqPyWCuWaxgY=` |

**Compare the 32 octets, never the encoded strings.** PSEA carries the digest
as padded standard base64; another profile may carry the same 32 octets as
lowercase hex, base64url, or raw bytes. A string comparison across those
encodings reports a mismatch on identical octets — the false-negative direction
confirmed by row E1 of [../RESULTS.md](../RESULTS.md). Comparing a 64-character
hex *string* as bytes against the 32 raw octets is a genuine length mismatch
(row E3), so an implementation that normalizes in the wrong direction passes E1
and fails E3.

## Integers-only constraint on the action payload

draft-yossif-psea-02 **Section 2.5 (Number Serialization (Integers Only))**
restricts the action payload to integers. Floating-point numbers, decimal
fractions, and exponent notation MUST NOT appear. Section 2.5 states the rule
governs the actionPayload the action binding hashes, and requires monetary and
other fractional quantities to be carried as integers in a fixed minor unit or
as strings.

The fixture follows this: the amount is `"amount_minor": 250000` — 2 500.00 CHF
expressed in minor units — not `2500.00`. A peer that places a JSON float in
the action payload falls outside the cross-platform canonicalization guarantee
and will observe payload-binding failures against implementations whose float
serializers differ. Any AAE-side encoding of the same action has to respect
this or the join key will not reproduce.

## The three composition cases

Both PSEA artifacts verify natively and both carry the *same* action digest.
What differs is which principal the AAE grant resolves to.

| ID | AAE grant principal | PSEA artifact | PSEA native | Expected composition |
|---|---|---|---|---|
| XP-1 | `principal-A` | PSEA-A (`principal-A`) | VERIFIED | **AUTHORIZED** |
| XP-2 | `principal-A` | PSEA-B (`principal-B`) | VERIFIED | **REFUSE** — `principal_divergence` |
| XP-3 | `unresolved` | PSEA-A (`principal-A`) | VERIFIED | **INDETERMINATE** |

**XP-1** — one human both mandated and approved. The composition authorizes.

**XP-2** — the interesting one. Both artifacts verify natively, and they join
on the same action digest, yet **no single human both mandated and approved the
action.** A relying party accepting a standing grant and a per-action proof
performs two independent key-to-principal resolutions — `principal_did`-to-
principal on the AAE side, `kid`-to-principal on the PSEA side. Both succeed;
nothing requires them to agree. A naive composition that checks "grant valid?"
and "proof valid?" and ANDs the answers returns AUTHORIZED here, which is
wrong. This is the class neither vector set currently carries, and it is the
reason the fixture exists.

**XP-3** — deliberately distinct from XP-2, and the distinction is the point.
XP-3 is INDETERMINATE, not REFUSE: the enrollment binding is not established on
one side, so the composition has no resolution to compare. **Absence of a
resolution is not divergence of resolutions.** Collapsing the two into one
outcome loses the difference between "these two artifacts name different
humans" (a detected conflict, fail closed) and "we cannot tell whose mandate
this is" (missing input, insufficient to decide). An implementation that
returns REFUSE for both is not more conservative in any useful sense — it
reports a conflict it did not observe, and a reviewer cannot distinguish the
two failure modes from the result.

Both non-AUTHORIZED outcomes are downstream of the enrollment gap described in
draft-yossif-enrollment-problem-00: the binding from an authenticator to a
named human is deployment-specific and out of PSEA's scope, so it appears here
twice, in two different shapes.

## What the fixture does and does not establish

PSEA's native verdict for PSEA-B in XP-2 is VERIFIED, and that is correct — the
proof is a valid PSEA proof. PSEA does not claim to identify a named human
(see the abstract, and Section 3.8: `psea_user_hash` is OPTIONAL and commits to
a deployment-issued subject identifier). The divergence in XP-2 is therefore
not a PSEA verification failure; it is a composition-layer failure that neither
profile detects alone. Nothing in this fixture should be read as PSEA claiming
to close it.

## Verifying the fixture

    cd conformance
    python3 -m pip install -r requirements.txt
    shasum -a 256 -c interop-aae/psea-fixture-v0.sha256

The values were checked against this repository's own reference code before
commit: the join key recomputed from `action_payload_cleartext` with
`src/jcs.py` (matching both `octets_hex` and `psea_wire_value`, and matching
the recorded `action_payload_jcs_utf8` byte-for-byte), and both tokens verified
with `src/psea.py` against `enrolled_keys[]` at a timestamp inside the
`iat`/`exp` window, each returning VERIFIED under the principal the fixture
claims.
