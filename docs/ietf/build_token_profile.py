"""
Build draft-yossif-psea-token-profile-00.xml from the source draft-02.xml.
Apply all 6 interop fixes for the token-profile doc.
"""
import re

SRC = "C:/Projects/yuthent_website/github-psea-spec/docs/ietf/draft-yossif-psea-02.xml"
OUT = "C:/Projects/yuthent_website/github-psea-spec/docs/ietf/draft-yossif-psea-token-profile-00.xml"

with open(SRC, "r", encoding="utf-8") as f:
    lines = f.readlines()

# ─── New front matter ────────────────────────────────────────────────────────
FRONT = """\
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE rfc [
  <!ENTITY nbsp    "&#160;">
  <!ENTITY zwsp   "&#8203;">
  <!ENTITY nbhy   "&#8209;">
  <!ENTITY wj     "&#8288;">
]>
<rfc version="3" ipr="trust200902" submissionType="IETF" category="std"
     docName="draft-yossif-psea-token-profile-00"
     xmlns:xi="http://www.w3.org/2001/XInclude">

  <front>
    <title abbrev="PSEA Token Profile">PSEA Token Profile: An EAT Profile for Action-Bound, User-Verification-Gated Transaction-Confirmation Evidence</title>

    <seriesInfo name="Internet-Draft" value="draft-yossif-psea-token-profile-00"/>

    <author fullname="Mohamad Khalil Yossif" initials="M. K." surname="Yossif">
      <organization>Yuthent</organization>
      <address>
        <email>mohamad@yuthent.com</email>
        <uri>https://yuthent.com/psea</uri>
      </address>
    </author>

    <date year="2026" month="May" day="26"/>

    <area>Security</area>
    <workgroup>Independent Submission</workgroup>

    <keyword>PSEA</keyword>
    <keyword>EAT profile</keyword>
    <keyword>transaction confirmation</keyword>
    <keyword>user verification</keyword>
    <keyword>action binding</keyword>
    <keyword>WYSIWYS</keyword>

    <abstract>
      <t>This document defines the PSEA Token Profile, a device-agnostic Entity Attestation Token
      (EAT) profile (per RFC 9711, Section 7) for action-bound, user-verification-gated
      transaction-confirmation Evidence.  The profile specifies the canonical encoding, signed proof
      token claim set, hash-chain integrity model, action-payload binding, cross-replay binding,
      and security properties that together constitute a What-You-Sign-Is-What-You-Execute proof
      that a human, present and verified at an authenticator, approved a specific named action at
      the moment of execution.  The profile is authenticator-agnostic: any authenticator capable of
      producing a user-verification-gated ES256 signature over a canonical action payload conforms,
      including smartphones, smartcards with PIN, FIDO security keys with user verification, and
      embedded secure elements.  The profile fills the transaction-confirmation gap left by the
      removal of the WebAuthn txAuthSimple and txAuthGeneric extensions, and complements OAuth 2.0
      Step-Up Authentication (RFC 9470) by supplying the per-action, cryptographically action-bound
      Evidence that step-up flows can require.</t>
    </abstract>
  </front>

  <middle>

"""

# ─── New introduction section ─────────────────────────────────────────────────
INTRO = """\
    <!-- =====================================================
         Section 1: Introduction
         ===================================================== -->
    <section anchor="introduction" numbered="true" toc="default">
      <name>Introduction</name>

      <t>Session-based authentication answers "did this entity present valid credentials at some
      point?"; execution-time authority answers "is an authorized human, present and verified,
      approving this specific action right now?".  The gap between these two questions is where
      session-hijacking, autonomous malware, and unattended-device risk materialize.  This document
      defines a token profile that fills that gap at the token layer: a signed EAT-profile token
      whose claim set constitutes cryptographic Evidence of execution authority at the moment of
      action, independent of prior session state.</t>

      <t>The signed token (ApprovalToken for the Explicit and Authoritative capability levels,
      PToken for Passive, SessionSummary for Silent) is a JWS Compact Serialization object
      (<xref target="RFC7515"/>) whose payload is an EAT-JSON claims-set.  The profile reuses the
      registered EAT claims <tt>ueid</tt>, <tt>eat_nonce</tt>, <tt>submods</tt>, and
      <tt>eat_profile</tt> (<xref target="RFC9711"/>) alongside JWT registered claims
      (<xref target="RFC7519"/>) and the PSEA-private <tt>psea_*</tt> extension claims defined in
      this document.</t>

      <t>The profile is authenticator-agnostic.  Any authenticator that can generate a hardware-
      backed, user-verification-gated ES256 signature over a canonical action payload conforms,
      including smartphones, FIDO2 security keys with user verification, smartcards with PIN, and
      embedded secure elements.  The deployment architecture -- including the operational four-tier
      P/S/E/A enforcement model, the HTTP verifier endpoints, the AttestationBlock wrapper, the
      Verifier Acknowledgement, and the trust-state model -- is informatively described in the
      companion Informational document [PSEA-ARCHITECTURE].</t>

      <t>The transaction-confirmation gap this profile addresses was previously targeted by the
      WebAuthn txAuthSimple and txAuthGeneric extensions, both of which were removed in Web
      Authentication Level 2 without widely deployed successors (<xref target="relationship-webauthn"/>).
      This profile complements OAuth 2.0 Step-Up Authentication (<xref target="RFC9470"/>) by
      providing the per-action, cryptographically action-bound Evidence token that a step-up
      challenge can require and a resource server can verify
      (<xref target="relationship-rfc9470"/>).</t>

      <section anchor="terminology" numbered="true" toc="default">
        <name>Requirements Language</name>

        <t>The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
        "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
        "OPTIONAL" in this document are to be interpreted as described in
        BCP&nbsp;14 <xref target="RFC2119"/> <xref target="RFC8174"/> when, and
        only when, they appear in all capitals, as shown here.</t>
      </section>

      <section anchor="glossary" numbered="true" toc="default">
        <name>Terminology</name>

        <t>This document uses the following terms.  RATS terminology follows
        <xref target="RFC9334"/>; PSEA-specific terms are defined here.</t>

        <dl>
          <dt>Attester</dt>
          <dd>The trust-anchor authenticator that generates Evidence by signing a proof token with a
          hardware-protected, user-verification-gated key.  The Attester MAY be a smartphone, a
          smartcard with PIN, a FIDO security key with user verification, an embedded secure element,
          or any equivalent authenticator.  A natural person is not an Attester.</dd>

          <dt>Verifier</dt>
          <dd>The server-side component that appraises Evidence and produces Attestation Results.
          The deployment architecture for the Verifier is described in [PSEA-ARCHITECTURE].</dd>

          <dt>Relying Party</dt>
          <dd>The application server that gates the action on the Verifier's Attestation Result.</dd>

          <dt>Subject (of Evidence)</dt>
          <dd>The natural person whose presence and intent the Attester's Evidence makes claims about.</dd>

          <dt>Evidence</dt>
          <dd>The signed proof token an Attester produces per this profile.  Evidence types:
          ApprovalToken (for the Explicit and Authoritative capability levels), PToken (Passive),
          and SessionSummary (Silent).  See <xref target="proof-token-format"/>.</dd>

          <dt>Attestation Result</dt>
          <dd>The integrity-protected artifact the Verifier produces and returns to the Relying Party.</dd>

          <dt>Endorsement</dt>
          <dd>A trust anchor the Verifier uses to appraise Evidence (for example, an Android Key
          Attestation root, an Apple App Attest root, a FIDO authenticator vendor root, or a
          smartcard issuer root).</dd>

          <dt>action / action payload</dt>
          <dd>The specific operation the Subject approves.  The canonical encoding of the action
          payload is hashed and included in the signed Evidence body (see
          <xref target="action-binding"/>).</dd>

          <dt>capability level</dt>
          <dd>One of the four PSEA capability levels: Passive (P), Silent (S), Explicit (E),
          Authoritative (A).  The claim <tt>psea_tier</tt> carries an abstract capability-level
          label bound into the signature.  The operational tier enforcement model that maps
          applications to capability levels is described informatively in [PSEA-ARCHITECTURE].</dd>
        </dl>
      </section>
    </section>

"""

# ─── Line index helpers ──────────────────────────────────────────────────────
# All 0-indexed
# front matter: 0-49 -> replaced by FRONT
# <middle>: line 50 -> included in FRONT
# blank line 51: skip
# comment + section intro start at 52
# introduction section: 55-184 -> replaced by INTRO
# psea-architecture: 185-567 -> DELETED
# canonical-encoding: 568-708 -> KEPT
# proof-token-format: 709-1705
#   ack-format: 1098-1158 -> DELETED
#   attestation-block+appraisal: 1159-1211 -> DELETED
# enforcement-tiers: 1706-2088 -> DELETED
# state-systems: 2089-2337 -> DELETED
# verifier-endpoints: 2337-2449 -> DELETED
# error-code-registry: 2449-2689 -> DELETED
# security-considerations: 2690-2945 -> KEPT
# privacy-considerations: 2946-3023 -> KEPT
# iana: 3024-3128 but remove iana-error-code (3055-3086) -> partial KEPT
# algorithm-agility: 3133-3189 -> KEPT
# </middle>: 3190 -> KEPT
# <back>: 3192-end -> references (filtered) + appendices + citation

# Collect the content chunks
out_parts = []

# 1. New front matter (replaces lines 0-49 + <middle> line 50 + blank 51)
out_parts.append(FRONT)

# 2. New introduction (replaces lines 52-184; but lines 52-54 are comment lines for intro)
out_parts.append(INTRO)

# 3. canonical-encoding section: lines 568-708 (0-indexed)
out_parts.append("".join(lines[568:709]))

# 4. proof-token-format: lines 709-1097 (before ack-format), then lines 1212-1705 (after attestation-block)
# But we also need to apply interop fix for this section
chunk_ptf_a = "".join(lines[709:1098])   # proof-token-format header through envelope-schemas
chunk_ptf_b = "".join(lines[1212:1706])  # presence-via-signature through end of proof-token-format

out_parts.append(chunk_ptf_a)
out_parts.append(chunk_ptf_b)

# 4b. relationship-webauthn: lines 447-474 (0-indexed 446-473)
# and relationship-rfc9470: lines 476-563 (0-indexed 475-562)
# These are in psea-architecture in source but belong in DOC 1 per spec
out_parts.append("".join(lines[446:474]))
out_parts.append("".join(lines[475:563]))

# 5. security-considerations: lines 2690-2945
out_parts.append("".join(lines[2690:2946]))

# 6. privacy-considerations: lines 2946-3023
out_parts.append("".join(lines[2946:3024]))

# 7. iana section: 3024-3128 but delete iana-error-code (lines 3055-3086 inclusive)
# Also update registries-overview summary to remove error-code mention
iana_chunk = "".join(lines[3024:3055]) + "".join(lines[3087:3129])
out_parts.append(iana_chunk)

# 8+9. algorithm-agility through </middle> and blank line:
# 0-indexed 3133 through 3190 inclusive
out_parts.append("".join(lines[3133:3191]))

# 10. <back> opening: 0-indexed 3191 = "  <back>\n", 3192 = "\n"
out_parts.append("".join(lines[3191:3193]))

# 11. References section complete (0-indexed 3193 to 3362 inclusive = lines 3194-3363)
# 0-indexed 3193 = "    <references>\n" through 3363 = "    </references>\n"
out_parts.append("".join(lines[3193:3364]))

# 13. appendix-canonical-test-vectors: comment + section (0-indexed 3364-3410)
out_parts.append("".join(lines[3364:3411]))

# 14. appendix-conformance: comment + section (0-indexed 3411-3505)
out_parts.append("".join(lines[3411:3506]))

# 15. citation (updated)
CITATION = """    <!-- =====================================================
         Appendix C: Citation and Reference
         ===================================================== -->
    <section anchor="citation" numbered="true" toc="default">
      <name>Citation and Reference</name>

      <t>Citation suggestion (BibTeX):</t>

      <sourcecode type="bibtex"><![CDATA[
@misc{yossif-psea-token-profile-00,
  author       = "Mohamad Khalil Yossif",
  title        = "PSEA Token Profile: An EAT Profile for Action-Bound,
                  User-Verification-Gated Transaction-Confirmation Evidence",
  series       = "Internet-Draft draft-yossif-psea-token-profile-00",
  publisher    = "Internet Engineering Task Force",
  year         = "2026",
  month        = "May",
  howpublished = "https://datatracker.ietf.org/doc/draft-yossif-psea-token-profile-00/"
}
]]></sourcecode>
    </section>

  </back>
</rfc>
"""
out_parts.append(CITATION)

# ─── Join and apply interop fixes ────────────────────────────────────────────
doc = "".join(out_parts)

# FIX 1: eat_nonce — the endpoint-nonce section has "nonce" field references.
# In the proof-schema JSON Schema, eat_nonce is already correct (it's named eat_nonce).
# The /attest/nonce endpoint section references "nonce" field in the signed body — this section
# is in verifier-endpoints which goes to DOC 2, not here. So in DOC 1, just verify eat_nonce
# is correct in proof-schema and proof-top-level artwork. The artwork at lines 813 already
# says eat_nonce. The proof-schema at lines 998-1000 already says eat_nonce. Good.
# Add eat_nonce to the JSON Schema required-when-present description (it's already optional).
# The interop fix for DOC 1: ensure the JSON Schema explicitly has eat_nonce as optional string.
# Already in the schema at line 998: "eat_nonce": { "type": "string", ... } - correct.

# FIX 3: psea_counter large-integer hazard
# Add a normative paragraph to counter-model section.
# Find the end of counter-model section (before chain-entry section)
counter_insert = (
    "        <t><strong>Interoperability bound (normative):</strong> Producers "
    "<bcp14>MUST</bcp14> emit <tt>psea_counter</tt> as a JSON integer in the range\n"
    "        [0, 2<sup>53</sup> &#8722; 1] (inclusive) so that the value round-trips losslessly\n"
    "        through IEEE 754 double-precision JSON parsers.  Verifiers "
    "<bcp14>MUST</bcp14> treat the claim\n"
    "        as a 64-bit unsigned integer for comparison purposes.  This profile does not "
    "string-encode\n"
    "        the counter; a string-valued <tt>psea_counter</tt> is non-conformant.  "
    "The reference\n"
    "        implementation never approaches the 2<sup>53</sup> bound at any reasonable "
    "operational\n"
    "        rate, but producers <bcp14>MUST</bcp14> enforce this bound explicitly.</t>\n"
)
# Insert before the closing </section> of counter-model
doc = doc.replace(
    "        <t>The five-counter design is intentional: it scopes the monotonic replay anchor per risk level\n"
    "        rather than using a single per-Attester counter, which is what preserves independent offline\n"
    "        progress across tiers (see the rationale above).</t>\n"
    "      </section>\n"
    "\n"
    "      <section anchor=\"chain-entry\"",
    "        <t>The five-counter design is intentional: it scopes the monotonic replay anchor per risk level\n"
    "        rather than using a single per-Attester counter, which is what preserves independent offline\n"
    "        progress across tiers (see the rationale above).</t>\n"
    "\n"
    + counter_insert +
    "      </section>\n"
    "\n"
    "      <section anchor=\"chain-entry\""
)

# FIX 4: Test vector timestamps — fix millisecond epoch values to seconds
# The test vector at appendix has 1700000060000 and 1700000000000 (milliseconds)
# Fix: 1700000060000 -> 1700000060, 1700000000000 -> 1700000000
doc = doc.replace('"endedAt":   1700000060000', '"endedAt":   1700000060')
doc = doc.replace('"startedAt": 1700000000000', '"startedAt": 1700000000')
doc = doc.replace('"endedAt":1700000060000', '"endedAt":1700000060')
doc = doc.replace('"startedAt":1700000000000', '"startedAt":1700000000')
# Also fix in the canonical bytes line
doc = doc.replace(',"endedAt":1700000060000,', ',"endedAt":1700000060,')
doc = doc.replace(',"startedAt":1700000000000}', ',"startedAt":1700000000}')

# FIX 5: psea_payload_hash encoding — add explicit normative text about the base64 split.
# Find the psea_payload_hash description in the proof-top-level artwork and proof-schema.
# The artwork already says "psea_payload_hash uses standard base64 (with padding)".
# Add a dedicated paragraph to the proof-schema section (proof-top-level) making this normative.
# Insert after the "Encoding split:" note in the artwork (line 853-855 of original):
# The artwork already has the note. Add a normative paragraph after the artwork figure closes.

split_para = (
    "\n"
    "        <t><strong>Base64 encoding split (normative):</strong> "
    "<tt>psea_payload_hash</tt> <bcp14>MUST</bcp14> be encoded as\n"
    "        standard base64 (RFC 4648, Section 4) with padding (the pattern "
    "<tt>^[A-Za-z0-9+/]{43}=$</tt>).\n"
    "        <tt>ueid</tt> and <tt>psea_user_hash</tt> <bcp14>MUST</bcp14> be encoded as "
    "base64url (RFC 4648, Section 5) without\n"
    "        padding.  This is a deliberate per-claim encoding split that implementers "
    "<bcp14>MUST</bcp14> observe\n"
    "        exactly; using base64url for <tt>psea_payload_hash</tt> or standard base64 "
    "for <tt>ueid</tt> or\n"
    "        <tt>psea_user_hash</tt> produces a non-conformant token.</t>\n"
)

# Insert the paragraph after the closing ]]></artwork> of fig-proof-structure
doc = doc.replace(
    "NOTE on chainEntry: chainEntry is NOT carried inbound. The Attester\n"
    "sends psea_chain_prev IN the signed payload (the prior proof's\n"
    "chainEntry, or the sentinel for the first proof). The Verifier\n"
    "computes this proof's chainEntry from the signed inputs (Section 4.8)\n"
    "and returns it inside the signed JWS acknowledgement; the SDK\n"
    "persists it as the next proof's psea_chain_prev.\n"
    "]]></artwork>\n"
    "        </figure>\n",
    "NOTE on chainEntry: chainEntry is NOT carried inbound. The Attester\n"
    "sends psea_chain_prev IN the signed payload (the prior proof's\n"
    "chainEntry, or the sentinel for the first proof). The Verifier\n"
    "computes this proof's chainEntry from the signed inputs (Section 4.8)\n"
    "and returns it inside the signed JWS acknowledgement; the SDK\n"
    "persists it as the next proof's psea_chain_prev.\n"
    "]]></artwork>\n"
    "        </figure>\n"
    + split_para
)

# ─── Fix dangling xrefs that pointed to deleted sections ─────────────────────
# ack-format and attestation-block are now in PSEA-ARCHITECTURE
# Replace xrefs to these deleted anchors with prose referencing [PSEA-ARCHITECTURE]
doc = doc.replace('<xref target="ack-format"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="attestation-block"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="attestation-block-appraisal"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="enforcement-tiers"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="tier-p"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="tier-s"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="tier-e"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="tier-a"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="tier-negotiation"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="tier-conformance"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="state-verifier-lifecycle"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="state-attester-local-gating"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="state-wire-commitment"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="verifier-endpoints"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="endpoint-verify"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="endpoint-enroll"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="endpoint-nonce"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="error-code-registry"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="tier-s-lifecycle"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="tier-s-signature-gate"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="tier-s-sessionsummary"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="psea-architecture"/>', '[PSEA-ARCHITECTURE]')
doc = doc.replace('<xref target="rats-role-mapping"/>', '[PSEA-ARCHITECTURE]')

# Fix xrefs to sections that live in DOC 2 (architectural-principles subsections)
doc = doc.replace('<xref target="human-presence"/>', '<xref target="PSEA-ARCHITECTURE"/>')
doc = doc.replace('<xref target="connectivity-independence"/>', '<xref target="PSEA-ARCHITECTURE"/>')
doc = doc.replace('<xref target="execution-time-proof"/>', '<xref target="PSEA-ARCHITECTURE"/>')
doc = doc.replace('<xref target="device-bound-trust"/>', '<xref target="PSEA-ARCHITECTURE"/>')
doc = doc.replace('<xref target="cryptographic-proof"/>', '<xref target="PSEA-ARCHITECTURE"/>')
doc = doc.replace('<xref target="architectural-principles"/>', '<xref target="PSEA-ARCHITECTURE"/>')

# Fix self-referential section refs that still use numbers from source doc
doc = doc.replace('Sections 3 through 8 of this document', 'the normative sections of this document')
doc = doc.replace('in Sections 3 through 8', 'in the normative sections of this document')
doc = doc.replace('(Section 4.5)', '([PSEA-ARCHITECTURE])')
doc = doc.replace('(Section 4.9)', '(<xref target="action-binding"/>)')
doc = doc.replace('(Section 4.9.5)', '(<xref target="cross-replay-binding"/>)')
doc = doc.replace('(Section 4.6.1)', '(<xref target="presence-uv-claim"/>)')
doc = doc.replace('(Section 4.8)', '(<xref target="chain-entry"/>)')

# Fix IANA registries-overview: remove the error-code registry mention
doc = doc.replace(
    "        <t>This document requests IANA to establish two new registries, register one media type, and\n"
    "        register a URN sub-namespace:</t>\n"
    "        <ul>\n"
    "          <li>The PSEA Attestation Source Registry (<xref target=\"iana-attestation-source\"/>).</li>\n"
    "          <li>The PSEA Error Code Registry (<xref target=\"iana-error-code\"/>).</li>\n"
    "          <li>One media-type registration (<xref target=\"iana-media-types\"/>).</li>\n"
    "          <li>Registration of the <tt>urn:ietf:params:psea</tt> URN sub-namespace\n"
    "          (<xref target=\"iana-urn-namespace\"/>).</li>\n"
    "        </ul>",
    "        <t>This document requests IANA to establish one new registry, register one media type, and\n"
    "        register a URN sub-namespace:</t>\n"
    "        <ul>\n"
    "          <li>The PSEA Attestation Source Registry (<xref target=\"iana-attestation-source\"/>).</li>\n"
    "          <li>One media-type registration (<xref target=\"iana-media-types\"/>).</li>\n"
    "          <li>Registration of the <tt>urn:ietf:params:psea</tt> URN sub-namespace\n"
    "          (<xref target=\"iana-urn-namespace\"/>).</li>\n"
    "        </ul>"
)

# Fix URN namespace repository description that referenced iana-error-code
doc = doc.replace(
    "          <dd>The PSEA Error Code Registry (<xref target=\"iana-error-code\"/>) and the PSEA Attestation\n"
    "          Source Registry (<xref target=\"iana-attestation-source\"/>), plus identifier strings assigned\n"
    "          under <tt>urn:ietf:params:psea</tt> by this and future PSEA documents.</dd>",
    "          <dd>The PSEA Attestation Source Registry (<xref target=\"iana-attestation-source\"/>), plus\n"
    "          identifier strings assigned under <tt>urn:ietf:params:psea</tt> by this and future PSEA\n"
    "          documents.  The PSEA Error Code Registry is established by [PSEA-ARCHITECTURE].</dd>"
)

# Fix attestation-source table reference pointing to deleted attestation-block section
doc = doc.replace(
    "              <td>This document, <xref target=\"attestation-block\"/></td>",
    "              <td>This document, [PSEA-ARCHITECTURE]</td>"
)

# psea_tier in cross-replay section: describe as abstract capability-level label, not product tier
# The cross-replay-binding section already describes them abstractly enough for this doc.
# The psea_tier values "E"/"A"/"P"/"S" are in the signed claim set so they stay.
# We just need to ensure the text doesn't call them "product SKUs" - the source text doesn't.

# Fix conformance appendix: references to tier-s-signature-gate and action-binding-verifier
# those internal anchors still exist in the doc so xrefs are fine.
# conformance references state-verifier-lifecycle -> [PSEA-ARCHITECTURE] - already fixed above.
# conformance references state-attester-local-gating -> [PSEA-ARCHITECTURE] - already fixed above.

# Fix presence-via-signature: references to AttestationBlock -> [PSEA-ARCHITECTURE]
doc = doc.replace(
    "AttestationBlock (<xref target=\"attestation-block\"/>)",
    "AttestationBlock ([PSEA-ARCHITECTURE])"
)
doc = doc.replace(
    "attested through the\n"
    "          platform attestation.\n"
    "          AttestationBlock (<xref target=\"attestation-block\"/>) and the deployment's Reference Values).",
    "attested through the\n"
    "          platform attestation.\n"
    "          AttestationBlock ([PSEA-ARCHITECTURE]) and the deployment's Reference Values)."
)

# Catch-all: any remaining [PSEA-ARCHITECTURE] should be a proper reference
# For xml2rfc, bare [PSEA-ARCHITECTURE] in text is fine as informative notation (not an xref)
# but ideally we'd have a reference entry. Add PSEA-ARCHITECTURE to informative references.

# Add PSEA-ARCHITECTURE reference entry to informative references section
psea_arch_ref = """\
        <reference anchor="PSEA-ARCHITECTURE">
          <front>
            <title>Post-Session Execution Assurance (PSEA): A Deployment Architecture for the PSEA Token Profile</title>
            <author fullname="Mohamad Khalil Yossif" initials="M. K." surname="Yossif">
              <organization>Yuthent</organization>
            </author>
            <date year="2026" month="May"/>
          </front>
          <seriesInfo name="Internet-Draft" value="draft-yossif-psea-architecture-00"/>
        </reference>

"""

doc = doc.replace(
    "        <reference anchor=\"RFC4846\"",
    psea_arch_ref + "        <reference anchor=\"RFC4846\""
)

# Now replace all [PSEA-ARCHITECTURE] text references with proper xref
doc = doc.replace("[PSEA-ARCHITECTURE]", "<xref target=\"PSEA-ARCHITECTURE\"/>")

# Remove unused references in DOC 1 (RFC4846 and RFC6819 only cited in architecture sections)
import re as _re
def remove_reference_block(d, anchor):
    # Remove <reference anchor="ANCHOR" ...> ... </reference>\n from the doc
    pat = _re.compile(
        r'\s*<reference anchor="' + _re.escape(anchor) + r'"[^>]*>.*?</reference>\n',
        _re.DOTALL
    )
    return pat.sub('\n', d)

doc = remove_reference_block(doc, "RFC4846")
doc = remove_reference_block(doc, "RFC6819")

# Write output
with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write(doc)

print(f"Written {len(doc)} chars to {OUT}")
print("Line count:", doc.count("\n"))
