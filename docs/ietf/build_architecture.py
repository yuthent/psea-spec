"""
Build draft-yossif-psea-architecture-00.xml from the source draft-02.xml.
Apply interop fixes 2, 6 (rolling hash) for the architecture doc.
"""
import re

SRC = "C:/Projects/yuthent_website/github-psea-spec/docs/ietf/draft-yossif-psea-02.xml"
OUT = "C:/Projects/yuthent_website/github-psea-spec/docs/ietf/draft-yossif-psea-architecture-00.xml"

with open(SRC, "r", encoding="utf-8") as f:
    lines = f.readlines()

# ─── New front matter ─────────────────────────────────────────────────────────
FRONT = """\
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE rfc [
  <!ENTITY nbsp    "&#160;">
  <!ENTITY zwsp   "&#8203;">
  <!ENTITY nbhy   "&#8209;">
  <!ENTITY wj     "&#8288;">
]>
<rfc version="3" ipr="trust200902" submissionType="IETF" category="info"
     docName="draft-yossif-psea-architecture-00"
     xmlns:xi="http://www.w3.org/2001/XInclude">

  <front>
    <title abbrev="PSEA Architecture">Post-Session Execution Assurance (PSEA): A Deployment Architecture for the PSEA Token Profile</title>

    <seriesInfo name="Internet-Draft" value="draft-yossif-psea-architecture-00"/>

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
    <keyword>execution assurance</keyword>
    <keyword>session security</keyword>
    <keyword>authentication</keyword>
    <keyword>authority verification</keyword>
    <keyword>RATS</keyword>

    <abstract>
      <t>This document is Informational and describes a concrete deployment architecture for the
      PSEA Token Profile [PSEA-TOKEN-PROFILE].  The architecture defines the four-tier P/S/E/A
      enforcement model (Passive, Silent, Explicit, Authoritative), the HTTP Verifier endpoints
      used to submit Evidence, the AttestationBlock wrapper for platform attestation tokens, the
      Verifier Acknowledgement (ACK) format, the error-code registry, and the operational
      trust-state model.  All token-level definitions -- canonical encoding, proof claim sets,
      hash-chain model, action-payload binding, EAT profile declaration, security and privacy
      considerations, and algorithm agility -- are normatively defined in [PSEA-TOKEN-PROFILE];
      this document references those definitions and describes how they are operationalized in
      a conforming deployment.</t>
    </abstract>
  </front>

  <middle>

"""

# ─── New Introduction ─────────────────────────────────────────────────────────
# We keep the original introduction from the source (the authority-gap narrative belongs here)
# Source intro: lines 56-181 (0-indexed 55-180)
# We replace only the front-matter <rfc> block (lines 0-49) and keep <middle> (line 50)
# and the introduction section as-is, except for document-scope updates.

# Source intro block: lines 55-184 (0-indexed), but we update document-scope text.

# Actually: keep the full introduction from source (lines 56-185 0-indexed 55-184)
# Then add psea-architecture section (lines 186-567 0-indexed 185-566) - but update
# the reference to "Sections 3 through 8 of this document" -> reference to PSEA-TOKEN-PROFILE
# Then add: architectural-principles (314-417 0-indexed 313-416) -- these are subsections of psea-architecture
# Then: what-psea-is-not (419-445 0-indexed 418-444)
# Then: attestation-block + appraisal (1160-1212 0-indexed 1159-1211) -- extracted from proof-token-format
# Then: ack-format (1099-1159 0-indexed 1098-1158) -- extracted from proof-token-format
# Then: enforcement-tiers (1707-2089 0-indexed 1706-2088)
# Then: state-systems (2090-2338 0-indexed 2089-2337)
# Then: verifier-endpoints (2338-2451 0-indexed 2337-2450)
# Then: error-code-registry + audit-labels (2451-2690 0-indexed 2450-2689)
# Then: iana (only iana-error-code subsection, plus overview)
# Then: </middle>
# Then: <back> + references (filtered) + citation

# The source psea-architecture section is 185-567 (0-indexed).
# This includes: rats-role-mapping, rats-passport-model, rats-data-flow, rats-colocation,
# rats-subject, architectural-principles (with all subsections), what-psea-is-not,
# relationship-webauthn, relationship-rfc9470.
# Per DOC 2 spec: keep psea-architecture + all subsections EXCEPT relationship-webauthn
# and relationship-rfc9470 (those go to DOC 1). Keep what-psea-is-not.

# So DOC 2 architecture section: lines 185-445 (0-indexed), skipping 446-562 (webauthn+rfc9470)

out_parts = []

# 1. New front matter
out_parts.append(FRONT)

# 2. Introduction + subsections: 0-indexed 55-184 (lines 56-185)
# Update the document-scope subsection to reference PSEA-TOKEN-PROFILE
out_parts.append("".join(lines[55:185]))

# 3. psea-architecture: 0-indexed 185-444 (lines 186-445)
# This covers: rats-role-mapping through what-psea-is-not (EXCLUDING relationship-webauthn/rfc9470)
out_parts.append("".join(lines[185:445]))

# 4. Close psea-architecture section -- the original closes at 0-indexed 563 just before "canonical-encoding"
# But we're cutting off at 444 (before relationship-webauthn). We need to close the psea-architecture
# section properly. The section closes are embedded. Let's check what's at 444-447:
# line 444 (0-idx) = end of what-psea-is-not
# line 445 (0-idx) = blank line after what-psea-is-not / before relationship-webauthn
# Actually what-psea-is-not section closes at line 445 (0-idx). The psea-architecture section
# closes at 0-idx 563 (just before canonical-encoding). By not including relationship-webauthn+rfc9470
# we need to add </section> to close psea-architecture.
# Let's look at what's around 444:
import sys
for i in range(441, 450):
    sys.stderr.write(f"  {i+1}: {repr(lines[i])}\n")

# 4b. Check if we need a closing </section> for psea-architecture
# The what-psea-is-not section (418-444 0-indexed) already ends with </section>
# The psea-architecture section itself needs a </section> -- which was originally at line 564 (0-indexed 563)
# We need to insert that.
out_parts.append("    </section>\n\n")  # close psea-architecture

# 5. ack-format: 0-indexed 1098-1158 (from proof-token-format)
out_parts.append("".join(lines[1098:1159]))

# 6. attestation-block + attestation-block-appraisal: 0-indexed 1159-1211
out_parts.append("".join(lines[1159:1212]))

# 7. enforcement-tiers: comment at 0-idx 1703, section opens 1706, closes at 0-idx 2084 inclusive
# Include through blank line at 0-idx 2085
out_parts.append("".join(lines[1703:2086]))

# 8. state-systems: comment at 0-idx 2086, section opens 2089, closes at 0-idx 2332 inclusive
# Include through blank line at 0-idx 2333
out_parts.append("".join(lines[2086:2334]))

# 9. verifier-endpoints: comment at 0-idx 2334, section opens 2337, closes at 0-idx 2445 inclusive
# Include through blank line at 0-idx 2446
out_parts.append("".join(lines[2334:2447]))

# 10. error-code-registry + audit-labels: comment at 0-idx 2447, section opens 2450,
# closes at 0-idx 2685 inclusive; include through blank at 0-idx 2686
out_parts.append("".join(lines[2447:2687]))

# 11. IANA section: only the error-code registry subsection
# iana section is 0-indexed 3024-3128
# iana-registries-overview: 3027-3040
# iana-error-code: 3055-3086
# We build a custom IANA section for DOC 2 with just the error-code registry
IANA_DOC2 = """\
    <!-- =====================================================
         IANA Considerations
         ===================================================== -->
    <section anchor="iana" numbered="true" toc="default">
      <name>IANA Considerations</name>

      <section anchor="iana-registries-overview" numbered="true">
        <name>Summary of Requested Registries</name>
        <t>This document requests IANA to establish one new registry:</t>
        <ul>
          <li>The PSEA Error Code Registry (<xref target="iana-error-code"/>).</li>
        </ul>
        <t>The PSEA Attestation Source Registry, the media-type registration, and the
        <tt>urn:ietf:params:psea</tt> URN sub-namespace registration are requested by
        [PSEA-TOKEN-PROFILE].</t>
      </section>

"""
out_parts.append(IANA_DOC2)
# Append the iana-error-code subsection: 0-indexed 3055-3086
out_parts.append("".join(lines[3055:3087]))
# Close iana section
out_parts.append("    </section>\n\n")

# 12. </middle>
out_parts.append("  </middle>\n\n")

# 13. <back>
out_parts.append("  <back>\n\n")

# 14. References - keep all from source; add PSEA-TOKEN-PROFILE entry
# References: 0-indexed 3193-3363
out_parts.append("".join(lines[3193:3364]))

# 15. citation (updated for DOC 2)
CITATION_DOC2 = """    <!-- =====================================================
         Appendix: Citation and Reference
         ===================================================== -->
    <section anchor="citation" numbered="true" toc="default">
      <name>Citation and Reference</name>

      <t>Citation suggestion (BibTeX):</t>

      <sourcecode type="bibtex"><![CDATA[
@misc{yossif-psea-architecture-00,
  author       = "Mohamad Khalil Yossif",
  title        = "Post-Session Execution Assurance (PSEA): A Deployment Architecture
                  for the PSEA Token Profile",
  series       = "Internet-Draft draft-yossif-psea-architecture-00",
  publisher    = "Internet Engineering Task Force",
  year         = "2026",
  month        = "May",
  howpublished = "https://datatracker.ietf.org/doc/draft-yossif-psea-architecture-00/"
}
]]></sourcecode>
    </section>

  </back>
</rfc>
"""
out_parts.append(CITATION_DOC2)

# ─── Join ───────────────────────────────────────────────────────────────────
doc = "".join(out_parts)

# ─── Interop fixes for DOC 2 ────────────────────────────────────────────────

# FIX 1 (DOC 2 part): error registry references to "nonce" field -> eat_nonce
# The endpoint-nonce section at /attest/nonce references "nonce" field in the signed body.
# This is in verifier-endpoints. Fix the prose to say eat_nonce.
doc = doc.replace(
    'the signed body\'s <tt>nonce</tt> field; the Verifier MUST reject\n'
    '        any proof whose <tt>nonce</tt> does not match or has expired (response codes\n'
    '        <tt>NONCE_EXPIRED</tt>, <tt>NONCE_REQUIRED</tt>, <tt>NONCE_MISMATCH</tt>;',
    'the signed body\'s <tt>eat_nonce</tt> field; the Verifier MUST reject\n'
    '        any proof whose <tt>eat_nonce</tt> does not match or has expired (response codes\n'
    '        <tt>NONCE_EXPIRED</tt>, <tt>NONCE_REQUIRED</tt>, <tt>NONCE_MISMATCH</tt>;'
)
# Also fix error-code table: NONCE_* codes reference "nonce" -> eat_nonce
doc = doc.replace(
    '<td>The signed body\'s "nonce" does not match the Verifier-issued nonce for this\n'
    '            action.</td>',
    '<td>The signed body\'s <tt>eat_nonce</tt> field does not match the Verifier-issued nonce '
    'for this\n            action.</td>'
)
doc = doc.replace(
    '<td>The associated action request carried a server-issued nonce, but the signed body does\n'
    '            not.</td>',
    '<td>The associated action request carried a server-issued <tt>eat_nonce</tt>, '
    'but the signed body does\n            not carry <tt>eat_nonce</tt>.</td>'
)

# FIX 2 (DOC 2): psea_verdict and psea_policy_verdict normative enumeration in ack-format
# Find the ack-format section and add normative text about verdict values.
# Insert normative paragraph after the psea_verdict and psea_policy_verdict descriptions.
doc = doc.replace(
    '          <dt><tt>psea_verdict</tt></dt>\n'
    '          <dd>The Verifier\'s decision for the appraised proof.</dd>\n',
    '          <dt><tt>psea_verdict</tt></dt>\n'
    '          <dd>The Verifier\'s decision for the appraised proof.  <bcp14>MUST</bcp14> be '
    'the fixed string literal <tt>"ACK"</tt>.\n'
    '          A signed ACK always carries <tt>psea_verdict == "ACK"</tt>; rejection responses '
    'use a different\n'
    '          non-ACK response path and do not carry this payload.  '
    'Implementations <bcp14>MUST</bcp14> reject any ACK\n'
    '          token whose <tt>psea_verdict</tt> is absent or is any value other than '
    '<tt>"ACK"</tt>.</dd>\n'
)
doc = doc.replace(
    '          <dt><tt>psea_policy_verdict</tt></dt>\n'
    '          <dd>The deployment policy evaluation result for this action.</dd>\n',
    '          <dt><tt>psea_policy_verdict</tt></dt>\n'
    '          <dd>The deployment policy evaluation result for this action.  '
    'When present, its <tt>decision</tt>\n'
    '          field <bcp14>MUST</bcp14> be one of exactly: <tt>"APPROVE"</tt>, '
    '<tt>"STEP_UP"</tt>, or <tt>"DENY"</tt>.  These\n'
    '          are a closed value set; no other values are defined.  The '
    '<tt>psea_policy_verdict</tt> object\n'
    '          also carries a <tt>reasons</tt> array of <tt>{code, humanText}</tt> objects.  '
    'The internal\n'
    '          evaluator verb <tt>WEBHOOK_HANDOFF</tt> is always resolved to either '
    '<tt>APPROVE</tt> or <tt>DENY</tt>\n'
    '          before signing when a step-up webhook is configured; <tt>STEP_UP</tt> '
    'passes through as-is.\n'
    '          <tt>psea_policy_verdict</tt> is omitted entirely on reject '
    'responses (where no ACK is signed).\n'
    '          Implementations <bcp14>MUST</bcp14> treat an unrecognized '
    '<tt>decision</tt> value as an error.</dd>\n'
)

# FIX 6 (DOC 2): psea_rolling_hash canonical concatenation formula in tier-s-sessionsummary
# Find the psea_rolling_hash description and add the canonical formula plus the self-assertion note.
doc = doc.replace(
    '            <dt>psea_rolling_hash</dt>\n'
    '            <dd>base64 of SHA-256 over a canonical concatenation of action identifiers (producer-defined,\n'
    '            but MUST be deterministic across replays of the same session).</dd>\n',
    '            <dt>psea_rolling_hash</dt>\n'
    '            <dd>Standard base64 (RFC 4648, Section 4) with padding of the SHA-256 over a canonical\n'
    '            concatenation of action identifier hashes.  The canonical formula is: (1) collect the\n'
    '            SHA-256 hash string for each in-session action, (2) sort those hash strings in ascending\n'
    '            lexicographic order, (3) join with ":" as separator and append a trailing ":", (4) compute\n'
    '            SHA-256 over the UTF-8 bytes of the joined string, (5) encode as standard base64 with\n'
    '            padding.  When the in-session action list is empty, <tt>psea_rolling_hash</tt> '
    '<bcp14>MUST</bcp14> be the\n'
    '            empty string.  The producer <bcp14>MUST</bcp14> use this formula deterministically;\n'
    '            replay of the same session yields the same hash.\n'
    '            <strong>Verifier non-verification (normative):</strong> the Verifier does not\n'
    '            recompute or verify <tt>psea_rolling_hash</tt>.  It is carried as a self-asserted\n'
    '            audit digest, not a server-verified security binding.  S-tier audit-trail integrity\n'
    '            for the rolling hash is therefore self-asserted; the authoritative integrity boundary\n'
    '            for Tier S is the SessionSummary JWS signature\n'
    '            (<xref target="tier-s-signature-gate"/>).</dd>\n'
)

# ─── Add PSEA-TOKEN-PROFILE normative reference ───────────────────────────────
psea_token_ref = """\
        <reference anchor="PSEA-TOKEN-PROFILE">
          <front>
            <title>PSEA Token Profile: An EAT Profile for Action-Bound, User-Verification-Gated Transaction-Confirmation Evidence</title>
            <author fullname="Mohamad Khalil Yossif" initials="M. K." surname="Yossif">
              <organization>Yuthent</organization>
            </author>
            <date year="2026" month="May"/>
          </front>
          <seriesInfo name="Internet-Draft" value="draft-yossif-psea-token-profile-00"/>
        </reference>

"""
doc = doc.replace(
    '        <reference anchor="RFC2119"',
    psea_token_ref + '        <reference anchor="RFC2119"'
)

# ─── Fix xrefs pointing to sections that live in PSEA-TOKEN-PROFILE ──────────
# In DOC 2, sections like canonical-encoding, proof-token-format, proof-top-level,
# chain-entry, action-binding, etc. are in DOC 1.
xrefs_to_token_profile = [
    "iana-attestation-source", "operational-defaults",
    "canonical-encoding", "canonical-encoding-numbers", "canonical-encoding-keys",
    "proof-token-format", "proof-top-level", "eat-profile",
    "proof-schema", "envelope-schemas",
    "chain-entry", "chain-formula", "chain-sentinel", "chain-verifier-behavior",
    "chain-gap-tolerance", "chain-gap-escalation",
    "action-binding", "action-binding-verifier", "action-binding-producer", "action-binding-rp",
    "cross-replay-binding",
    "presence-via-signature", "presence-uv-claim", "psea_uv",
    "user-id-hash", "device-state", "counter-model",
    "proof-versioning", "jose-hardening", "envelope-body-consistency",
    "security-considerations", "privacy-considerations",
    "threats-spoofing", "threats-tampering", "threats-info-disclosure",
    "algorithm-agility", "crypto-mti", "crypto-negotiation",
    "privacy-ueid", "privacy-hashing",
    "known-open-problems", "open-coercion", "open-wysiwys",
    "human-presence", "rp-countersignature-future",
    "relationship-webauthn", "relationship-rfc9470",
    "appendix-canonical-test-vectors", "appendix-conformance",
]
for anchor in xrefs_to_token_profile:
    doc = doc.replace(
        f'<xref target="{anchor}"/>',
        f'<xref target="PSEA-TOKEN-PROFILE"/>'
    )
    # Also handle xref with section text format
    doc = doc.replace(
        f'<xref target="{anchor}" ',
        f'<xref target="PSEA-TOKEN-PROFILE" '
    )

# Fix prose self-references to sections that now live in PSEA-TOKEN-PROFILE
doc = doc.replace('in Sections 3 through 8', 'in <xref target="PSEA-TOKEN-PROFILE"/>')
doc = doc.replace(
    'The normative wire shape is defined in Sections 3\n'
    '        through 8 of this document.',
    'The normative wire shape is defined in <xref target="PSEA-TOKEN-PROFILE"/>.'
)
doc = doc.replace(
    'the normative wire shape is defined in Sections 3 through 8.',
    'the normative wire shape is defined in <xref target="PSEA-TOKEN-PROFILE"/>.'
)
doc = doc.replace(
    'in Sections 3 and 4, not derived from RATS',
    'in <xref target="PSEA-TOKEN-PROFILE"/>, not derived from RATS'
)
doc = doc.replace('(see Section 4.9)', '(<xref target="PSEA-TOKEN-PROFILE"/>)')
doc = doc.replace('(Section 4.5)', '(<xref target="PSEA-TOKEN-PROFILE"/>)')
doc = doc.replace('(Section 4.9.5)', '(<xref target="PSEA-TOKEN-PROFILE"/>)')
doc = doc.replace('(Section 4.6.1)', '(<xref target="PSEA-TOKEN-PROFILE"/>)')
doc = doc.replace('(Section 4.8)', '(<xref target="PSEA-TOKEN-PROFILE"/>)')
doc = doc.replace('the wire formats and rules described in this\n'
    '        document are sufficient on their own to build a conforming implementation',
    'the wire formats and rules in <xref target="PSEA-TOKEN-PROFILE"/> plus the\n'
    '        architecture described in this document are sufficient to build a conforming implementation'
)

# Fix document-scope text that references this doc's category
doc = doc.replace(
    '<t>This document is Informational and is submitted through the Independent Submission Stream\n'
    '        <xref target="RFC4846"/>. It defines the PSEA wire protocol: canonical encoding, proof token\n'
    '        formats, the four enforcement tiers, trust state systems, verifier endpoints, error response\n'
    '        codes, and accompanying security considerations. The wire formats and rules in <xref target="PSEA-TOKEN-PROFILE"/> plus the\n'
    '        architecture described in this document are sufficient to build a conforming implementation; a reference\n'
    '        implementation exists informatively but is not a normative dependency.</t>',
    '<t>This document is Informational.  It describes the deployment architecture for\n'
    '        <xref target="PSEA-TOKEN-PROFILE"/>: the four enforcement tiers, trust state systems, verifier\n'
    '        endpoints, AttestationBlock, Verifier Acknowledgement, and error-code registry.  Canonical\n'
    '        encoding, proof token formats, security considerations, privacy considerations, and algorithm\n'
    '        agility are normatively defined in <xref target="PSEA-TOKEN-PROFILE"/>.  A reference\n'
    '        implementation exists informatively and is not a normative dependency of this document.</t>'
)

# Replace "in Sections 4 and 7, not derived from RATS" (data flow section)
doc = doc.replace(
    'in Sections 4 and 7, not derived from RATS',
    'in <xref target="PSEA-TOKEN-PROFILE"/> and in this document, not derived from RATS'
)

# Replace xref to RFC4846 inline in document-scope (it may still be referenced now)
# Keep it - document-scope in DOC 2 no longer references RFC4846 after our rewrite above.
# Remove RFC4846 from references if unused.
import re as _re
def remove_reference_block(d, anchor):
    pat = _re.compile(
        r'\s*<reference anchor="' + _re.escape(anchor) + r'"[^>]*>.*?</reference>\n',
        _re.DOTALL
    )
    return pat.sub('\n', d)

# Check if RFC4846 is still cited
if 'RFC4846' not in doc.replace('<reference anchor="RFC4846"', ''):
    doc = remove_reference_block(doc, "RFC4846")

# ─── Replace [PSEA-TOKEN-PROFILE] text with proper xref ──────────────────────
doc = doc.replace("[PSEA-TOKEN-PROFILE]", '<xref target="PSEA-TOKEN-PROFILE"/>')

# Remove unused references in DOC 2
import re as _re2
def remove_ref(d, anchor):
    pat = _re2.compile(
        r'\s*<reference anchor="' + _re2.escape(anchor) + r'"[^>]*>.*?</reference>\n',
        _re2.DOTALL
    )
    return pat.sub('\n', d)

for ref in ["RFC3629", "RFC3553", "RFC7518", "RFC9052", "FIPS180-4",
            "RFC6973", "RFC9470", "FIPS204"]:
    if ref not in doc.replace(f'<reference anchor="{ref}"', ''):
        doc = remove_ref(doc, ref)

# Write output
with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write(doc)

print(f"Written {len(doc)} chars to {OUT}")
print("Line count:", doc.count("\n"))
