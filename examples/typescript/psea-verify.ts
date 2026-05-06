#!/usr/bin/env node
/**
 * PSEA reference verifier — TypeScript / Node 22+.
 *
 * Verify-only. Implements the algorithms in `spec/tier-definitions.md`.
 * Walks ../../test-vectors/ and reports PASS/FAIL per vector.
 *
 * Zero npm dependencies — uses only Node's built-in `crypto` and `fs`.
 *
 * Run:
 *   node --experimental-strip-types psea-verify.ts
 *   # or
 *   npm run verify
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { createHash, createPublicKey, createVerify } from "node:crypto";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const ROOT = resolve(HERE, "..", "..");
const VECTORS = join(ROOT, "test-vectors");

const NOW = 1_733_280_000_000;
const MAX_CLOCK_SKEW_MS = 30_000;
const BIOMETRIC_FRESHNESS_MS = 30_000;

// ---------------------------------------------------------------------------
// Helpers

function jcs(value: unknown): string {
  // RFC 8785 minimal: sort keys recursively, no whitespace.
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(jcs).join(",") + "]";
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return (
    "{" +
    keys
      .map(
        (k) => JSON.stringify(k) + ":" + jcs((value as Record<string, unknown>)[k])
      )
      .join(",") +
    "}"
  );
}

function jcsBytes(value: unknown): Buffer {
  return Buffer.from(jcs(value), "utf8");
}

function sha256Hex(b: Buffer): string {
  return createHash("sha256").update(b).digest("hex");
}

function b64uDecode(s: string): Buffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

function spkiFromUncompressedP256(pubB64u: string): import("node:crypto").KeyObject {
  const raw = b64uDecode(pubB64u);
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error("expected 65-byte uncompressed P-256 public key");
  }
  // Build SubjectPublicKeyInfo for P-256 (NIST secp256r1)
  // SEQ(SEQ(OID ec-pub-key, OID prime256v1), BIT STRING raw)
  const algId = Buffer.from(
    "3013" +                       // SEQUENCE 0x13
    "06072a8648ce3d0201" +         // OID 1.2.840.10045.2.1 (ecPublicKey)
    "06082a8648ce3d030107",        // OID 1.2.840.10045.3.1.7 (prime256v1)
    "hex",
  );
  const bitString = Buffer.concat([Buffer.from([0x03, raw.length + 1, 0x00]), raw]);
  const inner = Buffer.concat([algId, bitString]);
  const spki = Buffer.concat([Buffer.from([0x30, 0x82, (inner.length >> 8) & 0xff, inner.length & 0xff]), inner]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

function rawSigToDer(raw: Buffer): Buffer {
  if (raw.length !== 64) throw new Error("expected 64-byte raw signature");
  const r = trimLeadingZeros(raw.subarray(0, 32));
  const s = trimLeadingZeros(raw.subarray(32, 64));
  const rEnc = encodeInt(r);
  const sEnc = encodeInt(s);
  const inner = Buffer.concat([rEnc, sEnc]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

function trimLeadingZeros(b: Buffer): Buffer {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}

function encodeInt(b: Buffer): Buffer {
  // Add a leading 0x00 if high bit set.
  const needsPad = (b[0] & 0x80) !== 0;
  const body = needsPad ? Buffer.concat([Buffer.from([0x00]), b]) : b;
  return Buffer.concat([Buffer.from([0x02, body.length]), body]);
}

function verifyES256(pub: import("node:crypto").KeyObject, msg: Buffer, rawSig: Buffer): boolean {
  try {
    const der = rawSigToDer(rawSig);
    const v = createVerify("sha256");
    v.update(msg);
    v.end();
    return v.verify(pub, der);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Registry

type RegistryEntry = {
  publicKey: string;
  trustState: string;
  trustStateHash: string;
  counter: number;
  chainHead: string;
  attestationNotAfter: number;
  tenantPolicy: string;
};

class Registry {
  fixedNowMs: number;
  devices: Record<string, RegistryEntry>;
  pubkeys: Record<string, import("node:crypto").KeyObject>;

  constructor(raw: any) {
    this.fixedNowMs = raw.fixedTimestampMs as number;
    this.devices = raw.verifierRegistry as Record<string, RegistryEntry>;
    this.pubkeys = {};
    for (const [did, entry] of Object.entries(this.devices)) {
      this.pubkeys[did] = spkiFromUncompressedP256(entry.publicKey);
    }
  }

  static load(p: string): Registry {
    const raw = JSON.parse(readFileSync(p, "utf8"));
    return new Registry(raw);
  }
}

// ---------------------------------------------------------------------------
// Per-tier verifiers

const RISK_TIER_MIN: Record<string, string> = { LOW: "P", MEDIUM: "S", HIGH: "E", CRITICAL: "A" };
const TIER_RANK: Record<string, number> = { P: 0, S: 1, E: 2, A: 3 };

function insufficientTier(tier: string, actionClass: string): boolean {
  return TIER_RANK[tier] < TIER_RANK[RISK_TIER_MIN[actionClass]];
}

function verifyTierP(reg: Registry, vec: any): string {
  const body = vec.proofToken.body;
  if (insufficientTier("P", vec.actionClass)) return "REJECT_INSUFFICIENT_TIER";
  const did = body.deviceId;
  if (!(did in reg.devices)) return "REJECT_UNKNOWN_DEVICE";
  if (body.trustStateHash !== reg.devices[did].trustStateHash) return "REJECT_STATE_DRIFT";
  if (Math.abs(reg.fixedNowMs - body.timestamp) > MAX_CLOCK_SKEW_MS)
    return "REJECT_TIMESTAMP_OUT_OF_RANGE";
  return "ACCEPT";
}

function verifyTierS(reg: Registry, vec: any): string {
  const body = vec.proofToken.body;
  if (insufficientTier("S", vec.actionClass)) return "REJECT_INSUFFICIENT_TIER";

  const expectedHash = sha256Hex(jcsBytes(vec.input.actionRequest));
  if (body.actionHash !== expectedHash) return "REJECT_ACTION_BINDING";

  const sess = vec.input.deviceState.session;
  if (!sess || sess.id !== body.sessionId) return "REJECT_UNKNOWN_SESSION";

  const did = body.deviceId;
  const pub = reg.pubkeys[did];
  if (!pub) return "REJECT_UNKNOWN_DEVICE";

  const sig = b64uDecode(vec.proofToken.signature);
  if (!verifyES256(pub, jcsBytes(body), sig)) return "REJECT_BAD_SIGNATURE";
  return "ACCEPT";
}

function verifyTierECommon(reg: Registry, vec: any, allowTest = false): string {
  const body = vec.proofToken.body;
  const state = vec.input.deviceState;

  const expectedHash = sha256Hex(jcsBytes(vec.input.actionRequest));
  if (body.actionHash !== expectedHash) return "REJECT_ACTION_BINDING";

  const did = body.deviceId;
  const pub = reg.pubkeys[did];
  if (!pub) return "REJECT_UNKNOWN_DEVICE";

  const sig = b64uDecode(vec.proofToken.signature);
  if (!verifyES256(pub, jcsBytes(body), sig)) return "REJECT_BAD_SIGNATURE";

  if (body.counter <= state.counter) return "REJECT_REPLAY";

  const { chainEntry: _ignored, ...bodyNoChain } = body;
  const expectedEntry = sha256Hex(
    Buffer.concat([Buffer.from(state.chainHead, "hex"), jcsBytes(bodyNoChain)]),
  );
  if (body.chainEntry !== expectedEntry) return "REJECT_CHAIN_BROKEN";
  if (body.chainPrev !== state.chainHead) return "REJECT_CHAIN_BROKEN";

  const bio = body.biometric;
  if (!bio) return "REJECT_BIOMETRIC";
  const age = body.timestamp - bio.freshness.capturedAt;
  if (age < 0 || age > BIOMETRIC_FRESHNESS_MS) return "REJECT_BIOMETRIC";

  const att = body.attestation;
  if (att.source === "test" && !allowTest) return "REJECT_ATTESTATION";
  if (att.notAfter < reg.fixedNowMs) return "REJECT_ATTESTATION";
  if (att.packageBinding.enforcement === "client-claim" &&
      ["REGULATED", "STANDARD"].includes(state.tenantPolicy)) {
    return "REJECT_ATTESTATION";
  }
  return "ACCEPT";
}

function verifyTierE(reg: Registry, vec: any): string {
  if (insufficientTier("E", vec.actionClass)) return "REJECT_INSUFFICIENT_TIER";
  return verifyTierECommon(reg, vec);
}

function verifyTierA(reg: Registry, vec: any): string {
  if (insufficientTier("A", vec.actionClass)) return "REJECT_INSUFFICIENT_TIER";
  const state = vec.input.deviceState;
  if (!state.networkReachable || !state.authorizeEndpointHealthy) {
    return "REJECT_OFFLINE_AUTHORITATIVE_BLOCKED";
  }
  const inner = verifyTierECommon(reg, vec);
  if (inner !== "ACCEPT") return inner;

  const blocked: string[] = state.blockedActionTypes ?? [];
  if (blocked.includes(vec.input.actionRequest.actionType)) {
    return "REJECT_POLICY_DENY";
  }
  if (state.auditLogHealthy === false) return "REJECT_AUDIT_FAILURE";
  return "ACCEPT";
}

const VERIFIERS: Record<string, (r: Registry, v: any) => string> = {
  P: verifyTierP, S: verifyTierS, E: verifyTierE, A: verifyTierA,
};

// ---------------------------------------------------------------------------
// Runner

function listVectors(): string[] {
  const out: string[] = [];
  for (const tier of ["tier-p", "tier-s", "tier-e", "tier-a"]) {
    const dir = join(VECTORS, tier);
    if (!statSync(dir, { throwIfNoEntry: false })) continue;
    for (const f of readdirSync(dir).sort()) {
      if (f.endsWith(".json")) out.push(join(dir, f));
    }
  }
  return out;
}

function main(): number {
  const reg = Registry.load(join(VECTORS, "keys", "test-keys.json"));
  const files = listVectors();
  let pass = 0, fail = 0;

  for (const f of files) {
    const vec = JSON.parse(readFileSync(f, "utf8"));
    const tier = vec.proofToken.header.tier as string;
    const actual = VERIFIERS[tier](reg, vec);
    const expected = vec.expected.result as string;
    const rel = relative(ROOT, f).replaceAll("\\", "/");
    if (actual === expected) {
      pass++;
      console.log(`  [PASS] ${rel}  (${actual})`);
    } else {
      fail++;
      console.log(`  [FAIL] ${rel}  expected=${expected} actual=${actual}`);
    }
  }
  console.log(`\n${pass} passed, ${fail} failed, ${files.length} total`);
  return fail === 0 ? 0 : 1;
}

process.exit(main());
