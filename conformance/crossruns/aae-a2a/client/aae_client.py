"""A minimal A2A client for the cross-run of the AAE extension for A2A, v1.

Written from three texts: spec/aae-a2a-extension-v1.md and CROSSRUN.md of
MoltyCel/aae-a2a-extension, and draft-kroehl-agentic-trust-aae-02. It shares
no code with that repository. It plays the `client` role of CROSSRUN.md
Section 1 against a supplier, runs the cases of a cases.json, and writes a
result file in the form of CROSSRUN.md Section 6.

  python aae_client.py --url http://127.0.0.1:8790 --cases cases.json \
      --keys test-keys.json --cases-commit <sha> --out result.json ...

Dependencies: the Python standard library and `cryptography` (Ed25519).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

URI = "https://moltrust.ch/extensions/aae/v1"            # spec Section 2
DRAFT = "draft-kroehl-agentic-trust-aae-02"               # spec Section 4
RESULT_FORMAT = "aae-a2a-crossrun/1"                      # CROSSRUN.md 6
ISSUER, BUYER, PRINCIPAL = "did:example:issuer", "did:example:buyer", "did:example:principal-acme"
MALLORY = "did:example:mallory"


# --- encodings ---------------------------------------------------------------

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jcs_number(x) -> str:
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int):
        return str(x)
    if not math.isfinite(x):
        raise ValueError("JCS has no NaN or infinity")
    if x.is_integer() and abs(x) < 2 ** 53:
        return str(int(x))
    return repr(x)  # shortest round-trip form; adequate for the values of the case set


def jcs(v) -> bytes:
    """RFC 8785 for the value types the case set uses: objects, arrays,
    strings, numbers within 2^53, booleans and null. Keys sort by UTF-16
    code units."""
    def enc(x) -> str:
        if x is None or isinstance(x, bool):
            return json.dumps(x)
        if isinstance(x, (int, float)):
            return _jcs_number(x)
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, list):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            keys = sorted(x, key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(enc(k) + ":" + enc(x[k]) for k in keys) + "}"
        raise TypeError(type(x))
    return enc(v).encode("utf-8")


def request_digest(request_part: dict) -> str:
    """Spec Section 8.5: SHA-256 over the JCS octets, no tag."""
    return "sha256:" + hashlib.sha256(jcs(request_part)).hexdigest()


def tagged_digest(tag: bytes, value) -> str:
    """-02 Sections 2.2.2 and 6.3: SHA-256(tag || 0x00 || JCS(value))."""
    return "sha256:" + hashlib.sha256(tag + b"\x00" + jcs(value)).hexdigest()


def rfc3339(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- keys ----------------------------------------------------------------------

class Keys:
    """The public test keys of CROSSRUN.md Section 2 (Ed25519 seeds)."""

    def __init__(self, path: str):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)["keys"]
        self.priv = {name: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["ed25519_seed_hex"]))
                     for name, k in doc.items()}

    def public_hex(self, name: str) -> str:
        return self.priv[name].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def jws(header: dict, payload: bytes, key: Ed25519PrivateKey) -> str:
    """Compact JWS, EdDSA (RFC 7515, RFC 8037), over the given payload bytes."""
    h = b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64u(payload)
    return f"{h}.{p}.{b64u(key.sign(f'{h}.{p}'.encode('ascii')))}"


# --- the AAE variants of CROSSRUN.md Section 3 --------------------------------

def mandate(actions=("read", "pay")) -> dict:
    return {"actions": list(actions), "purpose": "Office supplies for the cross-run buyer",
            "scope": "office-supplies", "principal_did": PRINCIPAL}


HOLD_ACTION = {"verb": "pay", "category": "office-supplies"}


def held_mandate(keys: Keys) -> dict:
    """The `hold` variant: the mandate plus `principal` and one grant with
    disposition hold for HOLD_ACTION, amount 0 to 300, currency EUR (-02
    Sections 2.2.1, 2.2.2, 2.5.1, 6.4)."""
    m = mandate()
    m["principal"] = {"did": PRINCIPAL, "public_key": keys.public_hex("principal")}
    m["grants"] = [{
        "action_binding": tagged_digest(b"aae:enforce-action:v1", HOLD_ACTION),
        "type_fields": ["verb", "category"],
        "disposition": "hold",
        "constraints": [{"type": "range", "field": "amount", "lo": 0, "hi": 300},
                        {"type": "exact", "field": "currency", "value": "EUR"}],
    }]
    return m


def build_aae(variant: str, audience: str, keys: Keys, now: datetime) -> tuple[str | None, str | None, dict | None]:
    """Returns (compact JWS, VC id, mandate) for an AAE variant."""
    if variant == "none":
        return None, None, None
    host = urlsplit(audience).hostname
    nb, na = now - timedelta(minutes=5), now + timedelta(hours=1)
    if variant == "expired":
        nb, na = now - timedelta(hours=2), now - timedelta(hours=1)
    m = {"read_only": lambda: mandate(["read"]), "hold": lambda: held_mandate(keys)}.get(
        variant, mandate)()
    domains = ["other-supplier.example"] if variant == "other_domain" else [host]
    vc_id = f"urn:uuid:{uuid.uuid4()}"
    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://moltrust.ch/contexts/aae/v1"],
        "type": ["VerifiableCredential", "AgentAuthorizationEnvelope"],
        "id": vc_id,
        "issuer": ISSUER,
        "validFrom": rfc3339(nb),
        "credentialSubject": {"id": BUYER, "aae": {
            "mandate": m,
            "constraints": {
                "max_transaction_value": {"value": 500, "currency": "EUR", "required": True},
                "allowed_domains": {"value": domains, "required": True}},
            "validity": {"not_before": rfc3339(nb), "not_after": rfc3339(na),
                         "single_use": variant == "single_use"}}},
    }
    header = {"alg": "EdDSA", "cty": "aae+json", "kid": ISSUER + "#key-1"}
    payload = json.dumps(vc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signer = keys.priv["mallory" if variant == "forged" else "issuer"]
    if variant == "payload_not_json":
        payload = b'{"issuer": "did:example:issuer", '
    elif variant == "duplicate_issuer":
        payload = b'{"issuer":"did:example:other-agent",' + payload[1:]
    return jws(header, payload, signer), vc_id, m


RESPONSE_OFFSETS = {"valid": 0, "wrong_key": 0, "iat_past_inside": -330, "iat_past_outside": -390,
                    "iat_future_inside": 30, "iat_future_outside": 90}


# --- A2A JSON-RPC (spec Appendix A) -------------------------------------------

class Supplier:
    def __init__(self, base_url: str):
        self.card_url = base_url.rstrip("/") + "/.well-known/agent-card.json"
        with urllib.request.urlopen(self.card_url) as r:
            self.card = json.load(r)
        ext = next(e for e in self.card["capabilities"]["extensions"] if e["uri"] == URI)
        self.params = ext["params"]
        if self.params.get("draft") != DRAFT:
            raise SystemExit(f"card draft {self.params.get('draft')!r} is not {DRAFT}")
        self.endpoint = next(i["url"] for i in self.card["supportedInterfaces"]
                             if i.get("protocolBinding") == "JSONRPC")
        self.audience = self.params["audience"]
        self._id = 0

    def send(self, message: dict, activate: bool) -> dict:
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": "SendMessage",
                "params": {"message": message}}
        headers = {"Content-Type": "application/json", "A2A-Version": "1.0"}
        if activate:
            headers["A2A-Extensions"] = URI
        req = urllib.request.Request(self.endpoint, data=json.dumps(body).encode("utf-8"),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            return json.loads(e.read() or b"{}")


def find_reason_code(data):
    """ErrorInfo.metadata.reason_code, wherever the binding nests it."""
    if isinstance(data, dict):
        if isinstance(data.get("reason_code"), str):
            return data["reason_code"]
        for v in data.values():
            found = find_reason_code(v)
            if found:
                return found
    if isinstance(data, list):
        for v in data:
            found = find_reason_code(v)
            if found:
                return found
    return None


def ext_meta(obj: dict | None) -> dict:
    return ((obj or {}).get("metadata") or {}).get(URI) or {}


def observe(reply: dict) -> tuple[dict, dict | None]:
    """The members of CROSSRUN.md Section 6 for one reply, and the task."""
    if "error" in reply:
        err = reply["error"]
        obs = {"jsonrpc_code": err.get("code")}
        rc = find_reason_code(err.get("data"))
        if rc:
            obs["reason_code"] = rc
        return obs, None
    task = reply["result"]["task"]
    res = ext_meta(task).get("result") or ext_meta(task["status"].get("message")).get("result") or {}
    obs = {"task_id": task["id"], "task_state": task["status"]["state"],
           "verdict": res.get("verdict"), "request_digest": res.get("request_digest")}
    if res.get("verdict") == "REJECT":
        obs["step"] = int(res["step"])
        obs["reason_code"] = res.get("reason_code")
    elif "steps_passed" in res:
        obs["steps_passed"] = [int(s) for s in res["steps_passed"]]
    if isinstance(res.get("ratification"), dict):
        obs["ratification_status"] = res["ratification"].get("status")
    return obs, task


def message(parts: list, meta: dict | None, task: dict | None = None, extensions=True) -> dict:
    m = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": parts}
    if extensions:
        m["extensions"] = [URI]
    if meta is not None:
        m["metadata"] = {URI: meta}
    if task is not None:
        m["taskId"], m["contextId"] = task["id"], task["contextId"]
    return m


def present(sup: Supplier, keys: Keys, case: dict, aae: str | None, vc_id: str | None,
            m: dict | None) -> tuple[dict, list[str]]:
    """One presentation: the presentation message, the challenge response,
    and for a held task the ratification of the case's variant."""
    notes: list[str] = []
    rp = case["request_part"]
    meta = None if aae is None else {"aae": aae}
    reply = sup.send(message([{"data": rp, "mediaType": "application/json"}], meta,
                             extensions=aae is not None), activate=case["activate"])
    obs, task = observe(reply)
    if task is None or task["status"]["state"] != "TASK_STATE_AUTH_REQUIRED":
        return obs, notes
    ch = ext_meta(task["status"].get("message")).get("challenge") or {}
    # Spec 6.3: check aud and aae_id before signing, and do not sign otherwise.
    if ch.get("aud") != sup.audience or ch.get("aae_id") != vc_id:
        notes.append("challenge aud or aae_id differs from what was presented; not signed")
        return obs, notes
    variant = case["challenge_response"]
    iat = datetime.now(timezone.utc) + timedelta(seconds=RESPONSE_OFFSETS[variant])
    payload = {"nonce": ch["nonce"], "aud": ch["aud"], "iat": rfc3339(iat), "aae_id": ch["aae_id"]}
    signer = keys.priv["mallory" if variant == "wrong_key" else "buyer"]
    resp = jws({"alg": "EdDSA", "kid": BUYER + "#key-1"},
               json.dumps(payload, separators=(",", ":")).encode("utf-8"), signer)
    obs, task = observe(sup.send(message([{"text": "AAE challenge response"}],
                                         {"challenge_response": resp}, task), activate=True))
    ratification = case.get("ratification", "none")  # CROSSRUN.md 3: `none` sends nothing
    if task is not None and ratification != "none" and obs.get("verdict") == "PENDING":
        held = ext_meta(task).get("result") or ext_meta(task["status"].get("message")).get("result")
        name, did = ("principal", PRINCIPAL) if ratification == "principal" else ("mallory", MALLORY)
        statement = {"ratify_version": "3.0", "ratifies": held["enforce"]["core_digest"],
                     "decision": "APPROVED", "authority": did}
        sig = keys.priv[name].sign(b"aae:enforce-ratify-statement:v1\x00" + jcs(statement))
        meta = {"ratification": {"decision": "APPROVED", "authority_proof": {
            "mandate": m, "authority": did, "signature": sig.hex()}}}
        obs, task = observe(sup.send(message([{"text": "Ratification"}], meta, task),
                                     activate=True))
    return obs, notes


# --- pass or fail, CROSSRUN.md Section 6 --------------------------------------

def judge(exp: dict, obs: dict, task_ids: dict) -> list[str]:
    fails = []
    if exp["kind"] == "error":
        if obs.get("jsonrpc_code") != exp["jsonrpc_code"]:
            fails.append(f"jsonrpc_code {obs.get('jsonrpc_code')} != {exp['jsonrpc_code']}")
        return fails
    for k in ("task_state", "verdict", "request_digest"):
        if obs.get(k) != exp[k]:
            fails.append(f"{k} {obs.get(k)} != {exp[k]}")
    if exp["verdict"] == "REJECT" and obs.get("step") != exp.get("step"):
        fails.append(f"step {obs.get('step')} != {exp.get('step')}")
    if exp["verdict"] == "ACCEPT" and not set(range(1, 8)) <= set(obs.get("steps_passed") or []):
        fails.append("steps_passed lacks one of 1-7")
    if "ratification_status" in exp and obs.get("ratification_status") != exp["ratification_status"]:
        fails.append("ratification_status differs")
    if "admission" in exp and (obs.get("verdict") == "ACCEPT") != exp["admission"]["admitted"]:
        fails.append("admission differs")
    other = exp.get("task_id_differs_from")
    if other and (not obs.get("task_id") or obs.get("task_id") == task_ids.get(other)):
        fails.append(f"task id equals that of {other}")
    return fails


def run(sup: Supplier, keys: Keys, cases: list[dict]) -> list[dict]:
    out, task_ids = [], {}
    for case in cases:
        aae, vc_id, m = build_aae(case["aae"], sup.audience, keys, datetime.now(timezone.utc))
        exp = case["expect"]
        n = case.get("attempts", 1)
        got, notes = [], []
        for _ in range(n):
            obs, msgs = present(sup, keys, case, aae, vc_id, m)
            got.append(obs)
            notes += msgs
        # Spec 8.5: recompute request_digest from the request part sent.
        mine = request_digest(case["request_part"])
        for o in got:
            if o.get("request_digest") not in (None, mine):
                notes.append(f"returned request_digest differs from the recomputed {mine}")
        if n == 1:
            obs, fails = got[0], judge(exp, got[0], task_ids)
            if obs.get("task_id"):
                task_ids[case["id"]] = obs["task_id"]
            entry = {"id": case["id"], "result": "fail" if fails else "pass", **obs}
        else:
            fails = []
            for i, (e, o) in enumerate(zip(exp["attempts"], got), start=1):
                fails += [f"attempt {i}: {f}" for f in judge(e, o, task_ids)]
            ids = [o.get("task_id") for o in got]
            if None in ids or len(set(ids)) != len(ids):
                fails.append("attempts are not distinct tasks")
            entry = {"id": case["id"], "result": "fail" if fails else "pass", "attempts": got}
        if fails or notes:
            entry["notes"] = "; ".join(fails + notes)
        out.append(entry)
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--cases", required=True, help="cases.json as published at --cases-commit")
    p.add_argument("--cases-commit", required=True)
    p.add_argument("--keys", required=True, help="test-keys.json of the same commit")
    p.add_argument("--out", required=True)
    p.add_argument("--participant", required=True)
    p.add_argument("--participant-url")
    p.add_argument("--receiver-provenance", required=True,
                   choices=("clean_room", "reference_informed", "unknown"))
    p.add_argument("--client-repo", required=True)
    p.add_argument("--server-commit", required=True)
    a = p.parse_args()

    raw = open(a.cases, "rb").read()
    spec = json.loads(raw)
    sup = Supplier(a.url)
    results = run(sup, Keys(a.keys), spec["cases"])
    here = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                          cwd=sys.path[0] or ".").stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "--", "."], capture_output=True,
                                text=True, cwd=sys.path[0] or ".").stdout.strip())
    summary = {k: sum(1 for r in results if r["result"] == k) for k in ("pass", "fail", "skipped")}
    doc = {
        "format": RESULT_FORMAT, "profile": URI, "draft": DRAFT,
        "cases_commit": a.cases_commit,
        "cases_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "run_at": rfc3339(datetime.now(timezone.utc)),
        "participant": {"name": a.participant, **({"url": a.participant_url} if a.participant_url else {})},
        "receiver_provenance": a.receiver_provenance,
        "client": {"implementation": "aae_client.py, a minimal Python client written from the "
                                     "profile, CROSSRUN.md and draft-kroehl-agentic-trust-aae-02",
                   "repository": a.client_repo, "commit": here, "dirty": dirty},
        "server": {"implementation": "aae-a2a-extension reference supplier",
                   "repository": "https://github.com/MoltyCel/aae-a2a-extension",
                   "commit": a.server_commit, "dirty": False, "agent_card": sup.card_url},
        "cases": results,
        "summary": summary,
    }
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    for r in results:
        print(r["id"], r["result"], r.get("notes", ""))
    print(f"{summary['pass']} pass, {summary['fail']} fail, {summary['skipped']} skipped -> {a.out}")
    return 1 if summary["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
