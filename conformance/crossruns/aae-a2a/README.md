# Cross-run: AAE extension for A2A, client role

A reported cross-run of the AAE extension for A2A, v1
([MoltyCel/aae-a2a-extension](https://github.com/MoltyCel/aae-a2a-extension)),
in the `client` role of its CROSSRUN.md Section 1: the client in
[`client/aae_client.py`](client/aae_client.py) against the reference supplier
of that repository, run locally, since the guide names no hosted endpoint.

This is not a PSEA conformance result. No case at the commit run carries a
PSEA proof, and no PSEA code is used.

## Inputs

- Cases: `tests/vectors/crossrun/cases.json` of MoltyCel/aae-a2a-extension at
  `326b9d105756015a6e23d4371534706655a4336f`, 24 cases, every case run, none
  skipped.
- Test keys: `tests/vectors/crossrun/test-keys.json` of the same commit, the
  public Ed25519 test keys of CROSSRUN.md Section 2.
- Server: `python -m aae_a2a.crossrun serve --port 8790` from a checkout of the
  same commit, on `127.0.0.1`, with the supplier's own clock.

## The client

About 420 lines of Python: the standard library and `cryptography` for
Ed25519. It was written from the profile (`spec/aae-a2a-extension-v1.md`),
CROSSRUN.md and draft-kroehl-agentic-trust-aae-02 (Sections 2, 2.2.1, 2.2.2,
2.5.1, 6.3 and 6.4 for the hold and ratification cases). It speaks JSON-RPC
over `urllib`, builds the AAE, challenge-response and ratification variants of
CROSSRUN.md Section 3 itself, recomputes `request_digest` from the request
part it sent (spec Section 8.5) with its own RFC 8785 serialization, and
judges each case by the rule of CROSSRUN.md Section 6. It shares no code with
the reference implementation.

The mandate members `purpose` and `scope` are the client's own values; the
guide refers to the reference's `buyer_mandate()` for them, which was not read,
and no case depends on them.

## Receiver provenance: `reference_informed`

CROSSRUN.md Section 6 defines `clean_room` as written from the profile text and
the guide alone, without the source code of that repository. That does not
hold here. The source code of MoltyCel/aae-a2a-extension, including
`aae_a2a/crossrun.py` (the reference buyer's case runner and result check),
`aae_a2a/pinned.py`, `aae_a2a/psea.py` and the tests, was read while preparing
[MoltyCel/aae-a2a-extension#19](https://github.com/MoltyCel/aae-a2a-extension/pull/19),
before this client was written. The client is a separate implementation, but
its author had read the reference, so the run is `reference_informed`.

## Result

[`2026-11-11-mohamad-khalil-yossif-client.json`](2026-11-11-mohamad-khalil-yossif-client.json):
24 pass, 0 fail, 0 skipped. It validates with
`python -m aae_a2a.crossrun check` of MoltyCel/aae-a2a-extension, which reads
the cases at `cases_commit` and recomputes every result from what the file
records.

A pass says the reference supplier and this client agree on these 24 cases.
It says nothing about cases outside the set, and, as CROSSRUN.md states,
nothing about how either side was written.

## Running it again

```
git clone https://github.com/MoltyCel/aae-a2a-extension && cd aae-a2a-extension
git checkout 326b9d105756015a6e23d4371534706655a4336f && make install
.venv/bin/python -m aae_a2a.crossrun serve --port 8790 &
python3 <psea-spec>/conformance/crossruns/aae-a2a/client/aae_client.py \
  --url http://127.0.0.1:8790 \
  --cases tests/vectors/crossrun/cases.json --keys tests/vectors/crossrun/test-keys.json \
  --cases-commit 326b9d105756015a6e23d4371534706655a4336f \
  --server-commit 326b9d105756015a6e23d4371534706655a4336f \
  --participant "<name>" --receiver-provenance <value> \
  --client-repo https://github.com/yuthent/psea-spec --out result.json
```

Task ids, AAE ids, nonces and `run_at` differ from run to run; the verdicts,
steps, reason codes and `request_digest` values do not.
