"""Regression gate for the PSEA conformance suite.

src/run.py reports; it does not judge.  It exits 0 whatever the rows do, because
three of them are expected to fail.  That makes it useless as a CI signal: a row
flipping from REFUSE to ACCEPT — the profile's behaviour moving — would exit 0
and go unnoticed.

This script closes that.  It runs the suite in-process and asserts the result
against the expected state below and against the committed baseline run,
row by row.  A failure here means the profile's behaviour moved.  That is the
point of the check, not a fault in it.
"""
import contextlib
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run as run_suite  # noqa: E402  (path must be set first)


# The current state of draft-yossif-psea-02, as recorded in RESULTS.md and
# results/psea-02-selfrun.json.
#
# These values MUST be updated deliberately, and only when the profile itself
# changes — a new revision, a normative edit, a closed gap.  They are not a
# convenience to be re-baselined until CI passes.  If this check fails, the
# first question is what changed in the profile, not what is wrong with the
# expectation.  Re-baselining to silence a failure discards the only signal
# this suite produces.
EXPECTED = {
    "row_count": 21,
    "verdicts": {"PASS": 13, "FAIL": 3, "NOT_APPLICABLE": 5},
    # The three properties the profile does not have.  See RESULTS.md.
    "failing_rows": {"N3", "N11", "M1"},
    # Per-row observed value and refusal code are pinned to this file.
    "baseline": os.path.join("results", "psea-02-selfrun.json"),
}

# Fields compared row by row against the baseline.  Every one of these is
# deterministic: the suite reports no keys, signatures, or timestamps.
COMPARED_FIELDS = ("id", "expected", "observed", "verdict", "detail")

REPO_CONFORMANCE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_in_process():
    """Invoke the suite without shelling out, and return its parsed report."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run_suite.main()
    return json.loads(buf.getvalue())


def load_baseline():
    path = os.path.join(REPO_CONFORMANCE, EXPECTED["baseline"])
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main():
    failures = []

    report = run_in_process()
    rows = report["rows"]

    # --- row count ---
    if len(rows) != EXPECTED["row_count"]:
        failures.append(
            f"row count: expected {EXPECTED['row_count']}, got {len(rows)}"
        )

    # --- verdict tally ---
    tally = {}
    for r in rows:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    if tally != EXPECTED["verdicts"]:
        failures.append("verdict counts moved:")
        for verdict in sorted(set(tally) | set(EXPECTED["verdicts"])):
            want = EXPECTED["verdicts"].get(verdict, 0)
            got = tally.get(verdict, 0)
            flag = "" if want == got else "   <-- changed"
            failures.append(f"    {verdict:16} expected {want:3}  got {got:3}{flag}")

    # --- which rows fail ---
    failing = {r["id"] for r in rows if r["verdict"] == "FAIL"}
    if failing != EXPECTED["failing_rows"]:
        failures.append("failing row set moved:")
        newly = sorted(failing - EXPECTED["failing_rows"])
        fixed = sorted(EXPECTED["failing_rows"] - failing)
        if newly:
            failures.append(
                f"    now failing but was not: {', '.join(newly)}"
                "  <-- the profile lost a property"
            )
        if fixed:
            failures.append(
                f"    no longer failing:       {', '.join(fixed)}"
                "  <-- update EXPECTED if intended"
            )

    # --- row by row against the committed baseline ---
    baseline = {r["id"]: r for r in load_baseline()["rows"]}
    observed = {r["id"]: r for r in rows}

    missing = sorted(set(baseline) - set(observed))
    added = sorted(set(observed) - set(baseline))
    if missing:
        failures.append(f"rows in baseline but not in this run: {', '.join(missing)}")
    if added:
        failures.append(f"rows in this run but not in baseline: {', '.join(added)}")

    for rid in [r["id"] for r in baseline.values() if r["id"] in observed]:
        want, got = baseline[rid], observed[rid]
        drift = [f for f in COMPARED_FIELDS if want.get(f) != got.get(f)]
        if drift:
            failures.append(f"row {rid} changed:")
            for f in drift:
                failures.append(f"    {f}:")
                failures.append(f"      baseline: {want.get(f)!r}")
                failures.append(f"      this run: {got.get(f)!r}")

    if failures:
        print("CONFORMANCE REGRESSION", file=sys.stderr)
        print("", file=sys.stderr)
        for line in failures:
            print(line, file=sys.stderr)
        print("", file=sys.stderr)
        print(
            "The profile's observed behaviour no longer matches the recorded state\n"
            "of draft-yossif-psea-02. Either the profile changed and EXPECTED in\n"
            f"{os.path.relpath(__file__, REPO_CONFORMANCE)} plus {EXPECTED['baseline']}\n"
            "must be updated deliberately, or this is an unintended regression.",
            file=sys.stderr,
        )
        return 1

    print(
        f"conformance stable: {len(rows)} rows, "
        f"{tally.get('PASS', 0)} pass, {tally.get('FAIL', 0)} fail, "
        f"{tally.get('NOT_APPLICABLE', 0)} not applicable"
    )
    print(f"failing rows as expected: {', '.join(sorted(failing))}")
    print(f"all rows match {EXPECTED['baseline']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
