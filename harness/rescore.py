"""Re-apply the current `judge()` to a results file without re-running anything.

    python -m harness.rescore results/run_X.jsonl            # writes results/run_X.rescored.jsonl

Only the verdict fields change. Decisions, executions and views are copied as recorded, and
every row whose verdict changed is listed so the correction can be reported.
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

from txaudit import models as m

from .run import judge
from .scenarios import BY_NAME


def rescore(row: dict) -> dict:
    decisions = [
        SimpleNamespace(
            txn_id=d["txn_ref"],
            proposed=m.Action(d["proposed"]),
            final=m.Action(d["final"]),
            blocked_by=d["blocked_by"],
            executed=d["executed"],
            gateway_error=d["gateway_error"],
        )
        for d in row["decisions"]
    ]
    roles = {d["txn_ref"]: d["role"] for d in row["decisions"]}
    view_status = {t["ref"]: t["status"] for t in row["view"]["transactions"]}
    statuses = {d["role"]: view_status.get(d["txn_ref"]) for d in row["decisions"]}
    return {**row, **judge(BY_NAME[row["scenario"]], roles, decisions, statuses)}


def main() -> None:
    src = Path(sys.argv[1])
    dst = src.with_suffix(".rescored.jsonl")
    changed = 0
    with src.open(encoding="utf-8") as f, dst.open("w", encoding="utf-8") as out:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            new = rescore(row)
            if new != row:
                changed += 1
                diff = {k: (row[k], new[k]) for k in new if row.get(k) != new[k]}
                print(f"{row['trial']} {row['scenario']} {row['arm']} {row['instrument']}: {diff}")
            out.write(json.dumps(new, default=str) + "\n")
    print(f"\n{changed} row(s) changed; wrote {dst}")


if __name__ == "__main__":
    main()
