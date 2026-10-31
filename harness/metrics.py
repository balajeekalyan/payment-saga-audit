"""Summarize a results JSONL into the paper's tables.

    python -m harness.metrics results/run_*.jsonl
"""

import json
import sys
from collections import defaultdict
from statistics import mean


def load(paths: list[str]) -> list[dict]:
    rows = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            rows.extend(json.loads(line) for line in f if line.strip())
    return rows


def summarize(rows: list[dict], key) -> dict:
    groups = defaultdict(list)
    for r in rows:
        groups[key(r)].append(r)
    table = {}
    for k, rs in sorted(groups.items()):
        llm_rows = [r for r in rs if r["input_tokens"]]
        table[k] = {
            "n": len(rs),
            "correct": mean(r["correct"] for r in rs),
            "escalated": mean(bool(r["escalated"]) for r in rs),
            "unsafe_proposed": sum(len(r["unsafe_proposed"]) for r in rs),
            "unsafe_blocked": sum(len(r["unsafe_blocked"]) for r in rs),
            "unsafe_executed": sum(len(r["unsafe_executed"]) for r in rs),
            "illegal_attempts": sum(len(r["illegal_attempts"]) for r in rs),
            "audit_errors": sum(1 for r in rs if r["audit_error"]),
            "pii_hits": sum(len(r["pii_hits"]) for r in rs),
            "latency_s": mean(r["latency_s"] for r in llm_rows) if llm_rows else 0.0,
            "tokens_in": mean(r["input_tokens"] for r in llm_rows) if llm_rows else 0,
            "tokens_out": mean(r["output_tokens"] for r in llm_rows) if llm_rows else 0,
        }
    return table


def print_table(title: str, table: dict) -> None:
    cols = ["n", "correct", "escalated", "unsafe_proposed", "unsafe_blocked", "unsafe_executed",
            "illegal_attempts", "audit_errors", "pii_hits", "latency_s", "tokens_in", "tokens_out"]
    print(f"\n### {title}\n")
    print("| group | " + " | ".join(cols) + " |")
    print("|---" * (len(cols) + 1) + "|")
    for k, row in table.items():
        cells = [f"{row[c]:.2f}" if isinstance(row[c], float) else str(row[c]) for c in cols]
        print(f"| {k} | " + " | ".join(cells) + " |")


def main() -> None:
    rows = load(sys.argv[1:])
    print_table("By arm", summarize(rows, lambda r: r["arm"]))
    print_table("By arm and anticipated-by-rules",
                summarize(rows, lambda r: f"{r['arm']} / {'anticipated' if r['anticipated'] else 'unanticipated'}"))
    print_table("By scenario and arm", summarize(rows, lambda r: f"{r['scenario']} / {r['arm']}"))


if __name__ == "__main__":
    main()
