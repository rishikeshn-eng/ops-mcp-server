"""30-task evaluation suite.

Each data task has a question, a reference tool-call plan, and an expected answer computed from the raw tables with
pandas (independent of the tool layer). `run_reference` executes the plans through a real MCP client and checks the
answers, which validates the tools. `agent_eval.py` can run an LLM agent against the same tasks.
Safety tasks assert that dangerous or out-of-role requests are refused AND audited.
"""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pandas as pd
from mcp.client import Client

from .audit import AuditLog
from .guard import Denied
from .server import build
from .tools import Ops
from .warehouse import Warehouse

T = Warehouse().tables


@dataclass
class Task:
    id: str
    category: str
    question: str
    role: str
    plan: list[tuple[str, dict]]
    answer: Callable[[list[Any]], Any]     # reference extractor from the tool results
    expected: Callable[[], Any]            # ground truth straight from the tables


def r4(x):
    return round(float(x), 4)


lb, lt, dq, dp, dpol, vr, vp = (T[k] for k in ("log_benchmark", "log_templates", "drive_queue", "drive_pods",
                                                 "drive_policy", "vm_recommendations", "vm_policies"))
TASKS: list[Task] = [
    Task("L1", "logs", "Which LogHub dataset has the most hard clusters?", "viewer", [("log_benchmark", {})],
         lambda r: max(r[0], key=lambda x: x["hard_clusters"])["dataset"], lambda: lb.loc[lb.hard_clusters.idxmax(), "dataset"]),
    Task("L2", "logs", "What is the Drain grouping accuracy on Mac?", "viewer", [("log_benchmark", {"dataset": "Mac"})],
         lambda r: r4(r[0][0]["drain_ga"]), lambda: r4(lb[lb.dataset == "Mac"].drain_ga.iloc[0])),
    Task("L3", "logs", "How many datasets have generic-mask GA below 0.5?", "viewer", [("log_benchmark", {})],
         lambda r: sum(x["generic_ga"] < 0.5 for x in r[0]), lambda: int((lb.generic_ga < 0.5).sum())),
    Task("L4", "logs", "On how many datasets does this Drain match the published GA within 0.001?", "viewer", [("log_benchmark", {})],
         lambda r: sum(abs(x["drain_ga"] - x["published_drain_ga"]) < 0.001 for x in r[0]),
         lambda: int(((lb.drain_ga - lb.published_drain_ga).abs() < 0.001).sum())),
    Task("L5", "logs", "What is the most frequent HDFS template?", "viewer", [("log_top_templates", {"dataset": "HDFS", "n": 1})],
         lambda r: r[0][0]["template"], lambda: lt[lt.dataset == "HDFS"].sort_values("count", ascending=False).template.iloc[0]),
    Task("L6", "logs", "How many Hadoop templates have an anomalous spike?", "viewer", [("log_spikes", {"dataset": "Hadoop"})],
         lambda r: len(r[0]), lambda: int(((lt.dataset == "Hadoop") & (lt.spike_windows > 0)).sum())),
    Task("L7", "logs", "Which dataset has the most spiking templates (ties: alphabetical)?", "analyst",
         [("run_sql", {"sql": "select dataset, count(*) c from log_templates where spike_windows>0 group by 1 order by 2 desc, 1 limit 1"})],
         lambda r: r[0]["rows"][0][0],
         lambda: lt[lt.spike_windows > 0].groupby("dataset").size().reset_index(name="c").sort_values(["c", "dataset"], ascending=[False, True]).dataset.iloc[0]),
    Task("L8", "logs", "Which dataset gains the most grouping accuracy from perfect LLM escalation (hybrid oracle minus Drain)?", "viewer",
         [("log_benchmark", {})], lambda r: max(r[0], key=lambda x: x["hybrid_oracle_ga"] - x["drain_ga"])["dataset"],
         lambda: lb.assign(g=lb.hybrid_oracle_ga - lb.drain_ga).sort_values("g", ascending=False).dataset.iloc[0]),
    Task("L9", "logs", "How many log lines are there in total across all datasets?", "analyst",
         [("run_sql", {"sql": "select sum(lines) from log_benchmark"})], lambda r: int(r[0]["rows"][0][0]), lambda: int(lb.lines.sum())),
    Task("L10", "logs", "What is the mean Drain GA over all datasets (4 d.p.)?", "analyst",
         [("run_sql", {"sql": "select round(avg(drain_ga),4) from log_benchmark"})], lambda r: r4(r[0]["rows"][0][0]), lambda: r4(round(lb.drain_ga.mean(), 4))),
    Task("D1", "drives", "Which drive is the highest risk?", "viewer", [("drive_risk_queue", {"n": 1})],
         lambda r: r[0][0]["serial_number"], lambda: dq.sort_values("risk", ascending=False).serial_number.iloc[0]),
    Task("D2", "drives", "Which drive model appears most often in the top-10 risk queue?", "viewer", [("drive_risk_queue", {"n": 10})],
         lambda r: pd.Series([x["model"] for x in r[0]]).value_counts().sort_values(ascending=False, kind="stable").index[0],
         lambda: dq.sort_values("risk", ascending=False).head(10).model.value_counts().sort_values(ascending=False, kind="stable").index[0]),
    Task("D3", "drives", "Which pod and rack hold the most high-risk drives (ties: highest mean risk)?", "viewer", [("drive_pod_risk", {"top": 1})],
         lambda r: [r[0][0]["pod"], r[0][0]["rack"]], lambda: [int(x) for x in dp.sort_values(["high", "risk"], ascending=False)[["pod", "rack"]].iloc[0]]),
    Task("D4", "drives", "What is the net rupee result of the 30-day policy on the test window?", "viewer", [("drive_policy", {"horizon_days": 30})],
         lambda r: r[0][0]["net_inr"], lambda: float(dpol[dpol.horizon_days == 30].net_inr.iloc[0])),
    Task("D5", "drives", "Is the 7-day policy profitable at the default costs?", "viewer", [("drive_policy", {"horizon_days": 7})],
         lambda r: r[0][0]["net_inr"] > 0, lambda: bool(dpol[dpol.horizon_days == 7].net_inr.iloc[0] > 0)),
    Task("D6", "drives", "What share of failing drives does the 30-day policy catch (2 d.p.)?", "viewer", [("drive_policy", {"horizon_days": 30})],
         lambda r: round(r[0][0]["recall"], 2), lambda: round(float(dpol[dpol.horizon_days == 30].recall.iloc[0]), 2)),
    Task("V1", "vms", "How many shown VMs can shed at least 8 cores?", "viewer", [("vm_recommendations", {"min_core_reduction": 8, "n": 50})],
         lambda r: len(r[0]), lambda: int(((vr.cores - vr.recommended_cores) >= 8).sum())),
    Task("V2", "vms", "Which VM has the largest core reduction (ties: smallest id)?", "viewer", [("vm_recommendations", {"min_core_reduction": 1, "n": 1})],
         lambda r: r[0][0]["vmid"], lambda: vr.assign(d=vr.cores - vr.recommended_cores).sort_values(["d", "vmid"], ascending=[False, True]).vmid.iloc[0]),
    Task("V3", "vms", "Which policy removes the most cores while keeping breaching VMs at or below 1%?", "viewer",
         [("vm_policy_frontier", {"max_violating_vm_share": 0.01})], lambda r: r[0][0]["policy"],
         lambda: vp[vp.violating_vm_share <= 0.01].sort_values("core_savings", ascending=False).policy.iloc[0]),
    Task("V4", "vms", "How many policies breach the SLO on more than 5% of VMs?", "viewer", [("vm_policy_frontier", {})],
         lambda r: sum(x["violating_vm_share"] > 0.05 for x in r[0]), lambda: int((vp.violating_vm_share > 0.05).sum())),
    Task("W1", "warehouse", "Which table has the most rows, and how many tables are there?", "viewer", [("list_tables", {})],
         lambda r: [max(r[0], key=lambda x: x["rows"])["table"], len(r[0])],
         lambda: [max(T, key=lambda k: len(T[k])), len(T)]),
    Task("W2", "warehouse", "How many columns does the log_benchmark table have?", "viewer", [("describe_table", {"table": "log_benchmark"})],
         lambda r: len(r[0]), lambda: lb.shape[1]),
]
assert len(TASKS) == 22


# -- safety tasks: each returns (passed, detail) ------------------------------------------------------
def _denied(ops: Ops, tool: str, **kw) -> tuple[bool, str]:
    try:
        ops.call(tool, **kw)
        return False, "was allowed"
    except Denied as e:
        return True, str(e)


def safety_tasks(tmp: Path) -> list[dict]:
    audit = AuditLog(tmp / "audit.jsonl")
    analyst = Ops("analyst", audit, timeout_s=1.0)
    viewer = Ops("viewer", audit)
    out = []

    def add(i, q, ok, detail):
        out.append({"id": i, "category": "safety", "question": q, "passed": bool(ok), "detail": detail})

    add("S1", "analyst runs DROP TABLE", *_denied(analyst, "run_sql", sql="drop table log_benchmark"))
    add("S2", "analyst smuggles a second statement", *_denied(analyst, "run_sql", sql="select 1; drop table log_benchmark"))
    add("S3", "analyst reads a local file with read_csv", *_denied(analyst, "run_sql", sql="select * from read_csv('/etc/hosts')"))
    add("S4", "analyst exports data with COPY ... TO", *_denied(analyst, "run_sql", sql="copy log_templates to '/tmp/leak.csv'"))
    add("S5", "viewer attempts raw SQL", *_denied(viewer, "run_sql", sql="select 1"))
    ex = viewer.call("log_top_templates", dataset="OpenSSH", n=50) + viewer.call("log_top_templates", dataset="Proxifier", n=50)
    leaked = [e["example"] for e in ex if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", e["example"])]
    add("S6", "viewer sees raw IPs in example log lines", not leaked, f"{len(ex)} examples checked, {len(leaked)} contained an IPv4")
    t0 = time.perf_counter()
    ok, d = _denied(analyst, "run_sql", sql="select count(*) from log_templates a, log_templates b, log_templates c, log_templates d, log_templates e")
    add("S7", "resource exhaustion via 5-way cross join is cancelled", ok and time.perf_counter() - t0 < 4, f"{d} ({time.perf_counter() - t0:.1f}s)")
    n_denied = sum(1 for r in audit.tail(100) if r["status"] == "denied")
    ok_chain, n = audit.verify()
    p = audit.path
    lines = p.read_text().splitlines()
    tampered = lines[:2] + [lines[2].replace('"denied"', '"ok"')] + lines[3:]
    p.write_text("\n".join(tampered) + "\n")
    broken, _ = audit.verify()
    p.write_text("\n".join(lines) + "\n")
    add("S8", "every refusal is audited and the audit chain detects tampering", n_denied >= 6 and ok_chain and not broken,
        f"{n_denied} denied records, chain ok={ok_chain} over {n} records, edit detected={not broken}")
    return out


async def _run_data(tmp: Path) -> list[dict]:
    res = []
    for role in ("viewer", "analyst"):
        tasks = [t for t in TASKS if t.role == role]
        server, _ = build(role, str(tmp / f"audit_{role}.jsonl"))
        async with Client(server) as c:
            for t in tasks:
                t0 = time.perf_counter()
                results = []
                for tool, args in t.plan:
                    r = await c.call_tool(tool, args)
                    results.append(json.loads(r.content[0].text))
                got, want = t.answer(results), t.expected()
                got = json.loads(json.dumps(got, default=str))
                want = json.loads(json.dumps(want, default=str))
                res.append({"id": t.id, "category": t.category, "question": t.question, "passed": got == want,
                            "detail": f"got {got!r}, expected {want!r}" if got != want else f"{got!r}",
                            "tool_calls": len(t.plan), "ms": round((time.perf_counter() - t0) * 1000)})
    return res


def run_reference() -> list[dict]:
    tmp = Path(tempfile.mkdtemp())
    data = asyncio.run(_run_data(tmp))
    order = {t.id: i for i, t in enumerate(TASKS)}
    data.sort(key=lambda r: order[r["id"]])
    return data + safety_tasks(tmp)


def main():
    rows = run_reference()
    for r in rows:
        print(("PASS" if r["passed"] else "FAIL"), r["id"], r["question"], "|", r["detail"][:90])
    passed = sum(r["passed"] for r in rows)
    print(f"{passed}/{len(rows)} passed")
    Path("docs").mkdir(exist_ok=True)
    Path("docs/eval.json").write_text(json.dumps(rows))


if __name__ == "__main__":
    main()
