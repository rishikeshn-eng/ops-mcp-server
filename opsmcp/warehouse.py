"""Warehouse tables built from the published results of logmine-bench, drive-early-warning and vm-rightsizer.

Each role gets its own in-memory DuckDB copy with external access disabled and configuration locked, so a role can
only ever see the tables/columns it was given, and nothing it does can touch disk or persist.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import duckdb
import pandas as pd

SNAP = Path(__file__).resolve().parent.parent / "snapshots"

DESCRIPTIONS = {
    "log_benchmark": "Per-dataset log parsing benchmark (LogHub-2k): Drain grouping accuracy vs published baseline.",
    "log_templates": "Mined log templates per dataset with counts, spike windows and one example raw line.",
    "drive_queue": "Top-25 highest-risk drives from the latest scored week (synthetic Backblaze-schema fleet).",
    "drive_pods": "Mean predicted risk and high-risk drive counts by pod and rack.",
    "drive_policy": "Replacement policy backtest per horizon, priced in rupees.",
    "vm_recommendations": "Largest VM downsizing recommendations with observed vs forecast peaks (synthetic fleet).",
    "vm_policies": "Rightsizing policies: cores removed vs share of VMs that would breach the throttle SLO.",
}
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
HOST = re.compile(r"\b(?:[\w-]+\.){2,}[\w-]+\b")


def redact(text: str) -> str:
    return HOST.sub("<host>", IP.sub("<ip>", text or ""))


def load_tables() -> dict[str, pd.DataFrame]:
    lm = json.loads((SNAP / "logmine.json").read_text())
    dr = json.loads((SNAP / "drive.json").read_text())
    vm = json.loads((SNAP / "vm.json").read_text())
    t = {}
    t["log_benchmark"] = pd.DataFrame([
        {"dataset": r["dataset"], "lines": r["lines"], "true_templates": r["true_templates"],
         "drain_ga": r["drain_GA"], "published_drain_ga": r["published_drain_GA"], "generic_ga": r["generic_GA"],
         "hybrid_oracle_ga": r.get("hybrid_GA"), "hard_clusters": r["hard_clusters"]} for r in lm["results"]])
    rows = []
    for ds, tree in lm["trees"].items():
        for n in tree:
            rows.append({"dataset": ds, "template": n["template"], "count": n["count"],
                         "spike_windows": len(n["spikes"]), "example": n["example"]})
    t["log_templates"] = pd.DataFrame(rows)
    t["drive_queue"] = pd.DataFrame(dr["queue"]).rename(columns={"smart_5_raw": "smart_5", "smart_187_raw": "smart_187",
                                                                 "smart_197_raw": "smart_197", "smart_198_raw": "smart_198"})
    t["drive_pods"] = pd.DataFrame(dr["map"])
    t["drive_policy"] = pd.DataFrame([
        {"horizon_days": int(h), "roc_auc": m["roc_auc"], "pr_auc": m["pr_auc"],
         "failing_drives": m["policy_test"]["failing_drives"], "replacements": m["policy_test"]["replacements"],
         "avoided_failures": m["policy_test"]["avoided_failures"], "false_alarms": m["policy_test"]["false_alarms"],
         "recall": m["policy_test"]["recall"], "net_inr": m["policy_test"]["net_inr"],
         "net_inr_ci_low": m["policy_net_ci95"][0], "net_inr_ci_high": m["policy_net_ci95"][1]}
        for h, m in dr["metrics"].items()])
    t["vm_recommendations"] = pd.DataFrame([{k: e[k] for k in ("vmid", "cores", "rec", "peak_hist", "peak_future")}
                                            for e in vm["examples"]]).rename(columns={"rec": "recommended_cores"})
    t["vm_policies"] = pd.DataFrame([{"policy": p["name"], "kind": p["kind"], "core_savings": p["core_savings"],
                                      "violating_vm_share": p["viol"], "mean_throttled_share": p["mean_throttled_share"],
                                      "inr_saved_per_month": p["inr_saved_per_month"]} for p in vm["pareto"]])
    return t


class Warehouse:
    def __init__(self):
        self.tables = load_tables()

    def connect(self, role: str) -> duckdb.DuckDBPyConnection:
        """In-memory copy for a role. viewer: example lines redacted. All roles: no file access, config locked."""
        con = duckdb.connect(":memory:", config={"enable_external_access": False})
        for name, df in self.tables.items():
            d = df.copy()
            if role == "viewer" and name == "log_templates":
                d["example"] = d["example"].map(redact)
            con.register(f"_src_{name}", d)
            con.execute(f'CREATE TABLE "{name}" AS SELECT * FROM _src_{name}')
            con.unregister(f"_src_{name}")
        con.execute("SET lock_configuration = true")
        return con
