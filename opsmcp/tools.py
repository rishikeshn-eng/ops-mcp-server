"""Tool implementations. Pure functions over an `Ops` object so they are testable without MCP."""
from __future__ import annotations

import hashlib
import json
import time

from .audit import AuditLog
from .guard import Denied, run_select
from .warehouse import DESCRIPTIONS, Warehouse

ROLE_TOOLS = {
    # viewer: curated tools only, example log lines redacted, no free-form SQL, no audit access
    "viewer": {"list_tables", "describe_table", "log_benchmark", "log_top_templates", "log_spikes",
               "drive_risk_queue", "drive_pod_risk", "drive_policy", "vm_recommendations", "vm_policy_frontier"},
    # analyst: everything, including read-only SQL and the audit tail
    "analyst": None,
}


class Ops:
    def __init__(self, role: str, audit: AuditLog, warehouse: Warehouse | None = None, timeout_s: float = 5.0):
        if role not in ROLE_TOOLS:
            raise ValueError(f"unknown role {role!r}")
        self.role, self.audit, self.timeout_s = role, audit, timeout_s
        self.wh = warehouse or Warehouse()
        self.con = self.wh.connect(role)

    # -- plumbing ----------------------------------------------------------
    def call(self, tool: str, **args):
        """Single entry point: authorise, run, audit. Returns a JSON-able result or raises Denied."""
        t0 = time.perf_counter()
        status, rows, err = "ok", None, None
        try:
            allowed = ROLE_TOOLS[self.role]
            if allowed is not None and tool not in allowed:
                raise Denied(f"role '{self.role}' may not call {tool}")
            result = getattr(self, "t_" + tool)(**args)
            rows = len(result["rows"]) if isinstance(result, dict) and "rows" in result else \
                len(result) if isinstance(result, list) else 1
            return result
        except Denied as e:
            status, err = "denied", str(e)
            raise
        except Exception as e:
            status, err = "error", f"{type(e).__name__}: {e}"
            raise
        finally:
            self.audit.record(role=self.role, tool=tool, args=args, status=status, rows=rows, error=err,
                              ms=round((time.perf_counter() - t0) * 1000, 2),
                              args_sha=hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:12])

    def _q(self, sql: str, params=()):
        cur = self.con.execute(sql, list(params))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def _require_table(self, name: str):
        if name not in self.wh.tables:
            raise Denied(f"unknown table '{name}'. Known: {sorted(self.wh.tables)}")

    # -- discovery -----------------------------------------------------------
    def t_list_tables(self):
        return [{"table": n, "rows": len(df), "description": DESCRIPTIONS[n]} for n, df in self.wh.tables.items()]

    def t_describe_table(self, table: str):
        self._require_table(table)
        return self._q(f'SELECT column_name, data_type FROM information_schema.columns WHERE table_name = ? ORDER BY ordinal_position', [table])

    # -- raw SQL (analyst) ------------------------------------------------------
    def t_run_sql(self, sql: str, limit: int = 100):
        return run_select(self.con, sql, limit, self.timeout_s)

    def t_audit_tail(self, n: int = 20):
        return self.audit.tail(min(int(n), 100))

    # -- logs ----------------------------------------------------------------------
    def t_log_benchmark(self, dataset: str | None = None):
        if dataset:
            return self._q("SELECT * FROM log_benchmark WHERE lower(dataset) = lower(?)", [dataset])
        return self._q("SELECT * FROM log_benchmark ORDER BY dataset")

    def t_log_top_templates(self, dataset: str, n: int = 10):
        return self._q("SELECT template, count, spike_windows, example FROM log_templates WHERE lower(dataset)=lower(?) "
                       "ORDER BY count DESC LIMIT ?", [dataset, max(1, min(int(n), 50))])

    def t_log_spikes(self, dataset: str):
        return self._q("SELECT template, count, spike_windows FROM log_templates WHERE lower(dataset)=lower(?) AND spike_windows>0 "
                       "ORDER BY spike_windows DESC, count DESC", [dataset])

    # -- drives ---------------------------------------------------------------------
    def t_drive_risk_queue(self, n: int = 10, model: str | None = None):
        if model:
            return self._q("SELECT * FROM drive_queue WHERE model = ? ORDER BY risk DESC LIMIT ?", [model, max(1, min(int(n), 25))])
        return self._q("SELECT * FROM drive_queue ORDER BY risk DESC LIMIT ?", [max(1, min(int(n), 25))])

    def t_drive_pod_risk(self, top: int = 5):
        return self._q("SELECT pod, rack, drives, round(risk,4) AS mean_risk, high FROM drive_pods "
                       "ORDER BY high DESC, risk DESC LIMIT ?", [max(1, min(int(top), 50))])

    def t_drive_policy(self, horizon_days: int = 30):
        return self._q("SELECT * FROM drive_policy WHERE horizon_days = ?", [int(horizon_days)])

    # -- vms -------------------------------------------------------------------------
    def t_vm_recommendations(self, min_core_reduction: int = 1, n: int = 10):
        return self._q("SELECT *, cores - recommended_cores AS core_reduction FROM vm_recommendations "
                       "WHERE cores - recommended_cores >= ? ORDER BY core_reduction DESC, vmid LIMIT ?",
                       [int(min_core_reduction), max(1, min(int(n), 50))])

    def t_vm_policy_frontier(self, max_violating_vm_share: float | None = None):
        if max_violating_vm_share is None:
            return self._q("SELECT * FROM vm_policies ORDER BY core_savings DESC")
        return self._q("SELECT * FROM vm_policies WHERE violating_vm_share <= ? ORDER BY core_savings DESC",
                       [float(max_violating_vm_share)])
