"""MCP server (stdio by default). Role comes from OPS_MCP_ROLE (default: viewer, the least privileged)."""
from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from .audit import AuditLog
from .guard import Denied
from .tools import ROLE_TOOLS, Ops


def build(role: str | None = None, audit_path: str | None = None) -> tuple[MCPServer, Ops]:
    role = role or os.environ.get("OPS_MCP_ROLE", "viewer")
    audit = AuditLog(audit_path or os.environ.get("OPS_MCP_AUDIT", "audit/audit.jsonl"))
    ops = Ops(role, audit)
    mcp = MCPServer("ops-warehouse", instructions=(
        "Read-only ops warehouse: log template mining, drive failure risk, VM rightsizing. "
        "Prefer the curated tools; run_sql (analyst role) accepts one SELECT. Every call is audited."))

    def wrap(tool: str):
        def run(**kw):
            try:
                return json.dumps(ops.call(tool, **kw), default=str)
            except Denied as e:
                return json.dumps({"error": "denied", "reason": str(e)})
        return run

    # Register only what the role may call: a tool the role cannot see cannot be prompt-injected into use.
    allowed = ROLE_TOOLS[role]
    defs = {
        "list_tables": "List warehouse tables with row counts and descriptions.",
        "describe_table": "Column names and types for one table.",
        "run_sql": "Run ONE read-only SELECT (max 500 rows, 5 s). Analyst role only.",
        "audit_tail": "Last N audit log records. Analyst role only.",
        "log_benchmark": "Drain parsing accuracy vs the published baseline, one dataset or all.",
        "log_top_templates": "Most frequent mined log templates for a dataset.",
        "log_spikes": "Templates with anomalous count spikes for a dataset.",
        "drive_risk_queue": "Highest-risk drives to replace first, optionally for one model.",
        "drive_pod_risk": "Pod/rack cells ranked by high-risk drive count.",
        "drive_policy": "Replacement-policy backtest (rupees) for a 7 or 30 day horizon.",
        "vm_recommendations": "Largest VM downsizing recommendations.",
        "vm_policy_frontier": "Rightsizing policies; optionally cap the share of VMs that may breach the SLO.",
    }
    import inspect
    for name, desc in defs.items():
        if allowed is not None and name not in allowed:
            continue
        impl = getattr(ops, "t_" + name)
        fn = wrap(name)
        fn.__signature__ = inspect.signature(impl)
        fn.__name__, fn.__doc__ = name, desc
        fn.__annotations__ = dict(impl.__annotations__)
        mcp.tool()(fn)
    return mcp, ops


def main():
    mcp, _ = build()
    mcp.run("stdio")


if __name__ == "__main__":
    main()
