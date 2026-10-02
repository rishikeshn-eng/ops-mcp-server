"""Run the eval, then embed results + tool catalog + a sample audit trail into docs/index.html."""
import asyncio, json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pathlib import Path
from mcp.client import Client
from opsmcp import evals
from opsmcp.audit import AuditLog
from opsmcp.server import build
from opsmcp.tools import Ops, ROLE_TOOLS
from opsmcp.guard import Denied

root = Path(__file__).resolve().parent.parent
rows = evals.run_reference()
(root / "docs" / "eval.json").write_text(json.dumps(rows))

async def tools():
    server, _ = build("analyst", tempfile.mktemp())
    async with Client(server) as c:
        return [{"name": t.name, "description": t.description, "viewer": t.name in ROLE_TOOLS["viewer"]} for t in (await c.list_tools()).tools]

tl = asyncio.run(tools())
audit = AuditLog(tempfile.mktemp())
v, a = Ops("viewer", audit), Ops("analyst", audit)
v.call("list_tables"); v.call("log_benchmark", dataset="HDFS"); v.call("drive_risk_queue", n=3)
for fn, kw in ((v.call, ("run_sql", {"sql": "select 1"})), (a.call, ("run_sql", {"sql": "drop table log_benchmark"})),
               (a.call, ("run_sql", {"sql": "select * from read_csv('/etc/passwd')"}))):
    try: fn(kw[0], **kw[1])
    except Denied: pass
a.call("run_sql", sql="select dataset, hard_clusters from log_benchmark order by 2 desc limit 3")
rec = audit.tail(20)
payload = {"eval": rows, "tools": tl, "viewer_tools": len(ROLE_TOOLS["viewer"]), "audit": rec,
           "denied": sum(r["status"] == "denied" for r in rec)}
html = (root / "site" / "template.html").read_text().replace("__DATA__", json.dumps(payload).replace("</", "<\\/"))
(root / "docs" / "index.html").write_text(html)
print("wrote docs/index.html;", sum(r["passed"] for r in rows), "/", len(rows), "tasks pass")
