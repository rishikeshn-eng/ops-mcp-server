import asyncio
import json
import sys

import pytest
from mcp import StdioServerParameters
from mcp.client import Client

from opsmcp import agent_eval, evals
from opsmcp.audit import AuditLog
from opsmcp.guard import Denied, check_select, run_select
from opsmcp.server import build
from opsmcp.tools import Ops
from opsmcp.warehouse import Warehouse

WH = Warehouse()


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "a.jsonl")


@pytest.mark.parametrize("sql", [
    "drop table log_templates", "select 1; select 2", "select * from read_csv('/etc/hosts')",
    "copy log_templates to '/tmp/x.csv'", "attach 'x.db'", "pragma database_list", "install httpfs",
    "select * from glob('/*')", "", "select from where", "update log_benchmark set lines = 0",
    "with x as (select 1) insert into log_benchmark select * from log_benchmark",
])
def test_guard_refuses(sql):
    con = WH.connect("analyst")
    with pytest.raises(Denied):
        run_select(con, sql)


def test_guard_allows_select_and_cte_and_ignores_keywords_in_strings():
    con = WH.connect("analyst")
    assert run_select(con, "with a as (select dataset from log_benchmark) select count(*) from a")["rows"] == [[16]]
    assert run_select(con, "select 'drop table x; read_csv' as s")["rows"] == [["drop table x; read_csv"]]
    assert run_select(con, "select 1 -- ; drop table x")["rows"] == [[1]]


def test_row_cap_and_truncation():
    con = WH.connect("analyst")
    r = run_select(con, "select * from log_templates", limit=5)
    assert len(r["rows"]) == 5 and r["truncated"]
    assert len(run_select(con, "select * from log_templates", limit=10 ** 9)["rows"]) == 500


def test_connection_cannot_reach_files_even_if_guard_is_bypassed():
    con = WH.connect("analyst")
    with pytest.raises(Exception):
        con.execute("select * from read_csv('/etc/hosts')").fetchall()
    with pytest.raises(Exception):
        con.execute("set enable_external_access = true")


def test_viewer_is_redacted_analyst_is_not(audit):
    v, a = Ops("viewer", audit), Ops("analyst", audit)
    ip = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    import re
    va = [e["example"] for ds in ("OpenSSH", "Proxifier") for e in v.call("log_top_templates", dataset=ds, n=50)]
    aa = [e["example"] for ds in ("OpenSSH", "Proxifier") for e in a.call("log_top_templates", dataset=ds, n=50)]
    assert not any(re.search(ip, x) for x in va) and any(re.search(ip, x) for x in aa)  # redaction is not vacuous


def test_role_gating_and_unknown_role(audit):
    with pytest.raises(Denied):
        Ops("viewer", audit).call("run_sql", sql="select 1")
    with pytest.raises(Denied):
        Ops("viewer", audit).call("audit_tail")
    with pytest.raises(ValueError):
        Ops("root", audit)


def test_audit_records_ok_denied_and_error_and_chain_verifies(audit):
    o = Ops("analyst", audit)
    o.call("list_tables")
    with pytest.raises(Denied):
        o.call("run_sql", sql="drop table x")
    with pytest.raises(Exception):
        o.call("log_top_templates", nonsense=1)
    st = [r["status"] for r in audit.tail()]
    assert st == ["ok", "denied", "error"]
    assert audit.verify() == (True, 3)
    # reopening continues the chain
    AuditLog(audit.path).record(role="x", tool="y", args={}, status="ok")
    assert audit.verify() == (True, 4)


def test_unknown_table_denied(audit):
    with pytest.raises(Denied):
        Ops("viewer", audit).call("describe_table", table="users; drop")


def test_viewer_mcp_server_does_not_even_list_run_sql(tmp_path):
    async def go():
        server, _ = build("viewer", str(tmp_path / "v.jsonl"))
        async with Client(server) as c:
            return {t.name for t in (await c.list_tools()).tools}
    names = asyncio.run(go())
    assert "run_sql" not in names and "audit_tail" not in names and "log_benchmark" in names


def test_stdio_server_roundtrip(tmp_path):
    async def go():
        params = StdioServerParameters(command=sys.executable, args=["-m", "opsmcp"],
                                       env={"OPS_MCP_ROLE": "viewer", "OPS_MCP_AUDIT": str(tmp_path / "s.jsonl")})
        async with Client(params) as c:
            r = await c.call_tool("log_benchmark", {"dataset": "HDFS"})
            return json.loads(r.content[0].text)
    out = asyncio.run(go())
    assert out[0]["dataset"] == "HDFS" and (tmp_path / "s.jsonl").exists()


def test_all_30_reference_tasks_pass():
    rows = evals.run_reference()
    assert len(rows) == 30
    assert [r["id"] for r in rows if not r["passed"]] == []


def test_agent_eval_loop_with_fake_model():
    """A scripted 'model' calls the right tool then answers: exercises the schema conversion and the loop."""
    task = next(t for t in evals.TASKS if t.id == "L2")
    state = {"n": 0}

    def fake(body):
        state["n"] += 1
        assert body["tools"][0]["functionDeclarations"]
        for d in body["tools"][0]["functionDeclarations"]:
            assert "anyOf" not in json.dumps(d["parameters"])
        if state["n"] == 1:
            return {"candidates": [{"content": {"parts": [{"functionCall": {"name": "log_benchmark", "args": {"dataset": "Mac"}}}]}}]}
        return {"candidates": [{"content": {"parts": [{"text": "Mac GA is 0.7865"}]}}], "usageMetadata": {"totalTokenCount": 10}}
    rows = asyncio.run(agent_eval.run_all(fake, [task]))
    assert rows == [{"id": "L2", "answer": "Mac GA is 0.7865", "tool_calls": 1, "tokens": 10, "passed": True}]
