# ops-mcp-server

A read-only, audited [MCP](https://modelcontextprotocol.io) server that exposes an ops warehouse as tools any agent can call. The warehouse holds the published results of three sibling projects:

| table(s) | source |
|---|---|
| `log_benchmark`, `log_templates` | [logmine-bench](https://github.com/rishikeshn-eng/logmine-bench) (real LogHub-2k) |
| `drive_queue`, `drive_pods`, `drive_policy` | [drive-early-warning](https://github.com/rishikeshn-eng/drive-early-warning) (synthetic fleet) |
| `vm_recommendations`, `vm_policies` | [vm-rightsizer](https://github.com/rishikeshn-eng/vm-rightsizer) (synthetic fleet) |

**Docs page:** https://rishikeshn-eng.github.io/ops-mcp-server/ (tool catalog, the 30-task results, a sample audit trail)

## Tools

12 tools. `viewer` (the default role) gets 10 curated ones; `analyst` also gets `run_sql` and `audit_tail`. A role only sees the tools it may call, so an unregistered tool cannot be prompt-injected into use.

`list_tables`, `describe_table`, `run_sql`*, `audit_tail`*, `log_benchmark`, `log_top_templates`, `log_spikes`, `drive_risk_queue`, `drive_pod_risk`, `drive_policy`, `vm_recommendations`, `vm_policy_frontier` (\*analyst only)

## Safety model

- **Read-only by construction.** Each role gets its own in-memory DuckDB copy of the tables, opened with `enable_external_access=false` and locked configuration. File reads fail, nothing persists, and `viewer` literally has no other data to reach.
- **SQL guard** (`guard.py`, analyst only): exactly one statement, statement type SELECT (checked by DuckDB's parser, not a regex), a denylist of file/table functions and DDL/DML keywords, 500-row cap, 5 s timeout that cancels the query.
- **Redaction.** `viewer` sees example log lines with IPs and hostnames masked; `analyst` sees them raw. A test asserts the masking is not vacuous (the raw data does contain IPs).
- **Audit log** (`audit.py`): every call, including refusals and errors, is appended to JSONL with a SHA-256 hash chain. Editing, deleting or reordering a record makes `verify()` fail.

### What this is not
- Roles are chosen by the `OPS_MCP_ROLE` environment variable of the server process. There is no per-user authentication, no OAuth, and only the stdio transport is exercised. Put real identity in front of it before exposing it.
- The keyword denylist is deliberately blunt and has false positives (a column or identifier named `set`, `load`, `export`, `call` is refused). The parser check and the locked connection are the real controls; the denylist is a third layer.
- The data is a snapshot of the sibling projects' outputs, not a live warehouse. It has not had a security review.

## Evaluation: 30 tasks, 30/30 on the reference run

22 data tasks across logs, drives, VMs and the warehouse itself, plus 8 safety tasks (DROP, multi-statement, `read_csv`, `COPY ... TO`, viewer calling SQL, IP leakage, a 5-way cross-join that must be cancelled, audit completeness and tamper detection). Each data task has a reference tool plan and an expected answer computed from the raw tables with pandas, independently of the tool layer.

**What the 30/30 means:** the tools return the right answers through a real MCP client and the guardrails hold. **What it does not mean:** that an LLM agent will use the tools well. `python -m opsmcp.agent_eval` runs a Gemini function-calling agent on the same 22 data tasks and scores whether the expected value appears in its answer; that loop is unit-tested against a scripted fake model but **has not been run against Gemini** (no API key at build time).

## Run

```bash
pip install "mcp>=2" duckdb pandas pytest        # mcp 2.x: the server uses MCPServer, not FastMCP
python -m pytest -q                               # 23 tests, ~3 s
python -m opsmcp.evals                            # the 30-task reference run
OPS_MCP_ROLE=analyst python -m opsmcp             # stdio server
```

Claude Desktop / any MCP client config:

```json
{"mcpServers": {"ops-warehouse": {"command": "python", "args": ["-m", "opsmcp"],
  "env": {"OPS_MCP_ROLE": "viewer", "OPS_MCP_AUDIT": "audit/audit.jsonl"}}}}
```

To add a source (for example the 311 forecaster), add a loader in `warehouse.py`, a description, and a tool in `tools.py` (`t_<name>`); the role table and server registration pick it up.
