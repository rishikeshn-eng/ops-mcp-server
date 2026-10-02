"""Run a Gemini agent (function calling) against the same 22 data tasks over the real MCP server.

    GEMINI_API_KEY=... python -m opsmcp.agent_eval

Scores whether the expected value appears in the agent's final answer. NOT run at build time (no API key):
`reference` numbers in the README validate the tools, not an agent.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import urllib.request
from pathlib import Path

from mcp.client import Client

from .evals import TASKS
from .server import build

MAX_STEPS = 8


def _http(body: dict) -> dict:
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "x-goog-api-key": os.environ["GEMINI_API_KEY"]})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def _schema(s: dict) -> dict:
    """MCP JSON schema -> the OpenAPI subset Gemini accepts."""
    keep = {"type", "properties", "required", "description", "items", "enum"}
    out = {k: v for k, v in s.items() if k in keep}
    if "anyOf" in s:  # Optional[X] -> X
        non_null = [x for x in s["anyOf"] if x.get("type") != "null"]
        out.update(_schema(non_null[0]) if non_null else {"type": "string"})
    if "properties" in out:
        out["properties"] = {k: _schema(v) for k, v in out["properties"].items()}
    if "type" in out and isinstance(out["type"], str):
        out["type"] = out["type"].upper()
    return out


def matches(answer: str, expected) -> bool:
    flat = expected if isinstance(expected, list) else [expected]
    norm = lambda x: str(x).lower().replace(",", "")
    a = norm(answer)
    return all(norm(x) in a for x in flat)


async def run_task(client: Client, task, transport) -> dict:
    tools = (await client.list_tools()).tools
    decl = [{"name": t.name, "description": t.description or "", "parameters": _schema(t.input_schema)} for t in tools]
    contents = [{"role": "user", "parts": [{"text": task.question + " Use the tools; answer concisely."}]}]
    calls = tokens = 0
    for _ in range(MAX_STEPS):
        resp = transport({"contents": contents, "tools": [{"functionDeclarations": decl}],
                          "generationConfig": {"temperature": 0}})
        tokens += (resp.get("usageMetadata") or {}).get("totalTokenCount", 0)
        parts = resp["candidates"][0]["content"]["parts"]
        contents.append({"role": "model", "parts": parts})
        fcs = [p["functionCall"] for p in parts if "functionCall" in p]
        if not fcs:
            text = " ".join(p.get("text", "") for p in parts)
            return {"id": task.id, "answer": text, "tool_calls": calls, "tokens": tokens,
                    "passed": matches(text, task.expected())}
        resp_parts = []
        for fc in fcs:
            calls += 1
            r = await client.call_tool(fc["name"], fc.get("args", {}))
            resp_parts.append({"functionResponse": {"name": fc["name"], "response": {"result": r.content[0].text}}})
        contents.append({"role": "user", "parts": resp_parts})
    return {"id": task.id, "answer": "", "tool_calls": calls, "tokens": tokens, "passed": False}


async def run_all(transport=_http, role_tasks=None) -> list[dict]:
    rows = []
    tmp = Path(tempfile.mkdtemp())
    for role in ("viewer", "analyst"):
        server, _ = build(role, str(tmp / f"{role}.jsonl"))
        async with Client(server) as c:
            for t in (role_tasks or TASKS):
                if t.role == role:
                    rows.append(await run_task(c, t, transport))
    return rows


def main():
    rows = asyncio.run(run_all())
    for r in rows:
        print("PASS" if r["passed"] else "FAIL", r["id"], f"{r['tool_calls']} calls", r["answer"][:80].replace("\n", " "))
    print(f"{sum(r['passed'] for r in rows)}/{len(rows)} correct, {sum(r['tokens'] for r in rows)} tokens")


if __name__ == "__main__":
    main()
