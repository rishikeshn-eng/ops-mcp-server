"""SQL guard: one statement, SELECT only, row-capped, time-boxed. Defence in depth: the connection itself has no
file access and locked config, so the guard is not the only line."""
from __future__ import annotations

import re
import threading

import duckdb

MAX_ROWS = 500
TIMEOUT_S = 5.0
# table functions / commands that reach outside the data even inside a SELECT
FORBIDDEN = re.compile(r"\b(read_\w+|glob|copy|attach|detach|install|load|pragma|export|import|call|set|"
                       r"duckdb_\w+|pg_\w+|getenv|current_setting|sniff_csv|parquet_\w+|http\w*|s3|"
                       r"create|insert|update|delete|drop|alter|truncate|vacuum|checkpoint)\b", re.I)


class Denied(Exception):
    """Raised for requests the policy refuses (logged as status=denied)."""


def _strip(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"--[^\n]*", " ", sql)
    return sql.strip().rstrip(";").strip()


def check_select(con: duckdb.DuckDBPyConnection, sql: str) -> str:
    s = _strip(sql)
    if not s:
        raise Denied("empty statement")
    try:
        stmts = con.extract_statements(s)
    except Exception as e:  # parse error
        raise Denied(f"cannot parse: {e}") from None
    if len(stmts) != 1:
        raise Denied("exactly one statement is allowed")
    if stmts[0].type != duckdb.StatementType.SELECT:
        raise Denied(f"only SELECT is allowed, got {stmts[0].type.name}")
    m = FORBIDDEN.search(re.sub(r"'(?:[^']|'')*'", "''", s))  # ignore words inside string literals
    if m:
        raise Denied(f"keyword/function not allowed: {m.group(0)}")
    return s


def run_select(con, sql: str, limit: int = 100, timeout_s: float = TIMEOUT_S):
    limit = max(1, min(int(limit), MAX_ROWS))
    s = check_select(con, sql)
    timer = threading.Timer(timeout_s, con.interrupt)
    timer.start()
    try:
        cur = con.execute(f"SELECT * FROM ({s}) AS q LIMIT {limit + 1}")
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
    except duckdb.InterruptException:
        raise Denied(f"query exceeded {timeout_s}s and was cancelled") from None
    except duckdb.Error as e:
        raise Denied(f"query failed: {e}") from None
    finally:
        timer.cancel()
    truncated = len(rows) > limit
    return {"columns": cols, "rows": [list(r) for r in rows[:limit]], "truncated": truncated}
