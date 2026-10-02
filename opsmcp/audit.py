"""Append-only, hash-chained JSONL audit log. Every call is recorded, including refusals."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "0" * 64
        return json.loads(self.path.read_text().strip().splitlines()[-1])["hash"]

    def record(self, **fields) -> dict:
        with self._lock:
            rec = {"ts": round(time.time(), 3), **fields, "prev": self._prev}
            rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()
            with self.path.open("a") as f:
                f.write(json.dumps(rec, default=str) + "\n")
            self._prev = rec["hash"]
            return rec

    def tail(self, n: int = 20) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().strip().splitlines()[-n:]]

    def verify(self) -> tuple[bool, int]:
        """Recompute the chain. Returns (ok, records_checked); any edit, deletion or reorder breaks it."""
        prev, n = "0" * 64, 0
        if not self.path.exists():
            return True, 0
        for line in self.path.read_text().strip().splitlines():
            rec = json.loads(line)
            h = rec.pop("hash")
            if rec["prev"] != prev or hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest() != h:
                return False, n
            prev, n = h, n + 1
        return True, n
