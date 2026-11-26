"""Small sqlite key/value cache with a TTL (RDAP and crt.sh rate-limit)."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class Cache:
    def __init__(self, path: Path | None, ttl_seconds: int, enabled: bool = True):
        self.ttl = ttl_seconds
        self.enabled = enabled and path is not None
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        if self.enabled:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(path), check_same_thread=False)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, t REAL, v TEXT)"
            )
            self._db.commit()

    @classmethod
    def memory(cls) -> "Cache":
        c = cls(None, 0, enabled=False)
        return c

    def get(self, key: str, ttl: int | None = None) -> Any | None:
        if not self._db:
            return None
        ttl = self.ttl if ttl is None else ttl
        with self._lock:
            row = self._db.execute("SELECT t, v FROM kv WHERE k = ?", (key,)).fetchone()
        if not row:
            return None
        if ttl and time.time() - row[0] > ttl:
            return None
        try:
            return json.loads(row[1])
        except ValueError:
            return None

    def set(self, key: str, value: Any) -> None:
        if not self._db:
            return
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO kv (k, t, v) VALUES (?, ?, ?)",
                (key, time.time(), json.dumps(value)),
            )
            self._db.commit()

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None
