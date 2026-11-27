"""A small on-disk cache (one SQLite file) for answers from external sources.

* Values are JSON, zlib-compressed (stored web pages shrink about tenfold).
* Each read says how old an answer may be. An expired answer is kept: when a
  fresh lookup fails (a timeout, a rate limit, an outage), `get_stale` can
  still return it, up to `max_stale` seconds old.
* Entries older than `max_stale` are deleted when the cache is opened.
* WAL mode and a busy timeout let several runs share the file at once; a
  write that still cannot get the lock is skipped, never fatal.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import zlib
from collections import Counter
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_MAX_STALE = 30 * 86400
CACHE_FILE = "domainfinder-cache.sqlite"


class Cache:
    def __init__(self, path: Path | None, ttl_seconds: int, enabled: bool = True,
                 max_stale: int = DEFAULT_MAX_STALE):
        self.ttl = ttl_seconds
        self.max_stale = max_stale
        self.enabled = enabled and path is not None
        self.path = path
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        self.stats: Counter[str] = Counter()  # hit, miss, stored, stale, pruned, write_skipped
        if self.enabled:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
            self._db.execute("PRAGMA busy_timeout = 30000")
            try:
                self._db.execute("PRAGMA auto_vacuum = INCREMENTAL")  # takes effect on a new file only
                self._db.execute("PRAGMA journal_mode = WAL")
            except sqlite3.OperationalError as e:  # e.g. a network file system without WAL support
                log.debug("cache: %s", e)
            self._db.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, t REAL, v BLOB)")
            self._db.commit()
            self.prune()

    @classmethod
    def memory(cls) -> "Cache":
        return cls(None, 0, enabled=False)

    # ------------------------------------------------------------------ io
    @staticmethod
    def _encode(value: Any) -> bytes:
        return zlib.compress(json.dumps(value).encode("utf-8"), 6)

    @staticmethod
    def _decode(raw: Any) -> Any:
        if isinstance(raw, bytes):
            raw = zlib.decompress(raw).decode("utf-8")
        return json.loads(raw)  # rows written before 1.5.0 hold plain JSON text

    def _row(self, key: str) -> tuple[float, Any] | None:
        if not self._db:
            return None
        try:
            with self._lock:
                row = self._db.execute("SELECT t, v FROM kv WHERE k = ?", (key,)).fetchone()
        except sqlite3.OperationalError as e:
            log.debug("cache read skipped: %s", e)
            return None
        if not row:
            return None
        try:
            return row[0], self._decode(row[1])
        except (ValueError, zlib.error, UnicodeDecodeError):
            return None

    def get(self, key: str, ttl: int | None = None) -> Any | None:
        """The cached value if it is at most `ttl` seconds old (default: the
        cache's lifetime). A ttl of 0 means "any age"."""
        row = self._row(key)
        ttl = self.ttl if ttl is None else ttl
        if row is None or (ttl and time.time() - row[0] > ttl):
            if self._db:
                self.stats["miss"] += 1
            return None
        self.stats["hit"] += 1
        return row[1]

    def get_stale(self, key: str) -> tuple[Any, float] | None:
        """(value, age in seconds) for an answer past its lifetime but younger
        than `max_stale`: the fallback when a fresh lookup failed."""
        row = self._row(key)
        if row is None:
            return None
        age = time.time() - row[0]
        if age > self.max_stale:
            return None
        self.stats["stale"] += 1
        return row[1], age

    def set(self, key: str, value: Any) -> None:
        if not self._db:
            return
        blob = self._encode(value)
        try:
            with self._lock:
                self._db.execute("INSERT OR REPLACE INTO kv (k, t, v) VALUES (?, ?, ?)", (key, time.time(), blob))
                self._db.commit()
            self.stats["stored"] += 1
        except sqlite3.OperationalError as e:  # locked by another run beyond the timeout, disk full
            self.stats["write_skipped"] += 1
            log.debug("cache write skipped: %s", e)

    # ------------------------------------------------------------ upkeep
    def prune(self) -> int:
        """Delete entries too old even for the stale fallback."""
        if not self._db:
            return 0
        try:
            with self._lock:
                n = self._db.execute("DELETE FROM kv WHERE t < ?", (time.time() - self.max_stale,)).rowcount
                self._db.commit()
                if n:
                    self._db.execute("PRAGMA incremental_vacuum")
        except sqlite3.OperationalError as e:
            log.debug("cache prune skipped: %s", e)
            return 0
        self.stats["pruned"] += n
        return n

    def size_bytes(self) -> int:
        if not self.path:
            return 0
        return sum(p.stat().st_size for p in (self.path, Path(str(self.path) + "-wal")) if p.exists())

    def close(self) -> None:
        if self._db:
            try:
                self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.OperationalError:
                pass
            self._db.close()
            self._db = None
