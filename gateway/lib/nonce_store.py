"""Nonces the gateway has already accepted, so a signed request works once.

A request's ts must be within 300s of gateway time, so a nonce only needs remembering for about that long either
side. Both stores forget entries older than WINDOW seconds.

MemoryNonces lives in one process: a restart forgets it, and each worker has its own. SqliteNonces lives in a file
in the state dir, so a replay still fails after a restart and across workers on one host.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

WINDOW = 900  # the 300s ts window either side, plus margin


class MemoryNonces:
    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    def claim(self, nonce: str, now: int) -> bool:
        """True the first time a nonce is seen, False on a replay."""
        self._seen = {n: ts for n, ts in self._seen.items() if ts >= now - WINDOW}
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True


class SqliteNonces:
    def __init__(self, path: Path) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=5)
        self._db.execute("create table if not exists seen (nonce text primary key, ts integer not null)")

    def claim(self, nonce: str, now: int) -> bool:
        """True the first time a nonce is seen, False on a replay."""
        with self._lock:
            self._db.execute("delete from seen where ts < ?", (now - WINDOW,))
            try:
                self._db.execute("insert into seen (nonce, ts) values (?, ?)", (nonce, now))
            except sqlite3.IntegrityError:
                return False
            return True
