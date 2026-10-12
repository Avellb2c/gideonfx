from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Iterator, Sequence


@dataclass(frozen=True, slots=True)
class SQLiteConnectionOptions:
    """Infrastructure-only options for short-lived SQLite connections."""

    path: Path
    timeout_seconds: float = 10.0
    isolation_level: str | None = "DEFERRED"
    uri: bool = False
    pragmas: Sequence[str] = ()


class SQLiteConnectionFactory:
    """Owns creation *and* disposal of SQLite connections.

    Python's ``sqlite3.Connection`` context manager commits/rolls back but does
    not close the connection.  This factory deliberately exposes only a managed
    context so callers cannot accidentally leak file descriptors while keeping
    transaction behavior identical to ``with connection``.
    """

    def __init__(self, options: SQLiteConnectionOptions) -> None:
        self._options = options
        # journal_mode is persistent database state, not a connection setting.
        # Reissuing it for every short-lived request connection takes schema
        # locks and creates needless contention with Agent heartbeats and UI
        # session checks. Apply it once per factory; connection-local pragmas
        # (foreign_keys, synchronous, busy_timeout, etc.) still run every time.
        self._persistent_pragmas = tuple(
            statement for statement in options.pragmas
            if statement.strip().lower().startswith("pragma journal_mode")
        )
        self._connection_pragmas = tuple(
            statement for statement in options.pragmas
            if statement not in self._persistent_pragmas
        )
        self._persistent_ready = not self._persistent_pragmas
        self._persistent_lock = Lock()

    @property
    def path(self) -> Path:
        return self._options.path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        options = self._options
        con = sqlite3.connect(
            options.path,
            timeout=float(options.timeout_seconds),
            isolation_level=options.isolation_level,
            uri=bool(options.uri),
        )
        con.row_factory = sqlite3.Row
        try:
            if not self._persistent_ready:
                with self._persistent_lock:
                    if not self._persistent_ready:
                        for statement in self._persistent_pragmas:
                            con.execute(statement)
                        self._persistent_ready = True
            for statement in self._connection_pragmas:
                con.execute(statement)
            try:
                yield con
            except BaseException:
                con.rollback()
                raise
            else:
                con.commit()
        finally:
            con.close()
