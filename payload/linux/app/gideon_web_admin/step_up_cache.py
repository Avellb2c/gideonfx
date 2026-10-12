from __future__ import annotations

"""Durable step-up authorization stores for GIDEON WebAdmin.

Two deliberately separate 15-minute grants are maintained:

* ``step_up_windows`` - sensitive WebAdmin operations (password + MFA policy).
* ``remote_step_up_windows`` - remote-control MFA-only reuse for interactive
  RDP/VNC sessions.

The remote-control grant is keyed by an opaque browser-scoped identifier that
is combined server-side with the authenticated user and user-agent.
It is therefore reusable across different remote targets and popup windows,
while remaining independent from WebAdmin session-row rotation and harmless
client-IP changes during the short authorization window.

No TOTP value, password, RDP credential, cookie or remote ticket is persisted.
"""

import hashlib
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

STORE_VERSION = "RC30.95.31.10"
DEFAULT_TTL_SECONDS = 900
_DB_FILENAME = "security-step-up.sqlite3"
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")


def _fallback_db_path() -> Path:
    explicit = str(os.environ.get("GIDEON_WEB_STEPUP_DB") or "").strip()
    if explicit:
        return Path(os.path.expandvars(explicit)).expanduser().resolve()
    if os.name == "nt":
        program_data = str(os.environ.get("PROGRAMDATA") or r"C:\ProgramData")
        return (Path(program_data) / "GIDEON Remote Control" / "web" / _DB_FILENAME).resolve()
    # This is the canonical persistent WebAdmin state directory declared in the
    # hardened systemd unit's ReadWritePaths.  A sibling /var/lib path is not
    # writable when ProtectSystem=strict and made MFA reuse impossible on an
    # otherwise healthy fresh Ubuntu deployment.
    return Path("/var/lib/gideon/web") / _DB_FILENAME


def normalize_remote_client_id(value: str | None) -> str:
    """Return a validated browser-scoped id or an empty string.

    This identifier is metadata, not an authentication secret.  A strict
    character/length policy prevents it from becoming an arbitrary database key.
    """
    raw = str(value or "").strip()
    return raw if _CLIENT_ID_RE.fullmatch(raw) else ""


def build_remote_scope_key(*, user_id: int, client_id: str, remote_ip: str, user_agent: str) -> str:
    """Derive one stable remote-MFA scope key for this browser/client context.

    The authenticated session cookie is still required on every request.  IP is
    intentionally excluded because short IPv4/IPv6 or proxy egress changes were
    invalidating an otherwise valid 15-minute MFA authorization.  ``remote_ip``
    remains in the signature for backwards-compatible callers and audit data.
    """
    uid = int(user_id or 0)
    cid = normalize_remote_client_id(client_id)
    if uid <= 0 or not cid:
        return ""
    _ = remote_ip
    ua = " ".join(str(user_agent or "").strip().split())[:512]
    material = f"gideon-remote-stepup-v2\0{uid}\0{cid}\0{ua}".encode("utf-8", "strict")
    return hashlib.sha256(material).hexdigest()


class PersistentStepUpCache:
    backend_name = "sqlite"
    store_version = STORE_VERSION

    def __init__(self, db_path: str | os.PathLike[str] | None = None) -> None:
        self._lock = threading.RLock()
        self._db_path = Path(db_path).expanduser().resolve() if db_path else _fallback_db_path()

    @property
    def db_path(self) -> Path:
        with self._lock:
            return Path(self._db_path)

    def configure(self, db_path: str | os.PathLike[str]) -> None:
        path = Path(db_path).expanduser().resolve()
        with self._lock:
            self._db_path = path

    def _connect(self) -> sqlite3.Connection:
        path = self.db_path
        path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(str(path), timeout=3.0, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=3000")
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.DatabaseError:
            pass
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS step_up_windows (
                session_id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                verified_unix INTEGER NOT NULL,
                until_unix INTEGER NOT NULL
            )
            """
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_step_up_user_until "
            "ON step_up_windows(user_id, until_unix)"
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS remote_step_up_windows (
                scope_key TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                issued_session_id INTEGER NOT NULL,
                verified_unix INTEGER NOT NULL,
                until_unix INTEGER NOT NULL
            )
            """
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_remote_step_up_user_until "
            "ON remote_step_up_windows(user_id, until_unix)"
        )
        return con

    @contextmanager
    def _connection(self):
        con = self._connect()
        try:
            yield con
        finally:
            try:
                con.close()
            except Exception:
                pass

    @staticmethod
    def _inactive(ttl_seconds: int) -> dict[str, int | bool]:
        ttl = max(1, int(ttl_seconds or DEFAULT_TTL_SECONDS))
        return {
            "active": False,
            "verified_unix": 0,
            "until_unix": 0,
            "remaining_seconds": 0,
            "ttl_seconds": ttl,
        }

    def purge(self, *, now_unix: int | None = None) -> int:
        now = int(time.time() if now_unix is None else now_unix)
        deleted = 0
        with self._connection() as con:
            cur = con.execute("DELETE FROM step_up_windows WHERE until_unix<=?", (now,))
            deleted += max(0, int(cur.rowcount if cur.rowcount is not None else 0))
            cur = con.execute("DELETE FROM remote_step_up_windows WHERE until_unix<=?", (now,))
            deleted += max(0, int(cur.rowcount if cur.rowcount is not None else 0))
        return deleted

    # ------------------------------------------------------------------
    # Sensitive-operation step-up (legacy/session-bound API preserved)
    # ------------------------------------------------------------------
    def status(
        self,
        *,
        session_id: int,
        user_id: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now_unix: int | None = None,
    ) -> dict[str, int | bool]:
        ttl = max(1, int(ttl_seconds or DEFAULT_TTL_SECONDS))
        sid = int(session_id or 0)
        uid = int(user_id or 0)
        if sid <= 0 or uid <= 0:
            return self._inactive(ttl)
        now = int(time.time() if now_unix is None else now_unix)
        with self._connection() as con:
            con.execute("DELETE FROM step_up_windows WHERE until_unix<=?", (now,))
            row = con.execute(
                "SELECT verified_unix, until_unix FROM step_up_windows WHERE session_id=? AND user_id=?",
                (sid, uid),
            ).fetchone()
        if row is None:
            return self._inactive(ttl)
        verified = int(row["verified_unix"] or 0)
        until = int(row["until_unix"] or 0)
        remaining = max(0, until - now)
        if remaining <= 0:
            return self._inactive(ttl)
        return {
            "active": True,
            "verified_unix": verified,
            "until_unix": until,
            "remaining_seconds": remaining,
            "ttl_seconds": ttl,
        }

    def mark(
        self,
        *,
        session_id: int,
        user_id: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now_unix: int | None = None,
    ) -> dict[str, int | bool]:
        ttl = max(1, int(ttl_seconds or DEFAULT_TTL_SECONDS))
        sid = int(session_id or 0)
        uid = int(user_id or 0)
        if sid <= 0 or uid <= 0:
            raise ValueError("STEP_UP_STORE_INVALID_SESSION")
        now = int(time.time() if now_unix is None else now_unix)
        until = now + ttl
        with self._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute("DELETE FROM step_up_windows WHERE until_unix<=?", (now,))
                con.execute(
                    """
                    INSERT INTO step_up_windows(session_id,user_id,verified_unix,until_unix)
                    VALUES(?,?,?,?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        user_id=excluded.user_id,
                        verified_unix=excluded.verified_unix,
                        until_unix=excluded.until_unix
                    """,
                    (sid, uid, now, until),
                )
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise
        return {
            "active": True,
            "verified_unix": now,
            "until_unix": until,
            "remaining_seconds": ttl,
            "ttl_seconds": ttl,
        }

    # ------------------------------------------------------------------
    # Remote-control MFA-only grant (browser-scope, target-independent)
    # ------------------------------------------------------------------
    def remote_status(
        self,
        *,
        scope_key: str,
        user_id: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now_unix: int | None = None,
    ) -> dict[str, int | bool]:
        ttl = max(1, int(ttl_seconds or DEFAULT_TTL_SECONDS))
        key = str(scope_key or "").strip().lower()
        uid = int(user_id or 0)
        if len(key) != 64 or uid <= 0:
            return self._inactive(ttl)
        now = int(time.time() if now_unix is None else now_unix)
        with self._connection() as con:
            con.execute("DELETE FROM remote_step_up_windows WHERE until_unix<=?", (now,))
            row = con.execute(
                "SELECT verified_unix, until_unix FROM remote_step_up_windows WHERE scope_key=? AND user_id=?",
                (key, uid),
            ).fetchone()
        if row is None:
            return self._inactive(ttl)
        verified = int(row["verified_unix"] or 0)
        until = int(row["until_unix"] or 0)
        remaining = max(0, until - now)
        if remaining <= 0:
            return self._inactive(ttl)
        return {
            "active": True,
            "verified_unix": verified,
            "until_unix": until,
            "remaining_seconds": remaining,
            "ttl_seconds": ttl,
        }

    def remote_mark(
        self,
        *,
        scope_key: str,
        user_id: int,
        issued_session_id: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now_unix: int | None = None,
    ) -> dict[str, int | bool]:
        ttl = max(1, int(ttl_seconds or DEFAULT_TTL_SECONDS))
        key = str(scope_key or "").strip().lower()
        uid = int(user_id or 0)
        sid = int(issued_session_id or 0)
        if len(key) != 64 or uid <= 0 or sid <= 0:
            raise ValueError("REMOTE_STEP_UP_SCOPE_INVALID")
        now = int(time.time() if now_unix is None else now_unix)
        until = now + ttl
        with self._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute("DELETE FROM remote_step_up_windows WHERE until_unix<=?", (now,))
                con.execute(
                    """
                    INSERT INTO remote_step_up_windows(scope_key,user_id,issued_session_id,verified_unix,until_unix)
                    VALUES(?,?,?,?,?)
                    ON CONFLICT(scope_key) DO UPDATE SET
                        user_id=excluded.user_id,
                        issued_session_id=excluded.issued_session_id,
                        verified_unix=excluded.verified_unix,
                        until_unix=excluded.until_unix
                    """,
                    (key, uid, sid, now, until),
                )
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise
        return {
            "active": True,
            "verified_unix": now,
            "until_unix": until,
            "remaining_seconds": ttl,
            "ttl_seconds": ttl,
        }

    def remote_clear_scope(self, *, scope_key: str, user_id: int) -> None:
        key = str(scope_key or "").strip().lower()
        uid = int(user_id or 0)
        if len(key) != 64 or uid <= 0:
            return
        with self._connection() as con:
            con.execute("DELETE FROM remote_step_up_windows WHERE scope_key=? AND user_id=?", (key, uid))

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def clear(self, *, session_id: int, user_id: int | None = None) -> None:
        sid = int(session_id or 0)
        if sid <= 0:
            return
        with self._connection() as con:
            if user_id is None:
                con.execute("DELETE FROM step_up_windows WHERE session_id=?", (sid,))
            else:
                con.execute("DELETE FROM step_up_windows WHERE session_id=? AND user_id=?", (sid, int(user_id or 0)))

    def clear_session(self, session_id: int) -> None:
        self.clear(session_id=session_id)

    def clear_user(self, user_id: int) -> None:
        uid = int(user_id or 0)
        if uid <= 0:
            return
        with self._connection() as con:
            con.execute("DELETE FROM step_up_windows WHERE user_id=?", (uid,))
            con.execute("DELETE FROM remote_step_up_windows WHERE user_id=?", (uid,))

    def diagnostics(self) -> dict[str, Any]:
        path = self.db_path
        return {
            "backend": self.backend_name,
            "store_version": self.store_version,
            "configured": True,
            "db_filename": path.name,
            "remote_scope": "user+browser_client+user_agent",
        }


STEP_UP_CACHE = PersistentStepUpCache()
