from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from gideon_common.redaction import redact_error
from gideon_infrastructure.sqlite_connections import SQLiteConnectionFactory, SQLiteConnectionOptions

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "SUPERADMIN": frozenset({"*"}),
    "ADMIN": frozenset({
        "dashboard.view", "agents.view", "agents.operate", "agents.purge",
        "jobs.view", "jobs.execute", "jobs.cancel", "jobs.download",
        "scripts.view", "scripts.manage", "releases.view", "releases.approve",
        "gateway.view", "audit.view", "users.view", "sessions.view", "sessions.manage",
        "transfers.view", "transfers.manage", "groups.view", "groups.manage",
        "diagnostics.view", "settings.view", "remote.view", "remote.control",
        "media.view", "media.manage", "screens.view", "screens.manage", "campaigns.approve",
    }),
    "OPERATOR": frozenset({
        "dashboard.view", "agents.view", "agents.operate", "jobs.view",
        "jobs.execute", "jobs.cancel", "jobs.download", "scripts.view",
        "gateway.view", "transfers.view", "transfers.manage", "groups.view",
        "diagnostics.view", "remote.view", "remote.control", "media.view", "media.manage", "screens.view", "screens.manage",
    }),
    "RELEASE_APPROVER": frozenset({
        "dashboard.view", "agents.view", "jobs.view", "releases.view",
        "releases.approve", "gateway.view", "audit.view", "groups.view",
        "diagnostics.view",
        "media.view",
    }),
    "AUDITOR": frozenset({
        "dashboard.view", "agents.view", "jobs.view", "jobs.download",
        "scripts.view", "releases.view", "gateway.view", "audit.view",
        "transfers.view", "groups.view", "diagnostics.view", "settings.view", "remote.view",
        "media.view", "screens.view",
    }),
    "MARKETING": frozenset({
        "dashboard.view", "media.view", "media.manage", "screens.view",
    }),
}


@dataclass(slots=True)
class SessionIdentity:
    session_id: int
    user_id: int
    username: str
    display_name: str
    role: str
    csrf_token: str
    mfa_complete: bool
    mfa_enabled: bool
    must_change_password: bool

    def can(self, permission: str) -> bool:
        grants = ROLE_PERMISSIONS.get(self.role, frozenset())
        return "*" in grants or permission in grants


class SecurityStore:
    def __init__(
        self,
        path: Path,
        *,
        idle_timeout_seconds: int = 43200,
        max_sessions_per_user: int = 5,
        session_touch_interval_seconds: int = 30,
    ) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
        self.idle_timeout_seconds = max(300, min(int(idle_timeout_seconds), 86400))
        self.max_sessions_per_user = max(1, min(int(max_sessions_per_user), 20))
        self.session_touch_interval_seconds = max(
            1,
            min(int(session_touch_interval_seconds), max(1, self.idle_timeout_seconds // 4)),
        )
        self._connections = SQLiteConnectionFactory(SQLiteConnectionOptions(
            path=self.path,
            timeout_seconds=10,
            pragmas=(
                "PRAGMA journal_mode=WAL",
                "PRAGMA foreign_keys=ON",
                "PRAGMA busy_timeout=10000",
            ),
        ))
        raw_key = str(os.environ.get("GIDEON_WEB_TOTP_ENCRYPTION_KEY") or "").strip().encode("ascii", "ignore")
        self._fernet = None
        if raw_key:
            try:
                self._fernet = Fernet(raw_key)
            except Exception as exc:
                raise RuntimeError("GIDEON_WEB_TOTP_ENCRYPTION_KEY inválida; debe ser una clave Fernet de 32 bytes codificada en base64 urlsafe.") from exc
        self.init_schema()

    def connect(self):
        """Return a managed SQLite transaction that always closes on exit."""
        return self._connections.connect()

    def init_schema(self) -> None:
        with self.connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    mfa_secret TEXT,
                    mfa_enabled INTEGER NOT NULL DEFAULT 0,
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_hash TEXT NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL,
                    csrf_token TEXT NOT NULL,
                    mfa_complete INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    expires_unix INTEGER NOT NULL,
                    last_seen_unix INTEGER NOT NULL,
                    remote_ip TEXT,
                    user_agent TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_unix);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    username TEXT,
                    role TEXT,
                    action TEXT NOT NULL,
                    resource TEXT,
                    result TEXT NOT NULL,
                    detail TEXT,
                    remote_ip TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
                CREATE TABLE IF NOT EXISTS script_assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    extension TEXT NOT NULL,
                    approval_state TEXT NOT NULL DEFAULT 'DRAFT',
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    approved_at TEXT,
                    approved_by TEXT,
                    approval_note TEXT,
                    scan_status TEXT NOT NULL DEFAULT 'NOT_SCANNED',
                    scan_detail TEXT,
                    scanned_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_scripts_created ON script_assets(created_at DESC);
                CREATE TABLE IF NOT EXISTS web_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    description TEXT,
                    agent_ids_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS web_sites (
                    site_code TEXT PRIMARY KEY COLLATE NOCASE,
                    site_name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_web_sites_name ON web_sites(site_name COLLATE NOCASE);
                CREATE TABLE IF NOT EXISTS recovery_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    expires_unix INTEGER NOT NULL,
                    used_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id, expires_unix);
                """
            )
            # Online schema migration for Web Admin databases created by previews.
            cols = {str(r[1]) for r in con.execute("PRAGMA table_info(script_assets)").fetchall()}
            for name, ddl in (
                ("scan_status", "TEXT NOT NULL DEFAULT 'NOT_SCANNED'"),
                ("scan_detail", "TEXT"),
                ("scanned_at", "TEXT"),
            ):
                if name not in cols:
                    con.execute(f"ALTER TABLE script_assets ADD COLUMN {name} {ddl}")

    def list_sessions(self, limit: int = 500) -> list[dict[str, Any]]:
        now = int(time.time())
        with self.connect() as con:
            con.execute("DELETE FROM sessions WHERE expires_unix<=?", (now,))
            rows = con.execute(
                """SELECT s.id,s.user_id,u.username,u.display_name,u.role,s.mfa_complete,s.created_at,
                          s.expires_unix,s.last_seen_unix,s.remote_ip,s.user_agent
                   FROM sessions s JOIN users u ON u.id=s.user_id
                   ORDER BY s.last_seen_unix DESC LIMIT ?""",
                (max(1, min(int(limit), 2000)),),
            ).fetchall()
        result=[]
        for r in rows:
            item=dict(r)
            try: item["last_seen_at"] = dt.datetime.fromtimestamp(int(item.get("last_seen_unix") or 0), tz=dt.timezone.utc).astimezone().isoformat(timespec="seconds")
            except Exception: item["last_seen_at"] = "-"
            try: item["expires_at"] = dt.datetime.fromtimestamp(int(item.get("expires_unix") or 0), tz=dt.timezone.utc).astimezone().isoformat(timespec="seconds")
            except Exception: item["expires_at"] = "-"
            result.append(item)
        return result

    def revoke_session(self, session_id: int, *, actor: str, remote_ip: str = "") -> None:
        with self.connect() as con:
            row = con.execute(
                "SELECT s.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?",
                (int(session_id),),
            ).fetchone()
            if row is None:
                raise KeyError("Sesión no encontrada.")
            con.execute("DELETE FROM sessions WHERE id=?", (int(session_id),))
        self.audit(actor, "sessions.revoke", "SUCCESS", f"Session={session_id}; User={row['username']}", remote_ip)

    def list_groups(self) -> list[dict[str, Any]]:
        import json
        with self.connect() as con:
            rows = con.execute("SELECT * FROM web_groups ORDER BY name COLLATE NOCASE").fetchall()
        result=[]
        for row in rows:
            item=dict(row)
            try: item["agent_ids"] = [str(x) for x in json.loads(str(item.get("agent_ids_json") or "[]"))]
            except Exception: item["agent_ids"] = []
            result.append(item)
        return result

    def create_group(self, name: str, description: str, agent_ids: list[str], *, actor: str, remote_ip: str = "") -> int:
        import json
        clean_name=str(name or "").strip()
        if not clean_name: raise ValueError("El nombre del grupo es obligatorio.")
        members=sorted({str(x).strip() for x in agent_ids if str(x).strip()})
        stamp=self.now_iso()
        with self.connect() as con:
            cur=con.execute(
                "INSERT INTO web_groups(name,description,agent_ids_json,created_at,created_by,updated_at) VALUES(?,?,?,?,?,?)",
                (clean_name,str(description or "").strip(),json.dumps(members,ensure_ascii=False),stamp,actor,stamp),
            )
            gid=int(cur.lastrowid)
        self.audit(actor,"groups.create","SUCCESS",f"Grupo={clean_name}; Members={len(members)}",remote_ip,resource=str(gid))
        return gid

    def delete_group(self, group_id: int, *, actor: str, remote_ip: str = "") -> None:
        with self.connect() as con:
            row=con.execute("SELECT name FROM web_groups WHERE id=?",(int(group_id),)).fetchone()
            if row is None: raise KeyError("Grupo no encontrado.")
            con.execute("DELETE FROM web_groups WHERE id=?",(int(group_id),))
        self.audit(actor,"groups.delete","SUCCESS",f"Grupo={row['name']}",remote_ip,resource=str(group_id))

    def list_sites(self) -> list[dict[str, Any]]:
        """Return sites explicitly managed by WebAdmin."""
        with self.connect() as con:
            rows = con.execute(
                "SELECT site_code,site_name,description,created_at,created_by,updated_at "
                "FROM web_sites ORDER BY site_code COLLATE NOCASE"
            ).fetchall()
        return [dict(row) for row in rows]

    def create_site(
        self, site_code: str, site_name: str, description: str = "", *,
        actor: str, remote_ip: str = "",
    ) -> str:
        code = str(site_code or "").strip().upper()
        name = str(site_name or "").strip()
        detail = str(description or "").strip()
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{0,31}", code):
            raise ValueError("El código debe tener 1 a 32 caracteres: letras, números, punto, guion o guion bajo.")
        if not name:
            raise ValueError("El nombre de la sede es obligatorio.")
        if len(name) > 120 or any(ord(ch) < 32 for ch in name):
            raise ValueError("El nombre de la sede no es válido o supera 120 caracteres.")
        if len(detail) > 500 or any(ord(ch) < 32 and ch not in "\r\n\t" for ch in detail):
            raise ValueError("La descripción no es válida o supera 500 caracteres.")
        stamp = self.now_iso()
        try:
            with self.connect() as con:
                con.execute(
                    "INSERT INTO web_sites(site_code,site_name,description,created_at,created_by,updated_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (code, name, detail, stamp, actor, stamp),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"La sede {code} ya existe en el catálogo.") from exc
        self.audit(actor, "sites.create", "SUCCESS", f"Sede={name}", remote_ip, resource=code)
        return code

    @staticmethod
    def now_iso() -> str:
        return dt.datetime.now().astimezone().isoformat(timespec="seconds")

    @staticmethod
    def _norm_user(username: str) -> str:
        return str(username or "").strip().lower()

    @staticmethod
    def validate_password(password: str) -> None:
        value = str(password or "")
        if len(value) < 12:
            raise ValueError("La contraseña debe tener al menos 12 caracteres.")
        checks = [
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        ]
        if sum(checks) < 3:
            raise ValueError("Use al menos 3 de 4: mayúsculas, minúsculas, números y símbolos.")

    def user_count(self) -> int:
        with self.connect() as con:
            row = con.execute("SELECT COUNT(*) FROM users").fetchone()
            return int(row[0] or 0)

    def bootstrap_admin(
        self, username: str, password: str, display_name: str = "Administrador GIDEON",
        *, must_change_password: bool = False, allow_temporary_password: bool = False,
    ) -> int:
        if self.user_count() > 0:
            raise RuntimeError("Ya existen usuarios. Use la administración Web para crear cuentas adicionales.")
        if allow_temporary_password:
            if len(str(password or "")) < 10:
                raise ValueError("La contraseña temporal debe tener al menos 10 caracteres.")
            must_change_password = True
        else:
            self.validate_password(password)
        stamp = self.now_iso()
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO users(username,display_name,password_hash,role,active,must_change_password,created_at,updated_at) VALUES(?,?,?,?,1,?,?,?)",
                (self._norm_user(username), str(display_name or username).strip(), self.ph.hash(password), "SUPERADMIN", 1 if must_change_password else 0, stamp, stamp),
            )
            user_id = int(cur.lastrowid)
        self.audit("bootstrap", "security/users", "SUCCESS", f"Primer SuperAdmin creado: {username}", "local", role="SYSTEM")
        return user_id

    def create_user(self, username: str, display_name: str, password: str, role: str, *, actor: str, remote_ip: str = "") -> int:
        role = str(role or "").upper()
        if role not in ROLE_PERMISSIONS:
            raise ValueError("Rol inválido.")
        self.validate_password(password)
        stamp = self.now_iso()
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO users(username,display_name,password_hash,role,active,must_change_password,created_at,updated_at) VALUES(?,?,?,?,1,1,?,?)",
                (self._norm_user(username), str(display_name or username).strip(), self.ph.hash(password), role, stamp, stamp),
            )
            user_id = int(cur.lastrowid)
        self.audit(actor, "users.create", "SUCCESS", f"Usuario={username}; Rol={role}", remote_ip)
        return user_id

    def list_users(self) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT id,username,display_name,role,active,mfa_enabled,must_change_password,created_at,updated_at,last_login_at,locked_until FROM users ORDER BY username"
            ).fetchall()
        return [dict(r) for r in rows]

    def set_user_active(self, user_id: int, active: bool, *, actor: str, remote_ip: str = "") -> None:
        with self.connect() as con:
            row = con.execute("SELECT username FROM users WHERE id=?", (int(user_id),)).fetchone()
            if row is None:
                raise KeyError("Usuario no encontrado.")
            con.execute("UPDATE users SET active=?,updated_at=? WHERE id=?", (1 if active else 0, self.now_iso(), int(user_id)))
            if not active:
                con.execute("DELETE FROM sessions WHERE user_id=?", (int(user_id),))
        self.audit(actor, "users.active", "SUCCESS", f"Usuario={row['username']}; Active={active}", remote_ip)

    def reset_password(self, user_id: int, password: str, *, actor: str, remote_ip: str = "") -> None:
        self.validate_password(password)
        with self.connect() as con:
            row = con.execute("SELECT username FROM users WHERE id=?", (int(user_id),)).fetchone()
            if row is None:
                raise KeyError("Usuario no encontrado.")
            con.execute(
                "UPDATE users SET password_hash=?,must_change_password=1,failed_attempts=0,locked_until=0,updated_at=? WHERE id=?",
                (self.ph.hash(password), self.now_iso(), int(user_id)),
            )
            con.execute("DELETE FROM sessions WHERE user_id=?", (int(user_id),))
        self.audit(actor, "users.password_reset", "SUCCESS", f"Usuario={row['username']}", remote_ip)

    def change_own_password(self, user_id: int, current: str, new: str, *, actor: str, remote_ip: str = "") -> None:
        self.validate_password(new)
        with self.connect() as con:
            row = con.execute("SELECT password_hash FROM users WHERE id=? AND active=1", (int(user_id),)).fetchone()
            if row is None:
                raise RuntimeError("Cuenta no disponible.")
            try:
                self.ph.verify(str(row["password_hash"]), current)
            except (VerifyMismatchError, InvalidHashError) as exc:
                raise ValueError("Contraseña actual incorrecta.") from exc
            con.execute(
                "UPDATE users SET password_hash=?,must_change_password=0,updated_at=? WHERE id=?",
                (self.ph.hash(new), self.now_iso(), int(user_id)),
            )
        self.audit(actor, "account.password_change", "SUCCESS", "Contraseña actualizada", remote_ip)

    def authenticate_password(self, username: str, password: str) -> dict[str, Any] | None:
        name = self._norm_user(username)
        now = int(time.time())
        with self.connect() as con:
            row = con.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
            if row is None or not int(row["active"] or 0):
                return None
            if int(row["locked_until"] or 0) > now:
                return {"locked": True, "locked_until": int(row["locked_until"]), "username": row["username"]}
            try:
                ok = self.ph.verify(str(row["password_hash"]), str(password or ""))
            except (VerifyMismatchError, InvalidHashError):
                ok = False
            if not ok:
                failed = int(row["failed_attempts"] or 0) + 1
                lock_until = now + 900 if failed >= 5 else 0
                con.execute(
                    "UPDATE users SET failed_attempts=?,locked_until=?,updated_at=? WHERE id=?",
                    (0 if lock_until else failed, lock_until, self.now_iso(), int(row["id"])),
                )
                return None
            if self.ph.check_needs_rehash(str(row["password_hash"])):
                con.execute("UPDATE users SET password_hash=?,updated_at=? WHERE id=?", (self.ph.hash(password), self.now_iso(), int(row["id"])))
            con.execute(
                "UPDATE users SET failed_attempts=0,locked_until=0,last_login_at=?,updated_at=? WHERE id=?",
                (self.now_iso(), self.now_iso(), int(row["id"])),
            )
            return dict(row)

    def reauthenticate(self, user_id: int, password: str, totp_code: str) -> None:
        """Strong re-authentication for sensitive Web Admin actions.

        This check never changes the account lock counter; the caller must already
        hold a valid authenticated session. Password + a fresh TOTP are required.
        """
        with self.connect() as con:
            row = con.execute(
                "SELECT id,username,password_hash,active,mfa_enabled,mfa_secret FROM users WHERE id=?",
                (int(user_id),),
            ).fetchone()
        if row is None or not int(row["active"] or 0):
            raise ValueError("Cuenta no disponible.")
        try:
            self.ph.verify(str(row["password_hash"]), str(password or ""))
        except (VerifyMismatchError, InvalidHashError) as exc:
            raise ValueError("Reautenticación fallida: contraseña actual incorrecta.") from exc
        if not int(row["mfa_enabled"] or 0):
            raise ValueError("La cuenta debe tener MFA habilitado para administrar secretos.")
        secret = self._unprotect_secret(str(row["mfa_secret"] or ""))
        if not secret or not self.verify_totp(secret, totp_code):
            raise ValueError("Reautenticación fallida: código MFA inválido.")

    def generate_recovery_code(self, user_id: int, *, ttl_seconds: int = 7 * 86400, actor: str, remote_ip: str = "") -> tuple[str, str]:
        """Create a single-use offline recovery code and store only its hash."""
        raw = "GIDEON-RCV-" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        now = int(time.time())
        expires = now + max(900, min(int(ttl_seconds), 30 * 86400))
        stamp = self.now_iso()
        with self.connect() as con:
            row = con.execute("SELECT username,active FROM users WHERE id=?", (int(user_id),)).fetchone()
            if row is None or not int(row["active"] or 0):
                raise ValueError("Cuenta no disponible.")
            con.execute("DELETE FROM recovery_codes WHERE user_id=? AND used_at IS NULL", (int(user_id),))
            con.execute(
                "INSERT INTO recovery_codes(user_id,token_hash,created_at,expires_unix,used_at) VALUES(?,?,?,?,NULL)",
                (int(user_id), digest, stamp, expires),
            )
        expires_at = dt.datetime.fromtimestamp(expires, tz=dt.timezone.utc).astimezone().isoformat(timespec="seconds")
        self.audit(actor, "account.recovery_code_create", "SUCCESS", f"Expira={expires_at}", remote_ip, role="SUPERADMIN")
        return raw, expires_at

    def recover_password_with_code(self, username: str, recovery_code: str, new_password: str, *, remote_ip: str = "") -> bool:
        """Consume a one-time recovery code and set a new password. MFA remains enabled."""
        self.validate_password(new_password)
        name = self._norm_user(username)
        token_hash = hashlib.sha256(str(recovery_code or "").strip().encode("utf-8")).hexdigest()
        now = int(time.time())
        with self.connect() as con:
            user = con.execute("SELECT id,username,active FROM users WHERE username=?", (name,)).fetchone()
            if user is None or not int(user["active"] or 0):
                return False
            code = con.execute(
                "SELECT id FROM recovery_codes WHERE user_id=? AND token_hash=? AND used_at IS NULL AND expires_unix>? ORDER BY id DESC LIMIT 1",
                (int(user["id"]), token_hash, now),
            ).fetchone()
            if code is None:
                return False
            stamp = self.now_iso()
            con.execute(
                "UPDATE users SET password_hash=?,must_change_password=0,failed_attempts=0,locked_until=0,updated_at=? WHERE id=?",
                (self.ph.hash(new_password), stamp, int(user["id"])),
            )
            con.execute("UPDATE recovery_codes SET used_at=? WHERE id=?", (stamp, int(code["id"])))
            con.execute("DELETE FROM sessions WHERE user_id=?", (int(user["id"]),))
        self.audit(name, "account.recovery_password", "SUCCESS", "Código de recuperación consumido", remote_ip, role="RECOVERY")
        return True

    def create_session(self, user_id: int, *, remote_ip: str, user_agent: str, ttl_seconds: int = 43200, mfa_complete: bool = False) -> tuple[str, str]:
        raw = secrets.token_urlsafe(48)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        csrf = secrets.token_urlsafe(32)
        now = int(time.time())
        expires = now + max(900, min(int(ttl_seconds), 86400))
        with self.connect() as con:
            con.execute("DELETE FROM sessions WHERE expires_unix<?", (now,))
            con.execute(
                "INSERT INTO sessions(token_hash,user_id,csrf_token,mfa_complete,created_at,expires_unix,last_seen_unix,remote_ip,user_agent) VALUES(?,?,?,?,?,?,?,?,?)",
                (digest, int(user_id), csrf, 1 if mfa_complete else 0, self.now_iso(), expires, now, remote_ip, user_agent[:512]),
            )
            rows = con.execute(
                "SELECT id FROM sessions WHERE user_id=? ORDER BY last_seen_unix DESC, id DESC",
                (int(user_id),),
            ).fetchall()
            for old in rows[self.max_sessions_per_user:]:
                con.execute("DELETE FROM sessions WHERE id=?", (int(old[0]),))
        return raw, csrf

    def identity_for_session(self, raw_token: str) -> SessionIdentity | None:
        if not raw_token:
            return None
        digest = hashlib.sha256(raw_token.encode()).hexdigest()
        now = int(time.time())
        with self.connect() as con:
            row = con.execute(
                """SELECT s.id session_id,s.user_id,s.csrf_token,s.mfa_complete,s.expires_unix,s.last_seen_unix,
                          u.username,u.display_name,u.role,u.active,u.mfa_enabled,u.must_change_password
                   FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?""",
                (digest,),
            ).fetchone()
            if (
                row is None or not int(row["active"] or 0) or int(row["expires_unix"] or 0) <= now
                or int(row["last_seen_unix"] or 0) + self.idle_timeout_seconds <= now
            ):
                con.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
                return None
            # Polling pages and static navigation may validate the same session
            # several times per second. Touching SQLite on every read bloats WAL
            # traffic and serializes otherwise independent requests. A bounded
            # touch interval preserves idle-timeout semantics with far fewer writes.
            if now - int(row["last_seen_unix"] or 0) >= self.session_touch_interval_seconds:
                con.execute(
                    "UPDATE sessions SET last_seen_unix=? WHERE id=? AND last_seen_unix<=?",
                    (now, int(row["session_id"]), now - self.session_touch_interval_seconds),
                )
        return SessionIdentity(
            session_id=int(row["session_id"]), user_id=int(row["user_id"]), username=str(row["username"]),
            display_name=str(row["display_name"]), role=str(row["role"]), csrf_token=str(row["csrf_token"]),
            mfa_complete=bool(row["mfa_complete"]), mfa_enabled=bool(row["mfa_enabled"]),
            must_change_password=bool(row["must_change_password"]),
        )

    def complete_mfa(self, session_id: int) -> None:
        with self.connect() as con:
            con.execute("UPDATE sessions SET mfa_complete=1 WHERE id=?", (int(session_id),))

    def rotate_session(self, raw_token: str, *, mfa_complete: bool | None = None) -> tuple[str, str] | None:
        """Rotate the bearer token and CSRF token without extending absolute expiry.

        Rotation is intentionally server-side: the old raw token stops working as soon
        as this method succeeds.  The original ``expires_unix`` is preserved so MFA,
        password changes or other privilege transitions never turn into a sliding
        all-day session.
        """
        if not raw_token:
            return None
        digest = hashlib.sha256(raw_token.encode()).hexdigest()
        now = int(time.time())
        new_raw = secrets.token_urlsafe(48)
        new_digest = hashlib.sha256(new_raw.encode()).hexdigest()
        new_csrf = secrets.token_urlsafe(32)
        with self.connect() as con:
            row = con.execute(
                "SELECT id,expires_unix,last_seen_unix,mfa_complete FROM sessions WHERE token_hash=?",
                (digest,),
            ).fetchone()
            if (
                row is None
                or int(row["expires_unix"] or 0) <= now
                or int(row["last_seen_unix"] or 0) + self.idle_timeout_seconds <= now
            ):
                con.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
                return None
            mfa_value = int(row["mfa_complete"] or 0) if mfa_complete is None else (1 if mfa_complete else 0)
            con.execute(
                "UPDATE sessions SET token_hash=?,csrf_token=?,mfa_complete=?,last_seen_unix=? WHERE id=?",
                (new_digest, new_csrf, mfa_value, now, int(row["id"])),
            )
        return new_raw, new_csrf

    def step_up_authenticate(
        self, user_id: int, password: str, totp_code: str, *, actor: str,
        remote_ip: str = "", resource: str = "sensitive-operation", role: str = "SUPERADMIN",
    ) -> None:
        """Password + fresh TOTP verification for explicitly sensitive actions.

        Normal authenticated work must not call this method.  It exists for PKI,
        security assets, product updates, credential resets and equivalent high-risk
        administration.
        """
        try:
            self.reauthenticate(user_id, password, totp_code)
        except Exception as exc:
            self.audit(actor, "auth.step_up", "FAILED", f"Resource={resource}; {exc}", remote_ip, resource=resource, role=role)
            raise
        self.audit(actor, "auth.step_up", "SUCCESS", f"Resource={resource}", remote_ip, resource=resource, role=role)

    def logout(self, raw_token: str) -> None:
        if not raw_token:
            return
        digest = hashlib.sha256(raw_token.encode()).hexdigest()
        with self.connect() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))

    def _protect_secret(self, value: str) -> str:
        clean = str(value or "")
        if not clean or self._fernet is None:
            return clean
        return "enc:v1:" + self._fernet.encrypt(clean.encode("utf-8")).decode("ascii")

    def _unprotect_secret(self, value: str) -> str:
        clean = str(value or "")
        if not clean.startswith("enc:v1:"):
            return clean
        if self._fernet is None:
            raise RuntimeError("Existe un secreto MFA cifrado pero GIDEON_WEB_TOTP_ENCRYPTION_KEY no está configurada.")
        try:
            return self._fernet.decrypt(clean[7:].encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("No se pudo descifrar el secreto MFA.") from exc

    @staticmethod
    def generate_totp_secret() -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

    @staticmethod
    def _totp(secret: str, for_time: int | None = None, period: int = 30, digits: int = 6) -> str:
        when = int(time.time() if for_time is None else for_time)
        counter = when // period
        padded = str(secret or "").upper() + "=" * ((8 - len(str(secret or "")) % 8) % 8)
        key = base64.b32decode(padded, casefold=True)
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
        return f"{value:0{digits}d}"

    @classmethod
    def verify_totp(cls, secret: str, code: str) -> bool:
        clean = "".join(ch for ch in str(code or "") if ch.isdigit())
        if len(clean) != 6:
            return False
        now = int(time.time())
        return any(hmac.compare_digest(cls._totp(secret, now + (step * 30)), clean) for step in (-1, 0, 1))

    def get_mfa_secret(self, user_id: int) -> str:
        with self.connect() as con:
            row = con.execute("SELECT mfa_secret FROM users WHERE id=?", (int(user_id),)).fetchone()
            return self._unprotect_secret(str(row[0] or "")) if row else ""

    def begin_mfa_setup(self, user_id: int) -> str:
        secret = self.generate_totp_secret()
        stored = self._protect_secret(secret)
        with self.connect() as con:
            con.execute("UPDATE users SET mfa_secret=?,mfa_enabled=0,updated_at=? WHERE id=?", (stored, self.now_iso(), int(user_id)))
        return secret

    def enable_mfa(self, user_id: int, code: str) -> bool:
        secret = self.get_mfa_secret(user_id)
        if not secret or not self.verify_totp(secret, code):
            return False
        with self.connect() as con:
            con.execute("UPDATE users SET mfa_enabled=1,updated_at=? WHERE id=?", (self.now_iso(), int(user_id)))
        return True

    def disable_mfa(self, user_id: int, *, actor: str, remote_ip: str = "") -> None:
        with self.connect() as con:
            row = con.execute("SELECT username FROM users WHERE id=?", (int(user_id),)).fetchone()
            if row is None:
                raise KeyError("Usuario no encontrado")
            con.execute("UPDATE users SET mfa_enabled=0,mfa_secret=NULL,updated_at=? WHERE id=?", (self.now_iso(), int(user_id)))
            con.execute("DELETE FROM sessions WHERE user_id=?", (int(user_id),))
        self.audit(actor, "users.mfa_disable", "SUCCESS", f"Usuario={row['username']}", remote_ip)

    @staticmethod
    def otpauth_uri(secret: str, username: str, issuer: str = "Gideon Rx") -> str:
        label = quote(f"{issuer}:{username}")
        return f"otpauth://totp/{label}?secret={quote(secret)}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"

    def audit(self, username: str, action: str, result: str, detail: str = "", remote_ip: str = "", *, resource: str = "", role: str = "") -> None:
        with self.connect() as con:
            con.execute(
                "INSERT INTO audit_log(created_at,username,role,action,resource,result,detail,remote_ip) VALUES(?,?,?,?,?,?,?,?)",
                (self.now_iso(), username, role, action, resource, result, redact_error(detail, max_chars=4000), remote_ip),
            )

    def list_audit(self, limit: int = 250) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 2000)),)).fetchall()
        return [dict(r) for r in rows]

    def add_script(self, *, name: str, stored_path: str, sha256: str, size_bytes: int, extension: str, actor: str) -> int:
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO script_assets(name,stored_path,sha256,size_bytes,extension,approval_state,created_at,created_by) VALUES(?,?,?,?,?,'DRAFT',?,?)",
                (name, stored_path, sha256, int(size_bytes), extension.lower(), self.now_iso(), actor),
            )
            return int(cur.lastrowid)

    def list_scripts(self) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM script_assets ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def get_script(self, script_id: int) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM script_assets WHERE id=?", (int(script_id),)).fetchone()
        return dict(row) if row else None

    def set_script_scan(self, script_id: int, status: str, detail: str = "") -> None:
        with self.connect() as con:
            con.execute(
                "UPDATE script_assets SET scan_status=?,scan_detail=?,scanned_at=? WHERE id=?",
                (str(status).upper(), redact_error(detail, max_chars=4000), self.now_iso(), int(script_id)),
            )

    def approve_script(self, script_id: int, approved: bool, *, actor: str, note: str = "") -> None:
        state = "APPROVED" if approved else "REVOKED"
        with self.connect() as con:
            row = con.execute("SELECT id FROM script_assets WHERE id=?", (int(script_id),)).fetchone()
            if row is None:
                raise KeyError("Script no encontrado")
            con.execute(
                "UPDATE script_assets SET approval_state=?,approved_at=?,approved_by=?,approval_note=? WHERE id=?",
                (state, self.now_iso() if approved else None, actor if approved else None, note[:1000], int(script_id)),
            )
