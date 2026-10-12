from __future__ import annotations

"""Remote-session tickets, target resolution and concurrency controls.

A remote-session ticket is intentionally one-time and short lived.  The ticket
is stored only as SHA-256 and is bound to the authenticated WebAdmin user and
one concrete target/protocol/credential tuple.  WebSocket reconnect requires a
new ticket.
"""

import datetime as dt
import hashlib
import ipaddress
import json
import secrets
import socket
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from gideon_infrastructure.sqlite_connections import SQLiteConnectionFactory, SQLiteConnectionOptions


class RemoteSessionError(RuntimeError):
    pass


def _now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _ticket_hash(raw: str) -> str:
    return hashlib.sha256(str(raw or "").encode("utf-8")).hexdigest()


DEFAULT_ALLOWED_TARGET_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)

MAX_CREDENTIAL_ROUNDS = 3
MAX_SECURITY_ATTEMPTS = 4
MAX_INTERACTIVE_ATTEMPTS = MAX_CREDENTIAL_ROUNDS * MAX_SECURITY_ATTEMPTS
MAX_HANDOFF_RECONNECTS = 1


def _normalize_rdp_security_plan(value: Any, current: str = "") -> tuple[str, ...]:
    raw = value if isinstance(value, (list, tuple)) else str(value or "").replace(";", ",").split(",")
    modes: list[str] = []
    for item in raw:
        mode = str(item or "").strip().lower()
        if mode in {"any", "nla", "tls", "rdp"} and mode not in modes:
            modes.append(mode)
    effective = str(current or "").strip().lower()
    if effective in {"any", "nla", "tls", "rdp"} and effective not in modes:
        modes.insert(0, effective)
    return tuple(modes[:MAX_SECURITY_ATTEMPTS])


def _config_bool(value: Any, default: bool) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    return bool(default)


def _allowed_cidrs(value: Any) -> tuple[str, ...]:
    if value in (None, "", [], (), {}):
        candidates: Iterable[Any] = DEFAULT_ALLOWED_TARGET_CIDRS
    elif isinstance(value, str):
        candidates = [x.strip() for x in value.replace(";", ",").split(",")]
    elif isinstance(value, (list, tuple, set)):
        candidates = value
    else:
        raise RemoteSessionError("remote_sessions.allowed_target_cidrs debe ser lista o texto separado por comas.")

    normalized: list[str] = []
    for item in candidates:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise RemoteSessionError(f"CIDR remoto inválido: {text}") from exc
        canonical = str(network)
        if canonical not in normalized:
            normalized.append(canonical)
    return tuple(normalized) or DEFAULT_ALLOWED_TARGET_CIDRS


@dataclass(frozen=True, slots=True)
class RemoteSessionPolicy:
    enabled: bool = True
    ticket_ttl_seconds: int = 60
    max_session_seconds: int = 14400
    max_active_sessions: int = 10
    max_sessions_per_user: int = 3
    max_sessions_per_target: int = 1
    connect_timeout_seconds: float = 3.0
    bind_ticket_to_ip: bool = True
    clipboard_enabled: bool = True
    file_transfer_enabled: bool = True
    max_clipboard_bytes: int = 1024 * 1024
    max_file_transfer_bytes: int = 100 * 1024 * 1024
    allowed_target_cidrs: tuple[str, ...] = DEFAULT_ALLOWED_TARGET_CIDRS

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "RemoteSessionPolicy":
        raw_value = config.get("remote_sessions") if isinstance(config, dict) else None
        if raw_value in (None, ""):
            raw: dict[str, Any] = {}
        elif isinstance(raw_value, dict):
            raw = dict(raw_value)
        else:
            raise RemoteSessionError("remote_sessions debe ser un objeto de configuración.")
        # Do not read dataclass defaults from ``cls.<slot>``.  With slots=True
        # those attributes are member_descriptor objects, which caused RC29 to
        # crash at startup when an older web_admin.json omitted allowed_target_cidrs.
        allowed = _allowed_cidrs(raw.get("allowed_target_cidrs"))
        return cls(
            enabled=_config_bool(raw.get("enabled"), True),
            ticket_ttl_seconds=max(15, min(int(raw.get("ticket_ttl_seconds", 60)), 300)),
            max_session_seconds=max(300, min(int(raw.get("max_session_seconds", 14400)), 43200)),
            max_active_sessions=max(1, min(int(raw.get("max_active_sessions", 10)), 100)),
            max_sessions_per_user=max(1, min(int(raw.get("max_sessions_per_user", 3)), 20)),
            max_sessions_per_target=max(1, min(int(raw.get("max_sessions_per_target", 1)), 5)),
            connect_timeout_seconds=max(0.5, min(float(raw.get("connect_timeout_seconds", 3.0)), 15.0)),
            bind_ticket_to_ip=_config_bool(raw.get("bind_ticket_to_ip"), True),
            clipboard_enabled=_config_bool(raw.get("clipboard_enabled"), True),
            file_transfer_enabled=_config_bool(raw.get("file_transfer_enabled"), True),
            max_clipboard_bytes=max(4096, min(int(raw.get("max_clipboard_bytes", 1024 * 1024)), 8 * 1024 * 1024)),
            max_file_transfer_bytes=max(1024 * 1024, min(int(raw.get("max_file_transfer_bytes", 100 * 1024 * 1024)), 1024 * 1024 * 1024)),
            allowed_target_cidrs=allowed,
        )


class RemoteSessionStore:
    def __init__(self, data_dir: Path, policy: RemoteSessionPolicy) -> None:
        self.policy = policy
        path = Path(data_dir).resolve() / "remote-sessions.sqlite3"
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connections = SQLiteConnectionFactory(SQLiteConnectionOptions(
            path=path,
            timeout_seconds=10,
            isolation_level=None,
            pragmas=(
                "PRAGMA journal_mode=WAL",
                "PRAGMA foreign_keys=ON",
                "PRAGMA busy_timeout=10000",
            ),
        ))
        self.init_schema()

    def connect(self):
        return self._connections.connect()

    def init_schema(self) -> None:
        with self.connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS remote_sessions (
                    session_id TEXT PRIMARY KEY,
                    ticket_hash TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    web_session_id INTEGER NOT NULL DEFAULT 0,
                    username TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_label TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    target_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    client_ip TEXT,
                    created_at TEXT NOT NULL,
                    created_unix INTEGER NOT NULL,
                    expires_unix INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    activated_at TEXT,
                    activated_unix INTEGER,
                    ended_at TEXT,
                    ended_unix INTEGER,
                    end_reason TEXT,
                    credential_mode TEXT NOT NULL DEFAULT 'VAULT',
                    route_mode TEXT NOT NULL DEFAULT 'DIRECT',
                    retry_root_session_id TEXT NOT NULL DEFAULT '',
                    retry_attempt INTEGER NOT NULL DEFAULT 1,
                    max_attempts INTEGER NOT NULL DEFAULT 1,
                    credential_round INTEGER NOT NULL DEFAULT 1,
                    security_attempt INTEGER NOT NULL DEFAULT 1,
                    max_credential_rounds INTEGER NOT NULL DEFAULT 1,
                    max_security_attempts INTEGER NOT NULL DEFAULT 1,
                    clipboard_enabled INTEGER NOT NULL DEFAULT 1,
                    file_transfer_enabled INTEGER NOT NULL DEFAULT 1,
                    rdp_security TEXT NOT NULL DEFAULT '',
                    rdp_security_plan TEXT NOT NULL DEFAULT '',
                    rdp_session_mode TEXT NOT NULL DEFAULT 'STANDARD',
                    handoff_reconnect_attempt INTEGER NOT NULL DEFAULT 0,
                    max_handoff_reconnects INTEGER NOT NULL DEFAULT 0,
                    connection_intent TEXT NOT NULL DEFAULT 'STANDARD_ACCESS',
                    local_session_impact TEXT NOT NULL DEFAULT '',
                    operator_acknowledged INTEGER NOT NULL DEFAULT 0,
                    operator_ack_unix INTEGER NOT NULL DEFAULT 0,
                    consent_state TEXT NOT NULL DEFAULT 'NOT_APPLICABLE'
                );
                CREATE INDEX IF NOT EXISTS idx_remote_sessions_status ON remote_sessions(status, activated_unix);
                CREATE INDEX IF NOT EXISTS idx_remote_sessions_user ON remote_sessions(user_id, status);
                CREATE INDEX IF NOT EXISTS idx_remote_sessions_target ON remote_sessions(target_host, target_port, status);
                """
            )
            columns = {str(row[1]) for row in con.execute("PRAGMA table_info(remote_sessions)").fetchall()}
            if "web_session_id" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN web_session_id INTEGER NOT NULL DEFAULT 0")
            if "credential_mode" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN credential_mode TEXT NOT NULL DEFAULT 'VAULT'")
            if "route_mode" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN route_mode TEXT NOT NULL DEFAULT 'DIRECT'")
            if "retry_root_session_id" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN retry_root_session_id TEXT NOT NULL DEFAULT ''")
            if "retry_attempt" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN retry_attempt INTEGER NOT NULL DEFAULT 1")
            if "max_attempts" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 1")
            if "credential_round" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN credential_round INTEGER NOT NULL DEFAULT 1")
            if "security_attempt" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN security_attempt INTEGER NOT NULL DEFAULT 1")
            if "max_credential_rounds" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN max_credential_rounds INTEGER NOT NULL DEFAULT 1")
            if "max_security_attempts" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN max_security_attempts INTEGER NOT NULL DEFAULT 1")
            if "clipboard_enabled" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN clipboard_enabled INTEGER NOT NULL DEFAULT 1")
            if "file_transfer_enabled" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN file_transfer_enabled INTEGER NOT NULL DEFAULT 1")
            if "rdp_security" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN rdp_security TEXT NOT NULL DEFAULT ''")
            if "rdp_security_plan" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN rdp_security_plan TEXT NOT NULL DEFAULT ''")
            if "rdp_session_mode" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN rdp_session_mode TEXT NOT NULL DEFAULT 'STANDARD'")
            if "handoff_reconnect_attempt" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN handoff_reconnect_attempt INTEGER NOT NULL DEFAULT 0")
            if "max_handoff_reconnects" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN max_handoff_reconnects INTEGER NOT NULL DEFAULT 0")
            if "connection_intent" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN connection_intent TEXT NOT NULL DEFAULT 'STANDARD_ACCESS'")
            if "local_session_impact" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN local_session_impact TEXT NOT NULL DEFAULT ''")
            if "operator_acknowledged" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN operator_acknowledged INTEGER NOT NULL DEFAULT 0")
            if "operator_ack_unix" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN operator_ack_unix INTEGER NOT NULL DEFAULT 0")
            if "consent_state" not in columns:
                con.execute("ALTER TABLE remote_sessions ADD COLUMN consent_state TEXT NOT NULL DEFAULT 'NOT_APPLICABLE'")
            con.execute("CREATE INDEX IF NOT EXISTS idx_remote_sessions_retry ON remote_sessions(retry_root_session_id, retry_attempt)")

    def _cleanup_locked(self, con: sqlite3.Connection, now: int) -> None:
        stale_before = now - int(self.policy.max_session_seconds)
        con.execute(
            """UPDATE remote_sessions
               SET status='EXPIRED', ended_at=?, ended_unix=?, end_reason='MAX_SESSION_AGE'
               WHERE status='ACTIVE' AND COALESCE(activated_unix, created_unix) < ?""",
            (_now_iso(), now, stale_before),
        )
        con.execute(
            """UPDATE remote_sessions
               SET status='EXPIRED', ended_at=?, ended_unix=?, end_reason='TICKET_EXPIRED'
               WHERE status='ISSUED' AND expires_unix < ?""",
            (_now_iso(), now, now),
        )

    def _new_row(
        self,
        *,
        user_id: int,
        web_session_id: int,
        username: str,
        source_type: str,
        source_id: str,
        source_label: str,
        target_host: str,
        target_port: int,
        protocol: str,
        credential_id: str,
        client_ip: str,
        credential_mode: str = "VAULT",
        route_mode: str = "DIRECT",
        retry_root_session_id: str = "",
        retry_attempt: int = 1,
        max_attempts: int = 1,
        credential_round: int = 1,
        security_attempt: int = 1,
        max_credential_rounds: int = 1,
        max_security_attempts: int = 1,
        clipboard_enabled: bool | None = None,
        file_transfer_enabled: bool | None = None,
        rdp_security: str = "",
        rdp_security_plan: Any = "",
        rdp_session_mode: str = "STANDARD",
        handoff_reconnect_attempt: int = 0,
        max_handoff_reconnects: int = 0,
        connection_intent: str = "STANDARD_ACCESS",
        local_session_impact: str = "",
        operator_acknowledged: bool = False,
        operator_ack_unix: int = 0,
        consent_state: str = "NOT_APPLICABLE",
    ) -> tuple[dict[str, Any], str]:
        raw_ticket = secrets.token_urlsafe(48)
        session_id = "rs_" + secrets.token_hex(16)
        now = int(time.time())
        expires = now + int(self.policy.ticket_ttl_seconds)
        mode = str(credential_mode or "VAULT").strip().upper()
        if mode not in {"VAULT", "INTERACTIVE"}:
            raise RemoteSessionError("Modo de credencial remoto inválido.")
        route = str(route_mode or "DIRECT").strip().upper()
        if route not in {"DIRECT", "REVERSE_TUNNEL"}:
            raise RemoteSessionError("Modo de ruta remota inválido.")
        attempt = max(1, int(retry_attempt or 1))
        maximum_rounds = max(1, min(int(max_credential_rounds or 1), MAX_CREDENTIAL_ROUNDS)) if mode == "INTERACTIVE" else 1
        maximum_security = max(1, min(int(max_security_attempts or 1), MAX_SECURITY_ATTEMPTS)) if mode == "INTERACTIVE" else 1
        if mode == "INTERACTIVE" and maximum_rounds == 1 and maximum_security == 1 and int(max_attempts or 1) > 1:
            # Backward compatibility for callers/sessions created before the
            # two-dimensional retry counters existed.
            maximum_rounds = min(int(max_attempts), MAX_CREDENTIAL_ROUNDS)
        bounded_total = maximum_rounds * maximum_security
        maximum = max(1, min(int(max_attempts or bounded_total), bounded_total, MAX_INTERACTIVE_ATTEMPTS)) if mode == "INTERACTIVE" else 1
        if attempt > maximum:
            raise RemoteSessionError("REMOTE_CREDENTIAL_RETRY_EXHAUSTED: no quedan intentos de credenciales.")
        current_round = max(1, min(int(credential_round or 1), maximum_rounds))
        current_security = max(1, min(int(security_attempt or 1), maximum_security))
        root = str(retry_root_session_id or "").strip() or session_id
        protocol_name = str(protocol or "").upper()
        effective_rdp_security = str(rdp_security or "").strip().lower() if protocol_name == "RDP" else ""
        if effective_rdp_security and effective_rdp_security not in {"any", "nla", "tls", "rdp"}:
            raise RemoteSessionError("Modo de seguridad RDP inválido.")
        effective_rdp_plan = _normalize_rdp_security_plan(rdp_security_plan, effective_rdp_security) if protocol_name == "RDP" else ()
        effective_session_mode = str(rdp_session_mode or "STANDARD").strip().upper() if protocol_name == "RDP" else "STANDARD"
        if effective_session_mode not in {"STANDARD", "RESUME", "ADMIN", "SEPARATE"}:
            raise RemoteSessionError("Modo de sesión RDP inválido.")
        current_handoff_reconnect = max(0, min(int(handoff_reconnect_attempt or 0), MAX_HANDOFF_RECONNECTS))
        maximum_handoff_reconnects = max(0, min(int(max_handoff_reconnects or 0), MAX_HANDOFF_RECONNECTS))
        if mode != "INTERACTIVE" or protocol_name != "RDP":
            current_handoff_reconnect = 0
            maximum_handoff_reconnects = 0
        if current_handoff_reconnect > maximum_handoff_reconnects:
            raise RemoteSessionError("RDP_SESSION_HANDOFF_RECONNECT_EXHAUSTED")
        effective_intent = str(connection_intent or "STANDARD_ACCESS").strip().upper()
        if effective_intent not in {"PHYSICAL_CONSOLE", "INDEPENDENT_SESSION", "ADMIN_CONSOLE", "STANDARD_ACCESS"}:
            raise RemoteSessionError("Intención de control remoto inválida.")
        effective_impact = str(local_session_impact or "")[:96].upper()
        effective_consent = str(consent_state or "NOT_APPLICABLE")[:96].upper()
        acknowledged = bool(operator_acknowledged)
        acknowledged_at = max(0, int(operator_ack_unix or 0)) if acknowledged else 0
        if acknowledged and not acknowledged_at:
            acknowledged_at = now
        row = {
            "session_id": session_id,
            "user_id": int(user_id),
            "web_session_id": int(web_session_id),
            "username": str(username or ""),
            "source_type": str(source_type or "").upper(),
            "source_id": str(source_id or ""),
            "source_label": str(source_label or "")[:240],
            "target_host": str(target_host or ""),
            "target_port": int(target_port),
            "protocol": protocol_name,
            "credential_id": str(credential_id or ""),
            "client_ip": str(client_ip or "")[:128],
            "created_at": _now_iso(),
            "created_unix": now,
            "expires_unix": expires,
            "status": "ISSUED",
            "credential_mode": mode,
            "route_mode": route,
            "retry_root_session_id": root,
            "retry_attempt": attempt,
            "max_attempts": maximum,
            "credential_round": current_round,
            "security_attempt": current_security,
            "max_credential_rounds": maximum_rounds,
            "max_security_attempts": maximum_security,
            "clipboard_enabled": int(self.policy.clipboard_enabled if clipboard_enabled is None else bool(clipboard_enabled)),
            "file_transfer_enabled": int(self.policy.file_transfer_enabled if file_transfer_enabled is None else bool(file_transfer_enabled)),
            "rdp_security": effective_rdp_security,
            "rdp_security_plan": ",".join(effective_rdp_plan),
            "rdp_session_mode": effective_session_mode,
            "handoff_reconnect_attempt": current_handoff_reconnect,
            "max_handoff_reconnects": maximum_handoff_reconnects,
            "connection_intent": effective_intent,
            "local_session_impact": effective_impact,
            "operator_acknowledged": int(acknowledged),
            "operator_ack_unix": acknowledged_at,
            "consent_state": effective_consent,
        }
        return row, raw_ticket

    @staticmethod
    def _insert_locked(con: sqlite3.Connection, row: dict[str, Any], raw_ticket: str) -> None:
        con.execute(
            """INSERT INTO remote_sessions(
                   session_id,ticket_hash,user_id,web_session_id,username,source_type,source_id,source_label,
                   target_host,target_port,protocol,credential_id,client_ip,created_at,created_unix,
                   expires_unix,status,credential_mode,route_mode,retry_root_session_id,retry_attempt,max_attempts,
                   credential_round,security_attempt,max_credential_rounds,max_security_attempts,
                   clipboard_enabled,file_transfer_enabled,rdp_security,rdp_security_plan,rdp_session_mode,
                   handoff_reconnect_attempt,max_handoff_reconnects,connection_intent,local_session_impact,
                   operator_acknowledged,operator_ack_unix,consent_state
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["session_id"], _ticket_hash(raw_ticket), row["user_id"], row["web_session_id"], row["username"],
                row["source_type"], row["source_id"], row["source_label"], row["target_host"],
                row["target_port"], row["protocol"], row["credential_id"], row["client_ip"],
                row["created_at"], row["created_unix"], row["expires_unix"], row["status"],
                row["credential_mode"], row["route_mode"], row["retry_root_session_id"], row["retry_attempt"], row["max_attempts"],
                row["credential_round"], row["security_attempt"], row["max_credential_rounds"], row["max_security_attempts"],
                row["clipboard_enabled"], row["file_transfer_enabled"], row["rdp_security"], row["rdp_security_plan"],
                row["rdp_session_mode"], row["handoff_reconnect_attempt"], row["max_handoff_reconnects"],
                row["connection_intent"], row["local_session_impact"], row["operator_acknowledged"],
                row["operator_ack_unix"], row["consent_state"],
            ),
        )

    def issue(
        self,
        *,
        user_id: int,
        web_session_id: int,
        username: str,
        source_type: str,
        source_id: str,
        source_label: str,
        target_host: str,
        target_port: int,
        protocol: str,
        credential_id: str,
        client_ip: str,
        credential_mode: str = "VAULT",
        route_mode: str = "DIRECT",
        retry_root_session_id: str = "",
        retry_attempt: int = 1,
        max_attempts: int = 1,
        credential_round: int = 1,
        security_attempt: int = 1,
        max_credential_rounds: int = 1,
        max_security_attempts: int = 1,
        clipboard_enabled: bool | None = None,
        file_transfer_enabled: bool | None = None,
        rdp_security: str = "",
        rdp_security_plan: Any = "",
        rdp_session_mode: str = "STANDARD",
        handoff_reconnect_attempt: int = 0,
        max_handoff_reconnects: int = 0,
        connection_intent: str = "STANDARD_ACCESS",
        local_session_impact: str = "",
        operator_acknowledged: bool = False,
        operator_ack_unix: int = 0,
        consent_state: str = "NOT_APPLICABLE",
    ) -> tuple[dict[str, Any], str]:
        if not self.policy.enabled:
            raise RemoteSessionError("El servicio de sesiones remotas está deshabilitado.")
        row, raw_ticket = self._new_row(
            user_id=user_id, web_session_id=web_session_id, username=username,
            source_type=source_type, source_id=source_id, source_label=source_label,
            target_host=target_host, target_port=target_port, protocol=protocol,
            credential_id=credential_id, client_ip=client_ip, credential_mode=credential_mode,
            route_mode=route_mode,
            retry_root_session_id=retry_root_session_id, retry_attempt=retry_attempt, max_attempts=max_attempts,
            credential_round=credential_round, security_attempt=security_attempt,
            max_credential_rounds=max_credential_rounds, max_security_attempts=max_security_attempts,
            clipboard_enabled=clipboard_enabled, file_transfer_enabled=file_transfer_enabled,
            rdp_security=rdp_security,
            rdp_security_plan=rdp_security_plan,
            rdp_session_mode=rdp_session_mode,
            handoff_reconnect_attempt=handoff_reconnect_attempt,
            max_handoff_reconnects=max_handoff_reconnects,
            connection_intent=connection_intent,
            local_session_impact=local_session_impact,
            operator_acknowledged=operator_acknowledged,
            operator_ack_unix=operator_ack_unix,
            consent_state=consent_state,
        )
        with self.connect() as con:
            self._insert_locked(con, row, raw_ticket)
        return row, raw_ticket

    def issue_retry(
        self,
        *,
        previous_session_id: str,
        user_id: int,
        web_session_id: int,
        username: str,
        credential_id: str,
        client_ip: str,
        target_host: str = "",
        target_port: int = 0,
        route_mode: str = "",
        rdp_security: str = "",
        reuse_credential: bool = False,
    ) -> tuple[dict[str, Any], str]:
        """Issue the next one-use ticket in an INTERACTIVE credential retry chain.

        Retry counters are enforced server-side in one SQLite transaction.  The
        password itself is never stored here; ``credential_id`` points only to
        the one-use in-memory credential cache.
        """
        if not self.policy.enabled:
            raise RemoteSessionError("El servicio de sesiones remotas está deshabilitado.")
        now = int(time.time())
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(con, now)
            previous = con.execute(
                "SELECT * FROM remote_sessions WHERE session_id=?", (str(previous_session_id),)
            ).fetchone()
            if previous is None:
                raise RemoteSessionError("Sesión remota no encontrada.")
            value = dict(previous)
            if int(value.get("user_id") or 0) != int(user_id) or str(value.get("username") or "") != str(username or ""):
                raise RemoteSessionError("La sesión remota pertenece a otro usuario.")
            if int(value.get("web_session_id") or 0) != int(web_session_id):
                raise RemoteSessionError("La sesión remota pertenece a otra sesión WebAdmin.")
            issued_ip = str(value.get("client_ip") or "")
            if self.policy.bind_ticket_to_ip and issued_ip and str(client_ip or "") != issued_ip:
                raise RemoteSessionError("La sesión remota cambió de dirección de origen.")
            if str(value.get("credential_mode") or "VAULT").upper() != "INTERACTIVE":
                raise RemoteSessionError("REMOTE_CREDENTIAL_RETRY_NOT_ALLOWED: esta sesión no usa credenciales interactivas.")
            if str(value.get("status") or "").upper() not in {"CLOSED", "EXPIRED"}:
                raise RemoteSessionError("REMOTE_CREDENTIAL_RETRY_NOT_READY: finalice la conexión anterior antes de reintentar.")
            root = str(value.get("retry_root_session_id") or value.get("session_id") or "")
            current = max(1, int(value.get("retry_attempt") or 1))
            maximum = max(1, min(int(value.get("max_attempts") or 1), MAX_INTERACTIVE_ATTEMPTS))
            credential_round = max(1, int(value.get("credential_round") or 1))
            security_attempt = max(1, int(value.get("security_attempt") or 1))
            maximum_rounds = max(1, min(int(value.get("max_credential_rounds") or 1), MAX_CREDENTIAL_ROUNDS))
            maximum_security = max(1, min(int(value.get("max_security_attempts") or 1), MAX_SECURITY_ATTEMPTS))
            if maximum_rounds == 1 and maximum_security == 1 and maximum > 1:
                maximum_rounds = min(maximum, MAX_CREDENTIAL_ROUNDS)
            latest_row = con.execute(
                """SELECT session_id FROM remote_sessions WHERE retry_root_session_id=?
                   ORDER BY retry_attempt DESC, handoff_reconnect_attempt DESC, created_unix DESC, rowid DESC LIMIT 1""",
                (root,),
            ).fetchone()
            if latest_row is None or str(latest_row[0]) != str(previous_session_id):
                raise RemoteSessionError("REMOTE_CREDENTIAL_RETRY_STALE: ya existe un intento posterior para esta sesión.")
            if current >= maximum:
                raise RemoteSessionError("REMOTE_CREDENTIAL_RETRY_EXHAUSTED: no quedan intentos de conexión.")
            if reuse_credential:
                if security_attempt >= maximum_security:
                    raise RemoteSessionError("REMOTE_SECURITY_RETRY_EXHAUSTED: no quedan modos para esta contraseña.")
                next_credential_id = str(value.get("credential_id") or "")
                next_round = credential_round
                next_security_attempt = security_attempt + 1
            else:
                if credential_round >= maximum_rounds:
                    raise RemoteSessionError("REMOTE_CREDENTIAL_RETRY_EXHAUSTED: no quedan contraseñas permitidas.")
                next_credential_id = str(credential_id or "")
                if not next_credential_id:
                    raise RemoteSessionError("La nueva credencial interactiva no está disponible.")
                next_round = credential_round + 1
                next_security_attempt = 1
            row, raw_ticket = self._new_row(
                user_id=user_id, web_session_id=web_session_id, username=username,
                source_type=str(value.get("source_type") or ""), source_id=str(value.get("source_id") or ""),
                source_label=str(value.get("source_label") or ""),
                target_host=str(target_host or value.get("target_host") or ""),
                target_port=int(target_port or value.get("target_port") or 0), protocol=str(value.get("protocol") or ""),
                credential_id=next_credential_id, client_ip=str(client_ip or issued_ip), credential_mode="INTERACTIVE",
                route_mode=str(route_mode or value.get("route_mode") or "DIRECT"),
                retry_root_session_id=root, retry_attempt=current + 1, max_attempts=maximum,
                credential_round=next_round, security_attempt=next_security_attempt,
                max_credential_rounds=maximum_rounds, max_security_attempts=maximum_security,
                clipboard_enabled=bool(value.get("clipboard_enabled", 1)),
                file_transfer_enabled=bool(value.get("file_transfer_enabled", 1)),
                rdp_security=str(rdp_security or value.get("rdp_security") or ""),
                rdp_security_plan=str(value.get("rdp_security_plan") or ""),
                rdp_session_mode=str(value.get("rdp_session_mode") or "STANDARD"),
                handoff_reconnect_attempt=int(value.get("handoff_reconnect_attempt") or 0),
                max_handoff_reconnects=int(value.get("max_handoff_reconnects") or 0),
                connection_intent=str(value.get("connection_intent") or "STANDARD_ACCESS"),
                local_session_impact=str(value.get("local_session_impact") or ""),
                operator_acknowledged=bool(value.get("operator_acknowledged", 0)),
                operator_ack_unix=int(value.get("operator_ack_unix") or 0),
                consent_state=str(value.get("consent_state") or "NOT_APPLICABLE"),
            )
            self._insert_locked(con, row, raw_ticket)
            return row, raw_ticket

    def issue_handoff_reconnect(
        self,
        *,
        previous_session_id: str,
        user_id: int,
        web_session_id: int,
        username: str,
        client_ip: str,
        target_host: str = "",
        target_port: int = 0,
        route_mode: str = "",
    ) -> tuple[dict[str, Any], str]:
        """Clone one RDP ticket after Windows changes the interactive session.

        This is a distinct, one-shot transport reconnect.  It preserves the
        password/security counters because Windows already accepted the same
        credential; only the obsolete guacd/RDP channel is replaced.
        """
        if not self.policy.enabled:
            raise RemoteSessionError("El servicio de sesiones remotas está deshabilitado.")
        now = int(time.time())
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(con, now)
            previous = con.execute(
                "SELECT * FROM remote_sessions WHERE session_id=?", (str(previous_session_id),)
            ).fetchone()
            if previous is None:
                raise RemoteSessionError("Sesión remota no encontrada.")
            value = dict(previous)
            if (
                int(value.get("user_id") or 0) != int(user_id)
                or int(value.get("web_session_id") or 0) != int(web_session_id)
                or str(value.get("username") or "") != str(username or "")
            ):
                raise RemoteSessionError("La sesión remota pertenece a otra sesión WebAdmin.")
            issued_ip = str(value.get("client_ip") or "")
            if self.policy.bind_ticket_to_ip and issued_ip and str(client_ip or "") != issued_ip:
                raise RemoteSessionError("La sesión remota cambió de dirección de origen.")
            if (
                str(value.get("credential_mode") or "VAULT").upper() != "INTERACTIVE"
                or str(value.get("protocol") or "").upper() != "RDP"
            ):
                raise RemoteSessionError("RDP_SESSION_HANDOFF_RECONNECT_NOT_ALLOWED")
            if str(value.get("status") or "").upper() not in {"ACTIVE", "CLOSED"}:
                raise RemoteSessionError("RDP_SESSION_HANDOFF_RECONNECT_NOT_READY")
            current_handoff = max(0, int(value.get("handoff_reconnect_attempt") or 0))
            maximum_handoff = max(0, min(int(value.get("max_handoff_reconnects") or 0), MAX_HANDOFF_RECONNECTS))
            if current_handoff >= maximum_handoff:
                raise RemoteSessionError("RDP_SESSION_HANDOFF_RECONNECT_EXHAUSTED")
            root = str(value.get("retry_root_session_id") or value.get("session_id") or "")
            latest_row = con.execute(
                """SELECT session_id FROM remote_sessions WHERE retry_root_session_id=?
                   ORDER BY retry_attempt DESC, handoff_reconnect_attempt DESC, created_unix DESC, rowid DESC LIMIT 1""",
                (root,),
            ).fetchone()
            if latest_row is None or str(latest_row[0]) != str(previous_session_id):
                raise RemoteSessionError("RDP_SESSION_HANDOFF_RECONNECT_STALE")
            credential_id = str(value.get("credential_id") or "")
            if not credential_id:
                raise RemoteSessionError("La credencial interactiva ya no está disponible.")

            row, raw_ticket = self._new_row(
                user_id=user_id, web_session_id=web_session_id, username=username,
                source_type=str(value.get("source_type") or ""), source_id=str(value.get("source_id") or ""),
                source_label=str(value.get("source_label") or ""),
                target_host=str(target_host or value.get("target_host") or ""),
                target_port=int(target_port or value.get("target_port") or 0),
                protocol="RDP", credential_id=credential_id,
                client_ip=str(client_ip or issued_ip), credential_mode="INTERACTIVE",
                route_mode=str(route_mode or value.get("route_mode") or "DIRECT"),
                retry_root_session_id=root,
                retry_attempt=int(value.get("retry_attempt") or 1),
                max_attempts=int(value.get("max_attempts") or 1),
                credential_round=int(value.get("credential_round") or 1),
                security_attempt=int(value.get("security_attempt") or 1),
                max_credential_rounds=int(value.get("max_credential_rounds") or 1),
                max_security_attempts=int(value.get("max_security_attempts") or 1),
                clipboard_enabled=bool(value.get("clipboard_enabled", 1)),
                file_transfer_enabled=bool(value.get("file_transfer_enabled", 1)),
                rdp_security=str(value.get("rdp_security") or ""),
                rdp_security_plan=str(value.get("rdp_security_plan") or ""),
                rdp_session_mode=str(value.get("rdp_session_mode") or "STANDARD"),
                handoff_reconnect_attempt=current_handoff + 1,
                max_handoff_reconnects=maximum_handoff,
                connection_intent=str(value.get("connection_intent") or "STANDARD_ACCESS"),
                local_session_impact=str(value.get("local_session_impact") or ""),
                operator_acknowledged=bool(value.get("operator_acknowledged", 0)),
                operator_ack_unix=int(value.get("operator_ack_unix") or 0),
                consent_state=str(value.get("consent_state") or "NOT_APPLICABLE"),
            )
            con.execute(
                """UPDATE remote_sessions SET status='CLOSED', ended_at=?, ended_unix=?,
                   end_reason='RDP_SESSION_HANDOFF_RECONNECT'
                   WHERE session_id=? AND status IN ('ISSUED','ACTIVE')""",
                (_now_iso(), now, str(previous_session_id)),
            )
            self._insert_locked(con, row, raw_ticket)
            return row, raw_ticket

    def consume(self, *, session_id: str, raw_ticket: str, user_id: int, web_session_id: int, username: str, client_ip: str = "") -> dict[str, Any]:
        now = int(time.time())
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(con, now)
            row = con.execute("SELECT * FROM remote_sessions WHERE session_id=?", (str(session_id),)).fetchone()
            if row is None:
                raise RemoteSessionError("Sesión remota no encontrada.")
            value = dict(row)
            if value["status"] != "ISSUED":
                raise RemoteSessionError("El ticket remoto ya fue utilizado o expiró.")
            if int(value["expires_unix"] or 0) < now:
                raise RemoteSessionError("El ticket remoto expiró.")
            if int(value["user_id"] or 0) != int(user_id) or str(value["username"] or "") != str(username or ""):
                raise RemoteSessionError("El ticket remoto pertenece a otro usuario.")
            if int(value.get("web_session_id") or 0) != int(web_session_id):
                raise RemoteSessionError("El ticket remoto pertenece a otra sesión WebAdmin.")
            issued_ip = str(value.get("client_ip") or "")
            if self.policy.bind_ticket_to_ip and issued_ip and str(client_ip or "") != issued_ip:
                raise RemoteSessionError("El ticket remoto cambió de dirección de origen.")
            if not raw_ticket or not secrets.compare_digest(str(value["ticket_hash"]), _ticket_hash(raw_ticket)):
                raise RemoteSessionError("Ticket remoto inválido.")

            active_total = int(con.execute("SELECT COUNT(*) FROM remote_sessions WHERE status='ACTIVE'").fetchone()[0])
            active_user = int(con.execute(
                "SELECT COUNT(*) FROM remote_sessions WHERE status='ACTIVE' AND user_id=?", (int(user_id),)
            ).fetchone()[0])
            if str(value.get("source_type") or "").upper() == "AGENT":
                active_target = int(con.execute(
                    "SELECT COUNT(*) FROM remote_sessions WHERE status='ACTIVE' AND source_type='AGENT' AND source_id=?",
                    (str(value.get("source_id") or ""),),
                ).fetchone()[0])
            else:
                active_target = int(con.execute(
                    "SELECT COUNT(*) FROM remote_sessions WHERE status='ACTIVE' AND target_host=? AND target_port=?",
                    (str(value["target_host"]), int(value["target_port"])),
                ).fetchone()[0])
            if active_total >= self.policy.max_active_sessions:
                raise RemoteSessionError("REMOTE_SESSION_CAPACITY: se alcanzó el máximo global de sesiones remotas.")
            if active_user >= self.policy.max_sessions_per_user:
                raise RemoteSessionError("REMOTE_SESSION_USER_CAPACITY: el usuario alcanzó su máximo de sesiones remotas.")
            if active_target >= self.policy.max_sessions_per_target:
                raise RemoteSessionError("REMOTE_SESSION_TARGET_BUSY: el equipo ya tiene una sesión remota activa.")

            activated = _now_iso()
            con.execute(
                """UPDATE remote_sessions
                   SET status='ACTIVE', activated_at=?, activated_unix=?, client_ip=?
                   WHERE session_id=? AND status='ISSUED'""",
                (activated, now, str(client_ip or value.get("client_ip") or "")[:128], str(session_id)),
            )
            value.update({"status": "ACTIVE", "activated_at": activated, "activated_unix": now})
            return value

    def close(self, session_id: str, *, reason: str = "DISCONNECTED") -> None:
        now = int(time.time())
        with self.connect() as con:
            con.execute(
                """UPDATE remote_sessions SET status='CLOSED', ended_at=?, ended_unix=?, end_reason=?
                   WHERE session_id=? AND status IN ('ISSUED','ACTIVE')""",
                (_now_iso(), now, str(reason or "DISCONNECTED")[:240], str(session_id)),
            )

    def get_for_user(self, session_id: str, user_id: int) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute(
                "SELECT * FROM remote_sessions WHERE session_id=? AND user_id=?",
                (str(session_id), int(user_id)),
            ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value.pop("ticket_hash", None)
        value.pop("credential_id", None)
        return value

    def credential_reference_for_retry(
        self, session_id: str, *, user_id: int, web_session_id: int, username: str
    ) -> str:
        """Return the opaque credential reference to trusted retry code only."""
        with self.connect() as con:
            row = con.execute(
                "SELECT credential_id,user_id,web_session_id,username FROM remote_sessions WHERE session_id=?",
                (str(session_id),),
            ).fetchone()
        if row is None:
            raise RemoteSessionError("Sesión remota no encontrada.")
        value = dict(row)
        if (
            int(value.get("user_id") or 0) != int(user_id)
            or int(value.get("web_session_id") or 0) != int(web_session_id)
            or str(value.get("username") or "") != str(username or "")
        ):
            raise RemoteSessionError("La sesión remota pertenece a otra sesión WebAdmin.")
        return str(value.get("credential_id") or "")

    def stats(self) -> dict[str, int]:
        now = int(time.time())
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(con, now)
            active = int(con.execute("SELECT COUNT(*) FROM remote_sessions WHERE status='ACTIVE'").fetchone()[0])
            issued = int(con.execute("SELECT COUNT(*) FROM remote_sessions WHERE status='ISSUED'").fetchone()[0])
        return {
            "active": active,
            "issued": issued,
            "max_active": int(self.policy.max_active_sessions),
            "max_per_user": int(self.policy.max_sessions_per_user),
            "max_per_target": int(self.policy.max_sessions_per_target),
        }


class RemoteTargetResolver:
    def __init__(self, allowed_cidrs: Iterable[str]) -> None:
        networks: list[ipaddress._BaseNetwork] = []
        for value in allowed_cidrs:
            try:
                networks.append(ipaddress.ip_network(str(value), strict=False))
            except ValueError:
                continue
        if not networks:
            raise RemoteSessionError("No existen redes permitidas para escritorio remoto.")
        self.networks = tuple(networks)

    def validate_ip(self, value: str) -> str:
        clean = str(value or "").strip()
        try:
            address = ipaddress.ip_address(clean)
        except ValueError as exc:
            raise RemoteSessionError("El destino remoto debe ser una dirección IP explícita; no se aceptan nombres arbitrarios.") from exc
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
            raise RemoteSessionError("La dirección remota no es un destino administrable válido.")
        if not any(address in network for network in self.networks if address.version == network.version):
            raise RemoteSessionError("REMOTE_TARGET_OUTSIDE_ALLOWLIST: el destino está fuera de las redes privadas autorizadas.")
        return str(address)

    def agent_candidates(self, row: dict[str, Any]) -> list[str]:
        diagnostics = row.get("Diagnostics") if isinstance(row.get("Diagnostics"), dict) else {}
        network = diagnostics.get("network") if isinstance(diagnostics.get("network"), dict) else {}
        values: list[str] = []
        for candidate in [network.get("source_ip"), *(network.get("local_ips") or [])]:
            clean = str(candidate or "").strip()
            if not clean or clean in values:
                continue
            try:
                values.append(self.validate_ip(clean))
            except RemoteSessionError:
                continue
        return values

    @staticmethod
    def agent_label(row: dict[str, Any]) -> str:
        return str(
            f"{row.get('site_code') or '-'} · {row.get('site_name') or '-'} · "
            f"{row.get('agent_name') or row.get('hostname') or row.get('agent_id')}"
        )

    def resolve_agent(self, row: dict[str, Any], requested_ip: str = "") -> tuple[str, str]:
        candidates = self.agent_candidates(row)
        if not candidates:
            raise RemoteSessionError(
                "AGENT_REMOTE_IP_MISSING: el Agent no reporta una IP privada enrutable para RDP/VNC. "
                "Verifique VPN/ruta hacia la red del equipo."
            )
        if requested_ip:
            selected = self.validate_ip(requested_ip)
            if selected not in candidates:
                raise RemoteSessionError("La IP seleccionada no pertenece a la telemetría actual del Agent.")
        else:
            selected = candidates[0]
        return selected, self.agent_label(row)

    def resolve_host(self, row: dict[str, Any]) -> tuple[str, str]:
        selected = self.validate_ip(str(row.get("ServerIP") or ""))
        label = f"{row.get('SiteCode') or '-'} · {row.get('SiteName') or '-'} · {selected}"
        return selected, str(label)

    @staticmethod
    def probe(host: str, port: int, *, timeout_seconds: float) -> tuple[bool, str]:
        try:
            with socket.create_connection((str(host), int(port)), timeout=float(timeout_seconds)):
                return True, "TCP disponible"
        except OSError as exc:
            return False, f"TCP/{int(port)} no disponible: {type(exc).__name__}: {exc}"
