#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GIDEON Agent Gateway v2.4.3 (optional execution method).

Standard-library control plane for GIDEON Agent HTTPS/PULL mode.
Designed to run on a central server (e.g. AWS EC2) behind HTTPS/reverse proxy,
or with direct TLS using --certfile/--keyfile.

The existing SSH/SFTP mode does not depend on this component.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import html
import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import sys
import time
import socket
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gideon_agent_config import CentralConfigError, build_document, sanitize_settings, validate_document
from gideon_common.redaction import redact, redact_error
from gideon_infrastructure.sqlite_connections import SQLiteConnectionFactory, SQLiteConnectionOptions
from gideon_gateway_schema import ensure_gateway_schema
from gideon_reverse_tunnel import (
    GatewayTunnelBroker,
    WebSocketPeer,
    _configure_tcp_keepalive,
    _ws_accept,
    TUNNEL_VERSION,
)

from gideon_version import GATEWAY_VERSION

try:
    from gideon_gateway_bootstrap import GATEWAY_CONFIG_PATH as DEFAULT_GATEWAY_CONFIG_PATH
except Exception:
    DEFAULT_GATEWAY_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "agent_gateway.json"

VERSION = GATEWAY_VERSION
LOG = logging.getLogger("gideon.agent_gateway")
PLAYER_MANIFEST_SCHEMA = "gideon-media-player-manifest/v1"
PLAYER_STATUS_SCHEMA = "gideon-agent-player-status/v1"
PLAYER_TARGET_KINDS = frozenset({"PHYSICAL_CONNECTOR", "LOCAL_WAYLAND_SESSION"})
OFFLINE_VLC_AUTHORIZATION_SCHEMA = "gideon-vlc-offline-install-authorization/v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PLAYER_STATE_RE = re.compile(r"^[A-Z][A-Z0-9_:-]{0,79}$")
_OFFLINE_VLC_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$")
_OFFLINE_VLC_ACTIVE_STATES = frozenset({"REQUESTED", "DELIVERED", "DEFERRED", "RUNNING"})
_OFFLINE_VLC_TERMINAL_STATES = frozenset({"INSTALLED", "FAILED", "CANCELLED", "EXPIRED", "SUPERSEDED"})
_OFFLINE_VLC_AGENT_REPORT_STATES = frozenset({"DEFERRED", "RUNNING", "INSTALLED", "FAILED", "CANCELLED", "EXPIRED"})
_OFFLINE_VLC_MAX_AUTHORIZATION_BYTES = 256 * 1024
# The signed grant provides a 15-minute start window. Once the installer has
# started, a missing Agent report for ten minutes means ownership can no longer
# be proven, while forty-five minutes is a hard ceiling even if a faulty Agent
# keeps repeating RUNNING forever. Both limits fail closed and unblock a later
# explicitly signed request; they never start an installation themselves.
_OFFLINE_VLC_RUNNING_STALE_SECONDS = 10 * 60
_OFFLINE_VLC_RUNNING_MAX_SECONDS = 45 * 60


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _agent_client_ca_paths(config: dict[str, Any]) -> tuple[Path, Path]:
    """Resolve the Gateway client-CA pair without ever placing the key in an Agent bundle."""
    cert_value = str(config.get("client_ca_file") or "").strip()
    if not cert_value:
        raise RuntimeError("AGENT_MTLS_CA_NOT_CONFIGURED")
    cert_path = Path(cert_value).expanduser()
    key_value = str(config.get("client_ca_key_file") or "").strip()
    key_path = Path(key_value).expanduser() if key_value else cert_path.with_suffix(".key")
    if not cert_path.is_file() or not key_path.is_file():
        raise RuntimeError("AGENT_MTLS_CA_KEY_NOT_FOUND")
    return cert_path, key_path


def issue_agent_client_certificate(
    config: dict[str, Any], *, csr_pem: str, agent_id: str, hostname: str = ""
) -> dict[str, str]:
    """Sign one short-lived client leaf from the Gateway-only Agent CA.

    The Agent generates the private key locally and sends only a CSR.  The CA
    private key is never returned by this function and is never copied into an
    installer or Agent directory.
    """
    raw = str(csr_pem or "").encode("utf-8")
    if len(raw) > 128 * 1024:
        raise ValueError("AGENT_MTLS_CSR_TOO_LARGE")
    csr = x509.load_pem_x509_csr(raw)
    if not bool(getattr(csr, "is_signature_valid", False)):
        raise ValueError("AGENT_MTLS_CSR_SIGNATURE_INVALID")
    agent_id = str(agent_id or "").strip()
    if not agent_id or len(agent_id) > 160:
        raise ValueError("AGENT_MTLS_AGENT_ID_INVALID")
    ca_path, key_path = _agent_client_ca_paths(config)
    ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
    ca_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"GIDEON Agent {agent_id}")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=2))
        .not_valid_after(now + dt.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    clean_host = str(hostname or "").strip()
    if clean_host and len(clean_host) <= 253 and all(part and len(part) <= 63 for part in clean_host.split(".")):
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(clean_host)]), critical=False)
    leaf = builder.sign(ca_key, hashes.SHA256())
    cert_pem = leaf.public_bytes(serialization.Encoding.PEM).decode("ascii")
    fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
    # ``not_valid_after_utc`` was added in newer cryptography releases.  The
    # cloud Gateway may intentionally use the distro-provided LTS package, so
    # keep mTLS enrollment compatible with versions that only expose the
    # timezone-naive ``not_valid_after`` property.
    expires_at = getattr(leaf, "not_valid_after_utc", None)
    if expires_at is None:
        expires_at = leaf.not_valid_after.replace(tzinfo=dt.timezone.utc)
    return {
        "Certificate": cert_pem,
        "FingerprintSHA256": fingerprint,
        "ExpiresAt": expires_at.isoformat(),
        "Issuer": ca_cert.subject.rfc4514_string(),
    }


def legacy_agent_id(site_code: str, hostname: str) -> str:
    """Stable fallback identity for pre-v6.0.33 agents.

    New agents send a persisted random AgentId. Existing installs that do not yet
    have one derive the same value from SiteCode + hostname so migration does not
    orphan their bearer token or queued work.
    """
    seed = f"{str(site_code or '').strip().lower()}|{str(hostname or '').strip().lower()}"
    return "agt-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(str(a or ""), str(b or ""))


def version_key(value: str) -> tuple[int, int, int, int]:
    parts=[]
    for token in str(value or "0").split(".")[:4]:
        digits="".join(ch for ch in token if ch.isdigit())
        parts.append(int(digits or 0))
    while len(parts)<4:
        parts.append(0)
    return tuple(parts[:4])


class GatewayDB:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir.resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "gateway.sqlite3"
        self.packages_dir = self.data_dir / "packages"
        self.results_dir = self.data_dir / "results"
        self.incoming_dir = self.data_dir / "incoming"
        self.packages_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        self.incoming_dir.mkdir(exist_ok=True)
        self._connections = SQLiteConnectionFactory(SQLiteConnectionOptions(
            path=self.db_path,
            timeout_seconds=15,
            isolation_level=None,
            pragmas=(
                "PRAGMA journal_mode=WAL",
                "PRAGMA synchronous=NORMAL",
                "PRAGMA busy_timeout=5000",
            ),
        ))
        self.init_schema()

    def connect(self):
        """Return a managed SQLite transaction that always closes on exit."""
        return self._connections.connect()

    def init_schema(self) -> None:
        """Create/repair the Gateway schema through the dedicated migrator."""
        with self.connect() as con:
            ensure_gateway_schema(con)

        status = self.schema_status()
        if not status["Ready"]:
            raise RuntimeError("Gateway schema repair did not reach a valid state: " + str(status))

    @staticmethod
    def _table_has_unique_key(con: sqlite3.Connection, name: str, expected: list[str]) -> bool:
        exists = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone() is not None
        if not exists:
            return False
        rows = con.execute(f'PRAGMA table_info("{name.replace(chr(34), chr(34)*2)}")').fetchall()
        pk = sorted(
            ((int(row[5] or 0), str(row[1])) for row in rows if int(row[5] or 0) > 0),
            key=lambda item: item[0],
        )
        if [col for _, col in pk] == expected:
            return True
        for idx in con.execute(f'PRAGMA index_list("{name.replace(chr(34), chr(34)*2)}")').fetchall():
            if not int(idx[2] or 0):
                continue
            idx_name = str(idx[1]).replace('"', '""')
            idx_cols = [str(r[2]) for r in con.execute(f'PRAGMA index_info("{idx_name}")').fetchall()]
            if idx_cols == expected:
                return True
        return False

    def schema_status(self) -> dict[str, Any]:
        """Return the runtime schema contract used by enrollment and jobs."""
        with self.connect() as con:
            agents_ok = self._table_has_unique_key(con, "agents", ["agent_id"])
            tokens_ok = self._table_has_unique_key(con, "agents", ["token_hash"])
            jobs_ok = self._table_has_unique_key(con, "jobs", ["job_id", "agent_id"])
            releases_ok = self._table_has_unique_key(
                con, "agent_releases", ["platform", "architecture", "channel", "version"]
            )
            configs_ok = self._table_has_unique_key(con, "agent_configurations", ["agent_id", "version"])
            config_status_ok = self._table_has_unique_key(con, "agent_config_status", ["agent_id"])
            update_requests_ok = self._table_has_unique_key(con, "agent_update_requests", ["request_id"])
            offline_vlc_requests_ok = self._table_has_unique_key(
                con, "agent_vlc_offline_install_requests", ["request_id"]
            )
            if offline_vlc_requests_ok:
                vlc_columns = {
                    str(row[1]) for row in con.execute(
                        'PRAGMA table_info("agent_vlc_offline_install_requests")'
                    ).fetchall()
                }
                offline_vlc_requests_ok = {
                    "started_at", "started_unix", "reported_unix",
                }.issubset(vlc_columns)
            media_manifests_ok = self._table_has_unique_key(con, "agent_media_manifests", ["agent_id", "manifest_version"])
            media_manifest_reissue_ok = not self._table_has_unique_key(
                con, "agent_media_manifests", ["agent_id", "manifest_sha256"]
            )
            media_reports_ok = self._table_has_unique_key(con, "agent_media_player_reports", ["report_id"])
            duplicate_agents = 0
            if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents'").fetchone():
                row = con.execute(
                    "SELECT COUNT(*) FROM (SELECT agent_id FROM agents GROUP BY agent_id HAVING COUNT(*) > 1)"
                ).fetchone()
                duplicate_agents = int(row[0] or 0) if row else 0
        return {
            "Ready": bool(agents_ok and tokens_ok and jobs_ok and releases_ok and configs_ok and config_status_ok and update_requests_ok and offline_vlc_requests_ok and media_manifests_ok and media_manifest_reissue_ok and media_reports_ok and duplicate_agents == 0),
            "SchemaVersion": 10,
            "AgentsKey": agents_ok,
            "AgentTokenKey": tokens_ok,
            "JobsKey": jobs_ok,
            "ReleasesKey": releases_ok,
            "AgentConfigurationsKey": configs_ok,
            "AgentConfigStatusKey": config_status_ok,
            "AgentUpdateRequestsKey": update_requests_ok,
            "AgentVlcOfflineInstallRequestsKey": offline_vlc_requests_ok,
            "AgentMediaManifestsKey": media_manifests_ok,
            "AgentMediaManifestReissue": media_manifest_reissue_ok,
            "AgentMediaPlayerReportsKey": media_reports_ok,
            "DuplicateAgentIds": duplicate_agents,
        }

    def ensure_runtime_schema(self) -> dict[str, Any]:
        """Defensively repair schema drift before a write path uses it.

        This protects long-running/stale Gateway processes and databases created
        by intermediate releases.  Enrollment no longer assumes that an UPSERT
        conflict target exists.
        """
        status = self.schema_status()
        if not status["Ready"]:
            self.init_schema()
            status = self.schema_status()
        if not status["Ready"]:
            raise RuntimeError("Gateway database schema is not ready: " + str(status))
        return status

    def resolve_agent_target(self, target: str) -> Optional[sqlite3.Row]:
        """Resolve an AgentId, or a legacy SiteCode only when unambiguous."""
        value = str(target or "").strip()
        if not value:
            return None
        with self.connect() as con:
            row = con.execute("SELECT * FROM agents WHERE agent_id=?", (value,)).fetchone()
            if row is not None:
                return row
            rows = con.execute(
                "SELECT * FROM agents WHERE site_code=? ORDER BY last_seen DESC", (value,)
            ).fetchall()
            if len(rows) == 1:
                return rows[0]
            return None

    def issue_enrollment_grant_record(self, *, ttl_seconds: int = 604800, max_uses: int = 64, label: str = "generated-installer") -> dict[str, Any]:
        """Issue a revocable, time/use-limited bootstrap credential.

        ``EnrollmentGrant`` is returned once. The database stores only its hash;
        ``GrantId`` is safe to retain in Web history for later revocation.
        """
        ttl = max(300, min(int(ttl_seconds), 30 * 86400))
        uses = max(1, min(int(max_uses), 500))
        token = secrets.token_urlsafe(36)
        grant_id = "grt-" + secrets.token_hex(12)
        now_unix = int(time.time())
        created = now_iso()
        with self.connect() as con:
            con.execute("DELETE FROM enrollment_grants WHERE expires_unix < ? OR remaining_uses <= 0", (now_unix,))
            con.execute(
                """INSERT INTO enrollment_grants(token_hash,created_at,expires_unix,remaining_uses,label,grant_id,revoked_at,revoke_reason)
                   VALUES(?,?,?,?,?,?,NULL,NULL)""",
                (token_hash(token), created, now_unix + ttl, uses, str(label or "generated-installer"), grant_id),
            )
        expires = dt.datetime.fromtimestamp(now_unix + ttl).astimezone().isoformat(timespec="seconds")
        return {
            "EnrollmentGrant": token,
            "GrantId": grant_id,
            "CreatedAt": created,
            "ExpiresAt": expires,
            "TtlSeconds": ttl,
            "MaxUses": uses,
            "RemainingUses": uses,
            "Label": str(label or "generated-installer"),
        }

    def issue_enrollment_grant(self, *, ttl_seconds: int = 604800, max_uses: int = 64, label: str = "generated-installer") -> str:
        return str(self.issue_enrollment_grant_record(ttl_seconds=ttl_seconds, max_uses=max_uses, label=label)["EnrollmentGrant"])

    def list_enrollment_grants(self, *, include_expired: bool = False) -> list[dict[str, Any]]:
        now_unix = int(time.time())
        sql = "SELECT grant_id,created_at,expires_unix,remaining_uses,label,revoked_at,revoke_reason FROM enrollment_grants"
        params: tuple[Any, ...] = ()
        if not include_expired:
            sql += " WHERE expires_unix>=? AND remaining_uses>0 AND (revoked_at IS NULL OR revoked_at='')"
            params = (now_unix,)
        sql += " ORDER BY expires_unix DESC"
        with self.connect() as con:
            rows = [dict(x) for x in con.execute(sql, params).fetchall()]
        for row in rows:
            row["GrantId"] = row.pop("grant_id", None)
            row["CreatedAt"] = row.pop("created_at", None)
            expires_unix = int(row.pop("expires_unix", 0) or 0)
            row["ExpiresAt"] = dt.datetime.fromtimestamp(expires_unix).astimezone().isoformat(timespec="seconds") if expires_unix else ""
            row["RemainingUses"] = int(row.pop("remaining_uses", 0) or 0)
            row["Label"] = row.pop("label", "")
            row["RevokedAt"] = row.pop("revoked_at", None)
            row["RevokeReason"] = row.pop("revoke_reason", None)
        return rows

    def revoke_enrollment_grant(self, grant_id: str, *, reason: str = "revoked-by-admin") -> bool:
        value = str(grant_id or "").strip()
        if not value:
            return False
        with self.connect() as con:
            cur = con.execute(
                """UPDATE enrollment_grants SET remaining_uses=0,revoked_at=?,revoke_reason=?
                   WHERE grant_id=? AND remaining_uses>0""",
                (now_iso(), str(reason or "revoked-by-admin")[:500], value),
            )
        return bool(cur.rowcount)

    def consume_enrollment_grant(self, token: str) -> bool:
        digest = token_hash(str(token or ""))
        if not token:
            return False
        now_unix = int(time.time())
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT expires_unix,remaining_uses,revoked_at FROM enrollment_grants WHERE token_hash=?", (digest,)
            ).fetchone()
            if (
                not row
                or int(row["expires_unix"] or 0) < now_unix
                or int(row["remaining_uses"] or 0) <= 0
                or str(row["revoked_at"] or "").strip()
            ):
                if row and not str(row["revoked_at"] or "").strip():
                    con.execute("DELETE FROM enrollment_grants WHERE token_hash=?", (digest,))
                con.commit()
                return False
            remaining = int(row["remaining_uses"]) - 1
            if remaining <= 0:
                con.execute("DELETE FROM enrollment_grants WHERE token_hash=?", (digest,))
            else:
                con.execute("UPDATE enrollment_grants SET remaining_uses=? WHERE token_hash=?", (remaining, digest))
            con.commit()
            return True

    def enroll_agent(
        self, site_code: str, site_name: str, hostname: str, version: str,
        *, agent_id: str = "", agent_name: str = "", protocol_version: str = "", platform_name: str = "",
        architecture: str = "", host_profile: str = "", remote_ip: str = "",
        capabilities: Optional[dict[str, Any]] = None,
    ) -> tuple[str, str]:
        agent_id = str(agent_id or "").strip() or legacy_agent_id(site_code, hostname)
        token = secrets.token_urlsafe(36)
        stamp = now_iso()
        caps = json.dumps(capabilities or {}, ensure_ascii=False)
        # Do not use ``ON CONFLICT(agent_id)`` here.  Intermediate/legacy DBs
        # observed in production could expose agent_id as a plain column.  Even
        # though startup repairs that schema, an explicit UPDATE/INSERT path is
        # safer and remains valid while a long-running Gateway is being upgraded.
        self.ensure_runtime_schema()
        digest = token_hash(token)
        values = (
            site_code, site_name, agent_name, hostname, digest, version, protocol_version,
            platform_name, architecture, host_profile, caps, str(remote_ip or "").strip(), stamp, "ONLINE", agent_id,
        )
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            existing = con.execute("SELECT rowid,enrolled_at FROM agents WHERE agent_id=? ORDER BY rowid", (agent_id,)).fetchall()
            if len(existing) > 1:
                keep_rowid = int(existing[0]["rowid"])
                con.execute("DELETE FROM agents WHERE agent_id=? AND rowid<>?", (agent_id, keep_rowid))
                existing = existing[:1]
            if existing:
                con.execute(
                    """UPDATE agents SET site_code=?,site_name=?,agent_name=?,hostname=?,token_hash=?,agent_version=?,
                       protocol_version=?,platform=?,architecture=?,host_profile=?,capabilities_json=?,last_remote_ip=?,
                       last_seen=?,status=? WHERE agent_id=?""",
                    values,
                )
            else:
                con.execute(
                    """INSERT INTO agents(agent_id,site_code,site_name,agent_name,hostname,token_hash,agent_version,protocol_version,
                       platform,architecture,host_profile,capabilities_json,last_remote_ip,last_seen,enrolled_at,status)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (agent_id, site_code, site_name, agent_name, hostname, digest, version, protocol_version,
                     platform_name, architecture, host_profile, caps, str(remote_ip or "").strip(), stamp, stamp, "ONLINE"),
                )
            con.commit()
        return token, agent_id

    def set_agent_configuration(self, agent_id: str, settings: dict[str, Any], *, actor: str = "admin", note: str = "") -> dict[str, Any]:
        target = self.resolve_agent_target(agent_id)
        if target is None:
            raise ValueError(f"AGENT_TARGET_NOT_FOUND_OR_AMBIGUOUS: {agent_id}")
        resolved_id = str(target["agent_id"])
        clean_settings = sanitize_settings(settings)
        with self.connect() as con:
            row = con.execute("SELECT MAX(version) AS v FROM agent_configurations WHERE agent_id=?", (resolved_id,)).fetchone()
            version = int((row["v"] if row else 0) or 0) + 1
            document = build_document(version=version, settings=clean_settings, updated_by=actor, note=note)
            con.execute(
                """INSERT INTO agent_configurations(agent_id,version,config_json,created_at,created_by,note)
                   VALUES(?,?,?,?,?,?)""",
                (resolved_id, version, json.dumps(document, ensure_ascii=False), document["updated_at"], str(actor or "admin")[:120], str(note or "")[:500]),
            )
        return document

    def get_agent_configuration(self, agent_id: str) -> Optional[dict[str, Any]]:
        target = self.resolve_agent_target(agent_id)
        resolved_id = str(target["agent_id"]) if target is not None else str(agent_id or "").strip()
        if not resolved_id:
            return None
        with self.connect() as con:
            row = con.execute(
                "SELECT config_json FROM agent_configurations WHERE agent_id=? ORDER BY version DESC LIMIT 1", (resolved_id,)
            ).fetchone()
        if not row:
            return None
        try:
            return validate_document(json.loads(str(row["config_json"] or "{}")))
        except Exception:
            return None

    def list_agent_configuration_history(self, agent_id: str, *, limit: int = 25) -> list[dict[str, Any]]:
        target = self.resolve_agent_target(agent_id)
        resolved_id = str(target["agent_id"]) if target is not None else str(agent_id or "").strip()
        with self.connect() as con:
            rows = con.execute(
                """SELECT version,config_json,created_at,created_by,note FROM agent_configurations
                   WHERE agent_id=? ORDER BY version DESC LIMIT ?""",
                (resolved_id, max(1, min(int(limit), 200))),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                doc = validate_document(json.loads(str(row["config_json"] or "{}")))
            except Exception:
                doc = {"version": int(row["version"] or 0), "settings": {}, "schema": "INVALID"}
            result.append({
                "Version": int(row["version"] or 0),
                "Configuration": doc,
                "CreatedAt": row["created_at"],
                "CreatedBy": row["created_by"],
                "Note": row["note"],
            })
        return result

    def get_agent_config_status(self, agent_id: str) -> dict[str, Any]:
        target = self.resolve_agent_target(agent_id)
        resolved_id = str(target["agent_id"]) if target is not None else str(agent_id or "").strip()
        with self.connect() as con:
            row = con.execute("SELECT * FROM agent_config_status WHERE agent_id=?", (resolved_id,)).fetchone()
        return dict(row) if row else {"agent_id": resolved_id, "applied_version": 0, "status": "UNKNOWN", "detail": "", "reported_at": ""}

    @staticmethod
    def _canonical_media_manifest(value: dict[str, Any]) -> bytes:
        # Keep byte-for-byte compatibility with gideon_agent_player._canonical_json.
        return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

    @staticmethod
    def _safe_player_text(value: Any, *, maximum: int = 300) -> str:
        text = str(value or "").strip()
        if len(text) > maximum or "\x00" in text:
            raise ValueError("Player report field invalid")
        return text

    @staticmethod
    def _safe_player_integer(value: Any, *, minimum: int, maximum: int, message: str) -> int:
        """Parse untrusted Player numbers without echoing their raw value.

        Player reports arrive from a separately-running desktop companion.  A
        malformed value must therefore fail closed, but it must not leak that
        value through an HTTP error response or audit trail.
        """
        if isinstance(value, bool):
            raise ValueError(message)
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(message) from exc
        if number < minimum or number > maximum:
            raise ValueError(message)
        return number

    @classmethod
    def _player_manifest_assignments(cls, payload: Any, *, agent_id: str) -> dict[str, dict[str, Any]]:
        """Return the screen facts to which Player reports are bound.

        The Gateway intentionally does not possess the WebAdmin private key.
        It can nevertheless bind untrusted desktop telemetry to the exact,
        immutable payload that WebAdmin signed and stored for this Agent.  This
        helper is used on both ingress and report paths so a malformed payload
        cannot become an authorization oracle later.
        """
        if not isinstance(payload, dict) or cls._safe_player_text(payload.get("AgentId"), maximum=160) != agent_id:
            raise ValueError("Stored media manifest invalid")
        raw_screens = payload.get("Screens")
        if not isinstance(raw_screens, list) or len(raw_screens) > 32:
            raise ValueError("Stored media manifest invalid")

        assignments: dict[str, dict[str, Any]] = {}
        output_bindings: set[tuple[str, str]] = set()
        for raw in raw_screens:
            if not isinstance(raw, dict):
                raise ValueError("Stored media manifest invalid")
            screen_id = cls._safe_player_text(raw.get("ScreenId"), maximum=160)
            output_key = cls._safe_player_text(raw.get("OutputKey"), maximum=160)
            policy = raw.get("Policy") if isinstance(raw.get("Policy"), dict) else {}
            target_kind = cls._safe_player_text(
                raw.get("TargetKind") or policy.get("TargetKind") or "PHYSICAL_CONNECTOR",
                maximum=64,
            ).upper()
            if target_kind not in PLAYER_TARGET_KINDS:
                raise ValueError("Stored media manifest invalid")
            expected_physical = target_kind == "PHYSICAL_CONNECTOR"
            physical_output = policy.get("PhysicalOutput", expected_physical)
            if not isinstance(physical_output, bool) or physical_output != expected_physical:
                raise ValueError("Stored media manifest invalid")
            expected_session = (
                "PERSISTENT_PHYSICAL_OUTPUT" if expected_physical else "LOCAL_WAYLAND_SESSION"
            )
            session_policy = cls._safe_player_text(
                policy.get("SessionIndependence") or expected_session, maximum=80,
            ).upper()
            if session_policy != expected_session:
                raise ValueError("Stored media manifest invalid")
            output_identity = cls._safe_player_text(
                policy.get("OutputIdentity") or output_key, maximum=160,
            )
            output_binding = (target_kind, output_identity.casefold())
            campaign_id = cls._safe_player_text(raw.get("CampaignId"), maximum=160)
            revision_no = cls._safe_player_integer(
                raw.get("RevisionNo"), minimum=1, maximum=2_147_483_647,
                message="Stored media manifest invalid",
            )
            playlist = raw.get("Playlist")
            if not screen_id or not output_key or not campaign_id or not isinstance(playlist, list) or not playlist or len(playlist) > 120:
                raise ValueError("Stored media manifest invalid")
            if screen_id in assignments or output_binding in output_bindings:
                raise ValueError("Stored media manifest invalid")

            videos: dict[str, str] = {}
            for item in playlist:
                if not isinstance(item, dict):
                    raise ValueError("Stored media manifest invalid")
                file_name = cls._safe_player_text(item.get("FileName"), maximum=200)
                digest = cls._safe_player_text(item.get("Sha256"), maximum=64).lower()
                # Phase 2's cache convention is SHA-256-addressed.  Requiring
                # the canonical name prevents the Player report from smuggling
                # arbitrary filesystem-looking identifiers into its audit row.
                if not _SHA256_RE.fullmatch(digest) or file_name != f"{digest}.mp4" or file_name in videos:
                    raise ValueError("Stored media manifest invalid")
                videos[file_name] = digest

            assignments[screen_id] = {
                "campaign_id": campaign_id,
                "revision_no": revision_no,
                "output_key": output_key,
                "target_kind": target_kind,
                "playlist_items": len(playlist),
                "videos": videos,
            }
            output_bindings.add(output_binding)
        return assignments

    def put_agent_media_manifest(self, agent_id: str, envelope: dict[str, Any]) -> dict[str, Any]:
        """Persist one WebAdmin-signed, immutable Player manifest.

        The Gateway validates canonical bytes and bounded envelope structure but
        deliberately never receives WebAdmin's private signing key.  The Agent
        validates Ed25519 again before it lets the isolated Player use content.
        """
        clean_agent = self._safe_player_text(agent_id, maximum=160)
        if not clean_agent or not isinstance(envelope, dict):
            raise ValueError("Agent/media manifest invalid")
        if str(envelope.get("Schema") or "") != PLAYER_MANIFEST_SCHEMA:
            raise ValueError("Media manifest schema invalid")
        payload = envelope.get("Payload")
        if not isinstance(payload, dict) or str(payload.get("AgentId") or "") != clean_agent:
            raise ValueError("Media manifest agent mismatch")
        version = self._safe_player_integer(
            envelope.get("ManifestVersion"), minimum=1, maximum=2_147_483_647,
            message="Media manifest version invalid",
        )
        digest = self._safe_player_text(envelope.get("ManifestSha256"), maximum=64).lower()
        signature = self._safe_player_text(envelope.get("Signature"), maximum=512)
        key_id = self._safe_player_text(envelope.get("KeyId"), maximum=160)
        if not _SHA256_RE.fullmatch(digest) or not key_id:
            raise ValueError("Media manifest identity invalid")
        try:
            signature_bytes = base64.b64decode(signature, validate=True)
        except Exception as exc:
            raise ValueError("Media manifest signature invalid") from exc
        if len(signature_bytes) != 64:
            raise ValueError("Media manifest signature invalid")
        document = self._canonical_media_manifest(payload)
        if len(document) > 256 * 1024 or sha256_bytes(document).lower() != digest:
            raise ValueError("Media manifest integrity invalid")
        # Validate the precise screen/output/video shape before persistence.
        # This is not signature verification (the private key stays in
        # WebAdmin); it is a defensive schema gate for the immutable payload
        # that later authorizes Player telemetry.
        self._player_manifest_assignments(payload, agent_id=clean_agent)
        self.ensure_runtime_schema()
        stamp = now_iso()
        with self.connect() as con:
            if con.execute("SELECT 1 FROM agents WHERE agent_id=?", (clean_agent,)).fetchone() is None:
                raise ValueError("Agent not found")
            # Idempotency is version-scoped. A resolved state can legitimately
            # recur after another version, so digest-only deduplication would
            # return a stale envelope that the Agent rejects as a replay.
            existing = con.execute(
                "SELECT * FROM agent_media_manifests WHERE agent_id=? AND manifest_version=?",
                (clean_agent, str(version)),
            ).fetchone()
            if existing is not None:
                if str(existing["manifest_sha256"]) != digest:
                    raise ValueError("Media manifest version conflict")
                return {
                    "agent_id": clean_agent,
                    "manifest_version": int(existing["manifest_version"]),
                    "manifest_sha256": str(existing["manifest_sha256"]),
                    "key_id": str(existing["key_id"]),
                    "signature": str(existing["signature"]),
                    "created_at": str(existing["created_at"]),
                    "created": False,
                }
            latest = con.execute(
                "SELECT MAX(CAST(manifest_version AS INTEGER)) AS version FROM agent_media_manifests WHERE agent_id=?", (clean_agent,)
            ).fetchone()
            if latest is not None and latest["version"] is not None and version <= int(latest["version"]):
                raise ValueError("Media manifest version is not monotonic")
            con.execute(
                """INSERT INTO agent_media_manifests(agent_id,manifest_version,manifest_sha256,key_id,signature,manifest_json,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (clean_agent, str(version), digest, key_id, signature, document.decode("utf-8"), stamp),
            )
        return {
            "agent_id": clean_agent, "manifest_version": version, "manifest_sha256": digest,
            "key_id": key_id, "signature": signature, "created_at": stamp, "created": True,
        }

    def get_agent_media_manifest(self, agent_id: str) -> dict[str, Any] | None:
        clean_agent = self._safe_player_text(agent_id, maximum=160)
        with self.connect() as con:
            row = con.execute(
                """SELECT * FROM agent_media_manifests WHERE agent_id=?
                   ORDER BY created_at DESC,rowid DESC LIMIT 1""", (clean_agent,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            payload = json.loads(str(result.pop("manifest_json") or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Stored media manifest invalid") from exc
        return {
            "Schema": PLAYER_MANIFEST_SCHEMA,
            "ManifestVersion": int(result["manifest_version"]),
            "Payload": payload,
            "ManifestSha256": str(result["manifest_sha256"]),
            "Signature": str(result["signature"]),
            "KeyId": str(result["key_id"]),
        }

    def report_agent_media_player(self, agent_id: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        """Store bounded, append-only Player status events for one Agent."""
        clean_agent = self._safe_player_text(agent_id, maximum=160)
        report = body.get("Player") if isinstance(body.get("Player"), dict) else body
        if not isinstance(report, dict) or str(report.get("Schema") or "") != PLAYER_STATUS_SCHEMA:
            raise ValueError("Player report invalid")
        version = self._safe_player_integer(
            report.get("ManifestVersion") or 0, minimum=0, maximum=2_147_483_647,
            message="Player report version invalid",
        )
        # A newly installed Agent has no accepted manifest yet. Its heartbeat
        # remains useful, but there is no screen event to persist or authorize.
        if version <= 0:
            return []
        reports = report.get("Screens")
        if not isinstance(reports, list) or len(reports) > 32:
            raise ValueError("Player report invalid")
        self.ensure_runtime_schema()
        with self.connect() as con:
            # Gateway connections use autocommit for normal short operations.
            # A multi-screen report must nevertheless be all-or-nothing: do
            # not retain a first screen if a later untrusted item is rejected.
            con.execute("BEGIN IMMEDIATE")
            manifest = con.execute(
                "SELECT manifest_sha256,manifest_json FROM agent_media_manifests WHERE agent_id=? AND manifest_version=?",
                (clean_agent, version),
            ).fetchone()
            if manifest is None:
                raise ValueError("Player manifest unknown")
            reported_digest = self._safe_player_text(report.get("ManifestSha256"), maximum=64).lower()
            if not _SHA256_RE.fullmatch(reported_digest) or reported_digest != str(manifest["manifest_sha256"]):
                raise ValueError("Player report manifest mismatch")
            try:
                manifest_payload = json.loads(str(manifest["manifest_json"] or "{}"))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("Stored media manifest invalid") from exc
            # The row is append-only, but verify its canonical digest again so
            # a damaged database cannot turn a stale/corrupt payload into an
            # authority for a desktop-side report.
            if sha256_bytes(self._canonical_media_manifest(manifest_payload)).lower() != str(manifest["manifest_sha256"]):
                raise ValueError("Stored media manifest invalid")
            assignments = self._player_manifest_assignments(manifest_payload, agent_id=clean_agent)
            saved: list[dict[str, Any]] = []
            seen_screens: set[str] = set()
            for raw in reports:
                if not isinstance(raw, dict):
                    raise ValueError("Player report item invalid")
                screen_id = self._safe_player_text(raw.get("ScreenId"), maximum=160)
                state = self._safe_player_text(raw.get("State") or "UNKNOWN", maximum=32).upper()
                campaign_id = self._safe_player_text(raw.get("CampaignId"), maximum=160)
                playlist_items = self._safe_player_integer(
                    raw.get("PlaylistItems"), minimum=0, maximum=120, message="Player report number invalid",
                )
                playlist = str(playlist_items)
                current_video = self._safe_player_text(raw.get("CurrentVideo"), maximum=200)
                vlc = report.get("VLC") if isinstance(report.get("VLC"), dict) else {}
                vlc_version = self._safe_player_text(vlc.get("Version"), maximum=80)
                if not screen_id or not _PLAYER_STATE_RE.fullmatch(state):
                    raise ValueError("Player report content invalid")
                if screen_id in seen_screens:
                    raise ValueError("Player report assignment mismatch")
                expected = assignments.get(screen_id)
                revision_no = self._safe_player_integer(
                    raw.get("RevisionNo"), minimum=0, maximum=2_147_483_647, message="Player report number invalid",
                )
                output_key = self._safe_player_text(raw.get("OutputKey"), maximum=160)
                reported_target_kind = self._safe_player_text(
                    raw.get("TargetKind") or (expected or {}).get("target_kind") or "PHYSICAL_CONNECTOR",
                    maximum=64,
                ).upper()
                if (
                    expected is None
                    or campaign_id != str(expected["campaign_id"])
                    or revision_no != int(expected["revision_no"])
                    or output_key != str(expected["output_key"])
                    or reported_target_kind != str(expected["target_kind"])
                    or playlist_items != int(expected["playlist_items"])
                    or current_video not in expected["videos"]
                ):
                    # Deliberately generic: none of the signed assignment
                    # fields, operator metadata, or Player-provided content is
                    # reflected to an authenticated-but-untrusted desktop.
                    raise ValueError("Player report assignment mismatch")
                video_sha = str(expected["videos"][current_video])
                free_bytes = self._safe_player_integer(
                    report.get("FreeBytes"), minimum=0, maximum=9_223_372_036_854_775_807,
                    message="Player report number invalid",
                )
                graphics_in = report.get("Graphics") if isinstance(report.get("Graphics"), dict) else {}
                graphics = {
                    "state": self._safe_player_text(graphics_in.get("State"), maximum=80),
                    "output_count": self._safe_player_integer(
                        graphics_in.get("OutputCount", 0), minimum=0, maximum=64, message="Player report number invalid",
                    ),
                    "output_key": output_key,
                    "target_kind": reported_target_kind,
                }
                detail = {
                    "last_success": self._safe_player_text(raw.get("LastSuccessAt"), maximum=80),
                    "error": self._safe_player_text(raw.get("Error") or report.get("LastSyncError"), maximum=500),
                    "current_video": current_video,
                }
                report_id = "mpr-" + secrets.token_hex(16)
                stamp = now_iso()
                con.execute(
                    """INSERT INTO agent_media_player_reports(report_id,agent_id,manifest_version,screen_id,campaign_id,revision_no,state,
                       video_sha256,playlist,free_bytes,vlc_version,graphics_json,detail_json,reported_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (report_id, clean_agent, str(version), screen_id, campaign_id, revision_no, state, video_sha, playlist,
                     free_bytes, vlc_version, json.dumps(graphics, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
                     json.dumps(detail, ensure_ascii=False, separators=(",", ":"), sort_keys=True), stamp),
                )
                saved.append({"report_id": report_id, "screen_id": screen_id, "state": state, "reported_at": stamp})
                seen_screens.add(screen_id)
        return saved

    def list_agent_media_player_reports(self, *, agent_id: str = "", limit: int = 200) -> list[dict[str, Any]]:
        clean_agent = self._safe_player_text(agent_id, maximum=160) if agent_id else ""
        bounded = max(1, min(int(limit), 1000))
        with self.connect() as con:
            if clean_agent:
                rows = con.execute(
                    "SELECT * FROM agent_media_player_reports WHERE agent_id=? ORDER BY reported_at DESC,rowid DESC LIMIT ?",
                    (clean_agent, bounded),
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM agent_media_player_reports ORDER BY reported_at DESC,rowid DESC LIMIT ?", (bounded,)
                ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["graphics"] = json.loads(str(item.pop("graphics_json") or "{}"))
                item["detail"] = json.loads(str(item.pop("detail_json") or "{}"))
            except (TypeError, ValueError, json.JSONDecodeError):
                item["graphics"], item["detail"] = {}, {}
            result.append(item)
        return result

    def report_agent_config_status(self, agent_id: str, *, version: int, status: str, detail: str = "") -> None:
        resolved = self.resolve_agent_target(agent_id)
        resolved_id = str(resolved["agent_id"]) if resolved is not None else str(agent_id or "").strip()
        if not resolved_id:
            return
        state = str(status or "UNKNOWN").upper()[:40]
        with self.connect() as con:
            con.execute(
                """INSERT INTO agent_config_status(agent_id,applied_version,status,detail,reported_at)
                   VALUES(?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET
                   applied_version=excluded.applied_version,status=excluded.status,detail=excluded.detail,reported_at=excluded.reported_at""",
                (resolved_id, max(0, int(version)), state, str(detail or "")[:4000], now_iso()),
            )

    def request_agent_update(self, agent_id: str, *, actor: str = "admin", target_version: str = "") -> dict[str, Any]:
        """Persist a one-shot request for the latest approved stable release."""
        target = self.resolve_agent_target(agent_id)
        if target is None:
            raise ValueError(f"AGENT_TARGET_NOT_FOUND_OR_AMBIGUOUS: {agent_id}")
        resolved_id = str(target["agent_id"])
        release = self.best_release(
            str(target["platform"] or "").lower(),
            str(target["architecture"] or "").lower(),
            "stable",
            approved_only=True,
        )
        if release is None:
            raise ValueError("AGENT_UPDATE_NO_APPROVED_RELEASE: no existe release stable aprobada para esta plataforma/arquitectura")
        selected = str(release.get("version") or "").strip()
        requested = str(target_version or "").strip()
        if requested and requested != selected:
            raise ValueError(f"AGENT_UPDATE_TARGET_CHANGED: solicitada={requested} disponible={selected}")
        request_id = "aur-" + secrets.token_hex(12)
        stamp = now_iso()
        current = str(target["agent_version"] or "")
        state = "COMPLETED" if version_key(current) >= version_key(selected) else "REQUESTED"
        completed_at = stamp if state == "COMPLETED" else None
        with self.connect() as con:
            con.execute(
                "UPDATE agent_update_requests SET status='SUPERSEDED',detail='Reemplazada por una solicitud posterior' "
                "WHERE agent_id=? AND status IN ('REQUESTED','DELIVERED')",
                (resolved_id,),
            )
            con.execute(
                """INSERT INTO agent_update_requests(
                   request_id,agent_id,target_version,requested_at,requested_by,status,completed_at,current_version,detail
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (request_id, resolved_id, selected, stamp, str(actor or "admin")[:120], state, completed_at, current,
                 "El Agent ya reporta esta versión." if state == "COMPLETED" else "Esperando comprobación autenticada del Agent."),
            )
        return self.get_agent_update_request(resolved_id) or {}

    def get_agent_update_request(self, agent_id: str) -> Optional[dict[str, Any]]:
        resolved = self.resolve_agent_target(agent_id)
        resolved_id = str(resolved["agent_id"]) if resolved is not None else str(agent_id or "").strip()
        if not resolved_id:
            return None
        with self.connect() as con:
            row = con.execute(
                "SELECT * FROM agent_update_requests WHERE agent_id=? ORDER BY requested_at DESC,request_id DESC LIMIT 1",
                (resolved_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def observe_agent_update_request(self, agent_id: str, current_version: str, *, update_state: str = "") -> Optional[dict[str, Any]]:
        """Advance the latest request from REQUESTED to DELIVERED/COMPLETED/FAILED."""
        request = self.get_agent_update_request(agent_id)
        if not request:
            return None
        state = str(request.get("status") or "").upper()
        if state not in {"REQUESTED", "DELIVERED"}:
            return request
        target = str(request.get("target_version") or "")
        reported = str(current_version or "")
        agent_state = str(update_state or "").upper()
        stamp = now_iso()
        if target and version_key(reported) >= version_key(target):
            next_state, detail = "COMPLETED", f"Agent confirmó versión {reported}."
        elif agent_state in {"UPDATE_ERROR", "ROLLED_BACK"}:
            next_state, detail = "FAILED", f"El Agent reportó {agent_state}; revise su diagnóstico antes de reintentar."
        else:
            next_state, detail = "DELIVERED", "Solicitud entregada; el Agent comprobará firma, SHA-256 y compatibilidad."
        with self.connect() as con:
            con.execute(
                """UPDATE agent_update_requests SET status=?,delivered_at=COALESCE(delivered_at,?),
                   completed_at=CASE WHEN ? IN ('COMPLETED','FAILED') THEN ? ELSE completed_at END,
                   current_version=?,detail=? WHERE request_id=?""",
                (next_state, stamp, next_state, stamp, reported, detail, str(request.get("request_id") or "")),
            )
        return self.get_agent_update_request(agent_id)

    @staticmethod
    def _offline_vlc_public_request(row: sqlite3.Row | dict[str, Any] | None) -> dict[str, Any]:
        """Return an administrative-safe install-request record.

        The signed envelope is intentionally absent: it is bearer-delivered
        only to the authenticated Agent bound to this row.
        """
        if row is None:
            return {}
        value = dict(row)
        return {
            "RequestId": str(value.get("request_id") or "")[:160],
            "AgentId": str(value.get("agent_id") or "")[:160],
            "CatalogSha256": str(value.get("catalog_sha256") or "")[:64].lower(),
            "ExpiresAt": str(value.get("expires_at") or "")[:80],
            "Status": str(value.get("status") or "")[:80].upper(),
            "RequestedAt": str(value.get("requested_at") or "")[:80],
            "RequestedBy": str(value.get("requested_by") or "")[:120],
            "DeliveredAt": str(value.get("delivered_at") or "")[:80],
            "StartedAt": str(value.get("started_at") or "")[:80],
            "ReportedAt": str(value.get("reported_at") or "")[:80],
            "CompletedAt": str(value.get("completed_at") or "")[:80],
            "Detail": str(value.get("detail") or "")[:240],
        }

    @staticmethod
    def _offline_vlc_authorization(envelope: Any, *, agent_id: str) -> tuple[dict[str, Any], str, int]:
        """Validate non-cryptographic routing invariants of a signed envelope.

        WebAdmin holds the private release key and the Agent performs the
        authoritative Ed25519 verification immediately before installation.
        The Gateway only validates strict routing/expiry invariants so it never
        becomes a signing authority or an arbitrary command relay.
        """
        if not isinstance(envelope, dict):
            raise ValueError("VLC_OFFLINE_AUTHORIZATION_REQUIRED")
        try:
            encoded = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("VLC_OFFLINE_AUTHORIZATION_INVALID") from exc
        if not encoded or len(encoded) > _OFFLINE_VLC_MAX_AUTHORIZATION_BYTES:
            raise ValueError("VLC_OFFLINE_AUTHORIZATION_SIZE_INVALID")
        if str(envelope.get("Schema") or "") != OFFLINE_VLC_AUTHORIZATION_SCHEMA:
            raise ValueError("VLC_OFFLINE_AUTHORIZATION_SCHEMA_INVALID")
        payload = envelope.get("Payload")
        signature = str(envelope.get("Signature") or "").strip()
        if not isinstance(payload, dict) or not signature or len(signature) > 1024:
            raise ValueError("VLC_OFFLINE_AUTHORIZATION_ENVELOPE_INVALID")
        request_id = str(payload.get("RequestId") or "").strip()
        catalog_sha256 = str(payload.get("CatalogSha256") or "").strip().lower()
        if not _OFFLINE_VLC_REQUEST_ID_RE.fullmatch(request_id):
            raise ValueError("VLC_OFFLINE_REQUEST_ID_INVALID")
        if not _SHA256_RE.fullmatch(catalog_sha256):
            raise ValueError("VLC_OFFLINE_CATALOG_HASH_INVALID")
        if str(payload.get("Action") or "") != "INSTALL" or payload.get("GplAcknowledged") is not True:
            raise ValueError("VLC_OFFLINE_AUTHORIZATION_SCOPE_INVALID")
        if str(payload.get("AgentId") or "").strip() != str(agent_id or "").strip():
            raise ValueError("VLC_OFFLINE_AUTHORIZATION_AGENT_MISMATCH")
        try:
            expiry = dt.datetime.fromisoformat(str(payload.get("ExpiresAt") or "").replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError("naive")
            expiry_unix = int(expiry.astimezone(dt.timezone.utc).timestamp())
        except Exception as exc:
            raise ValueError("VLC_OFFLINE_AUTHORIZATION_EXPIRY_INVALID") from exc
        current = int(time.time())
        if expiry_unix <= current or expiry_unix > current + 24 * 60 * 60:
            raise ValueError("VLC_OFFLINE_AUTHORIZATION_EXPIRED_OR_TOO_LONG")
        return dict(payload), hashlib.sha256(encoded).hexdigest(), expiry_unix

    def _expire_offline_vlc_requests(self, con: sqlite3.Connection, *, now_unix: int | None = None) -> None:
        current = int(now_unix if now_unix is not None else time.time())
        stamp = dt.datetime.fromtimestamp(current, tz=dt.timezone.utc).isoformat(timespec="seconds")
        con.execute(
            """UPDATE agent_vlc_offline_install_requests
               SET status='EXPIRED', completed_at=COALESCE(completed_at,?), detail='Autorización vencida antes de completar.'
               WHERE status IN ('REQUESTED','DELIVERED','DEFERRED') AND expires_unix<=?""",
            (stamp, current),
        )
        con.execute(
            """UPDATE agent_vlc_offline_install_requests
               SET status='EXPIRED', completed_at=COALESCE(completed_at,?),
                   detail='Instalación VLC expirada por watchdog; puede emitir una nueva autorización.'
               WHERE status='RUNNING' AND (
                    (started_unix IS NOT NULL AND started_unix<=?)
                    OR (reported_unix IS NOT NULL AND reported_unix<=?)
                    OR (started_unix IS NULL AND expires_unix<=?)
               )""",
            (
                stamp,
                current - _OFFLINE_VLC_RUNNING_MAX_SECONDS,
                current - _OFFLINE_VLC_RUNNING_STALE_SECONDS,
                current - _OFFLINE_VLC_RUNNING_MAX_SECONDS,
            ),
        )

    def request_agent_offline_vlc_install(
        self, agent_id: str, authorization: dict[str, Any], *, actor: str = "admin"
    ) -> dict[str, Any]:
        """Persist a one-shot signed VLC install request for one exact Agent.

        The Agent's last authenticated capability must report the exact catalog
        digest. This prevents approving an installation against a stale or
        substituted endpoint kit even before the Agent's own signature check.
        """
        target = self.resolve_agent_target(agent_id)
        if target is None:
            raise ValueError(f"AGENT_TARGET_NOT_FOUND_OR_AMBIGUOUS: {agent_id}")
        resolved_id = str(target["agent_id"])
        payload, authorization_sha256, expiry_unix = self._offline_vlc_authorization(authorization, agent_id=resolved_id)
        try:
            capabilities = json.loads(str(target["capabilities_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            capabilities = {}
        player = capabilities.get("Player") if isinstance(capabilities, dict) else {}
        offline = player.get("OfflineVlc") if isinstance(player, dict) else {}
        reported_hash = str(offline.get("CatalogSha256") or "").strip().lower() if isinstance(offline, dict) else ""
        if str(offline.get("State") or "") != "READY_FOR_EXPLICIT_INSTALL" or reported_hash != str(payload["CatalogSha256"]):
            raise ValueError("VLC_OFFLINE_AGENT_CATALOG_NOT_READY_OR_CHANGED")
        request_id = str(payload["RequestId"])
        stamp = now_iso()
        serialized = json.dumps(authorization, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self.connect() as con:
            # ``GatewayDB`` uses short-lived SQLite connections in autocommit
            # mode.  Without an explicit write transaction, two WebAdmin
            # requests arriving together can both observe "no active request"
            # and insert separate authorisations for the same Agent.  Acquire
            # the write reservation before expiring/checking/inserting so the
            # one-active-request invariant is atomic across processes too.
            con.execute("BEGIN IMMEDIATE")
            self._expire_offline_vlc_requests(con)
            active = con.execute(
                """SELECT request_id,status FROM agent_vlc_offline_install_requests WHERE agent_id=?
                   AND status IN ('REQUESTED','DELIVERED','DEFERRED','RUNNING')
                   ORDER BY requested_at DESC LIMIT 1""",
                (resolved_id,),
            ).fetchone()
            if active is not None:
                raise ValueError("VLC_OFFLINE_INSTALL_ALREADY_ACTIVE")
            con.execute(
                """INSERT INTO agent_vlc_offline_install_requests(
                   request_id,agent_id,authorization_json,authorization_sha256,catalog_sha256,expires_at,expires_unix,
                   status,requested_at,requested_by,detail
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (request_id, resolved_id, serialized, authorization_sha256, str(payload["CatalogSha256"]),
                 str(payload["ExpiresAt"]), expiry_unix, "REQUESTED", stamp, str(actor or "admin")[:120],
                 "Esperando heartbeat autenticado del Agent."),
            )
        return self.get_agent_offline_vlc_install_request(resolved_id) or {}

    def get_agent_offline_vlc_install_request(self, agent_id: str) -> Optional[dict[str, Any]]:
        target = self.resolve_agent_target(agent_id)
        resolved_id = str(target["agent_id"]) if target is not None else str(agent_id or "").strip()
        if not resolved_id:
            return None
        with self.connect() as con:
            self._expire_offline_vlc_requests(con)
            row = con.execute(
                "SELECT * FROM agent_vlc_offline_install_requests WHERE agent_id=? ORDER BY requested_at DESC,rowid DESC LIMIT 1",
                (resolved_id,),
            ).fetchone()
        return self._offline_vlc_public_request(row) if row is not None else None

    def deliver_agent_offline_vlc_install_request(self, agent_id: str) -> dict[str, Any]:
        """Return the one matching envelope only to its authenticated Agent."""
        resolved_id = str(agent_id or "").strip()
        if not resolved_id:
            return {}
        with self.connect() as con:
            self._expire_offline_vlc_requests(con)
            row = con.execute(
                """SELECT * FROM agent_vlc_offline_install_requests WHERE agent_id=?
                   AND status IN ('REQUESTED','DELIVERED','DEFERRED','RUNNING')
                   ORDER BY requested_at DESC,rowid DESC LIMIT 1""",
                (resolved_id,),
            ).fetchone()
            if row is None:
                return {}
            value = dict(row)
            status = str(value.get("status") or "").upper()
            if status == "REQUESTED":
                con.execute(
                    "UPDATE agent_vlc_offline_install_requests SET status='DELIVERED',delivered_at=COALESCE(delivered_at,?),detail='Autorización entregada al Agent autenticado.' WHERE request_id=?",
                    (now_iso(), str(value["request_id"])),
                )
                status = "DELIVERED"
            response = {"RequestId": str(value["request_id"]), "State": status}
            if status in {"DELIVERED", "DEFERRED"}:
                try:
                    envelope = json.loads(str(value["authorization_json"]))
                except (TypeError, ValueError, json.JSONDecodeError):
                    con.execute(
                        "UPDATE agent_vlc_offline_install_requests SET status='FAILED',completed_at=?,detail='Autorización almacenada inválida.' WHERE request_id=?",
                        (now_iso(), str(value["request_id"])),
                    )
                    return {"RequestId": str(value["request_id"]), "State": "FAILED"}
                response["Authorization"] = envelope
            return response

    def observe_agent_offline_vlc_install(
        self, agent_id: str, request_id: str, *, state: str, detail: str = ""
    ) -> Optional[dict[str, Any]]:
        """Accept a bounded result only from the Agent that owns the request."""
        resolved_id = str(agent_id or "").strip()
        clean_id = str(request_id or "").strip()
        clean_state = str(state or "").upper().strip()
        if not _OFFLINE_VLC_REQUEST_ID_RE.fullmatch(clean_id) or clean_state not in _OFFLINE_VLC_AGENT_REPORT_STATES:
            raise ValueError("VLC_OFFLINE_STATUS_INVALID")
        with self.connect() as con:
            self._expire_offline_vlc_requests(con)
            row = con.execute(
                "SELECT * FROM agent_vlc_offline_install_requests WHERE request_id=? AND agent_id=?",
                (clean_id, resolved_id),
            ).fetchone()
            if row is None:
                raise ValueError("VLC_OFFLINE_STATUS_REQUEST_NOT_FOUND")
            previous = str(row["status"] or "").upper()
            if previous in _OFFLINE_VLC_TERMINAL_STATES:
                return self._offline_vlc_public_request(row)
            stamp = now_iso()
            stamp_unix = int(time.time())
            terminal = clean_state in {"INSTALLED", "FAILED", "CANCELLED", "EXPIRED"}
            con.execute(
                """UPDATE agent_vlc_offline_install_requests SET status=?,reported_at=?,reported_unix=?,
                   started_at=CASE WHEN ?='RUNNING' THEN COALESCE(started_at,?) ELSE started_at END,
                   started_unix=CASE WHEN ?='RUNNING' THEN COALESCE(started_unix,?) ELSE started_unix END,
                   completed_at=CASE WHEN ? THEN ? ELSE completed_at END,detail=?
                   WHERE request_id=? AND agent_id=?""",
                (
                    clean_state, stamp, stamp_unix,
                    clean_state, stamp, clean_state, stamp_unix,
                    1 if terminal else 0, stamp, str(detail or "")[:240], clean_id, resolved_id,
                ),
            )
        return self.get_agent_offline_vlc_install_request(resolved_id)

    def configuration_response(self, agent_id: str, current_version: int) -> dict[str, Any]:
        desired = self.get_agent_configuration(agent_id)
        if not desired:
            return {"Status": "NO_CONFIGURATION", "CurrentVersion": max(0, int(current_version)), "DesiredVersion": 0}
        desired_version = int(desired.get("version") or 0)
        if desired_version <= max(0, int(current_version)):
            return {"Status": "CURRENT", "CurrentVersion": max(0, int(current_version)), "DesiredVersion": desired_version}
        return {
            "Status": "UPDATE_AVAILABLE",
            "CurrentVersion": max(0, int(current_version)),
            "DesiredVersion": desired_version,
            "Configuration": desired,
        }

    def authenticate_agent(self, bearer: str) -> Optional[sqlite3.Row]:
        digest = token_hash(bearer)
        with self.connect() as con:
            return con.execute(
                "SELECT * FROM agents WHERE token_hash=?", (digest,)
            ).fetchone()

    def set_agent_mtls_fingerprint(self, agent_id: str, fingerprint: str) -> None:
        """Bind the latest issued client certificate to one enrolled Agent.

        The Gateway CA is shared by the fleet, so merely checking that a
        certificate chains to that CA is not sufficient to bind a TLS client
        to its bearer token.  Persisting the leaf SHA-256 fingerprint closes
        that identity-confusion gap while keeping migration additive.
        """
        resolved = self.resolve_agent_target(agent_id)
        resolved_id = str(resolved["agent_id"]) if resolved is not None else str(agent_id or "").strip()
        clean = "".join(str(fingerprint or "").split()).lower()
        if not resolved_id or len(clean) != 64 or any(ch not in "0123456789abcdef" for ch in clean):
            raise ValueError("AGENT_MTLS_FINGERPRINT_INVALID")
        with self.connect() as con:
            changed = con.execute(
                "UPDATE agents SET mtls_fingerprint=? WHERE agent_id=?", (clean, resolved_id)
            ).rowcount
        if not changed:
            raise ValueError("AGENT_MTLS_AGENT_NOT_FOUND")

    def heartbeat(
        self, agent_id: str, hostname: str, version: str,
        *, agent_name: str = "", protocol_version: str = "", platform_name: str = "",
        architecture: str = "", host_profile: str = "", remote_ip: str = "",
        capabilities: Optional[dict[str, Any]] = None, diagnostics: Optional[dict[str, Any]] = None,
    ) -> None:
        resolved = self.resolve_agent_target(agent_id)
        target_agent_id = str(resolved["agent_id"]) if resolved is not None else str(agent_id)
        safe_diag = redact(diagnostics or {}) if isinstance(diagnostics, dict) else {}
        if safe_diag and len(json.dumps(safe_diag, ensure_ascii=False, default=str).encode("utf-8")) > 64 * 1024:
            safe_diag = {
                "state": {"status": "DIAGNOSTIC_ERROR", "connectivity_state": "DIAGNOSTIC_ERROR"},
                "last_error": "Diagnostic payload exceeded 64 KiB and was discarded by the Gateway.",
            }
        # Receipt of this heartbeat proves TCP + TLS + API + bearer authentication
        # for the endpoint actually used. Preserve previous diagnostic context but
        # mark these checks as validated by the Gateway itself.
        if safe_diag:
            for section in ("state", "network", "timestamps", "checks"):
                if not isinstance(safe_diag.get(section), dict):
                    safe_diag[section] = {}
            prior_state = str(safe_diag["state"].get("connectivity_state") or safe_diag["state"].get("status") or "").upper()
            if prior_state and prior_state not in {"ONLINE", "CONNECTED", "ACTIVE", "BUSY"}:
                safe_diag["state"]["previous_connectivity_state"] = prior_state
            safe_diag["state"].update({"status": "ONLINE", "connectivity_state": "CONNECTED", "gateway_connected": True})
            safe_diag["network"]["gateway_observed_ip"] = str(remote_ip or "").strip()
            safe_diag["timestamps"]["last_heartbeat"] = now_iso()
            checks = safe_diag["checks"]
            for name in ("tcp", "tls", "api", "authentication"):
                checks[name] = {"status": "OK", "detail": "Validado por el Gateway al recibir este heartbeat."}
        with self.connect() as con:
            con.execute(
                """UPDATE agents SET last_seen=?,agent_name=?,hostname=?,agent_version=?,protocol_version=?,
                   platform=?,architecture=?,host_profile=?,capabilities_json=?,diagnostics_json=?,last_remote_ip=?,status='ONLINE'
                   WHERE agent_id=?""",
                (now_iso(), agent_name, hostname, version, protocol_version, platform_name, architecture,
                 host_profile, json.dumps(capabilities or {}, ensure_ascii=False),
                 json.dumps(safe_diag, ensure_ascii=False) if safe_diag else None,
                 str(remote_ip or "").strip(), target_agent_id),
            )
        update_diag = safe_diag.get("update") if isinstance(safe_diag.get("update"), dict) else {}
        self.observe_agent_update_request(target_agent_id, version, update_state=str(update_diag.get("state") or ""))

    def list_agents(self) -> list[dict[str, Any]]:
        # Fleet view must remain O(1) database connections.  The previous code
        # performed two additional SQLite opens/queries per Agent (N+1), which
        # becomes 181 DB transactions for a 90-endpoint fleet on every refresh.
        with self.connect() as con:
            rows=[dict(x) for x in con.execute(
                "SELECT * FROM agents ORDER BY site_code, COALESCE(agent_name,''), COALESCE(hostname,''), agent_id"
            ).fetchall()]
            desired_versions = {
                str(x["agent_id"]): int(x["version"] or 0)
                for x in con.execute(
                    "SELECT agent_id, MAX(version) AS version FROM agent_configurations GROUP BY agent_id"
                ).fetchall()
            }
            config_status = {
                str(x["agent_id"]): dict(x)
                for x in con.execute("SELECT * FROM agent_config_status").fetchall()
            }
            latest_update_requests = {
                str(x["agent_id"]): dict(x)
                for x in con.execute(
                    """SELECT r.* FROM agent_update_requests r
                       WHERE r.request_id=(
                         SELECT r2.request_id FROM agent_update_requests r2
                         WHERE r2.agent_id=r.agent_id
                         ORDER BY r2.requested_at DESC,r2.request_id DESC LIMIT 1
                        )"""
                ).fetchall()
            }
            self._expire_offline_vlc_requests(con)
            latest_offline_vlc_requests = {
                str(x["agent_id"]): self._offline_vlc_public_request(x)
                for x in con.execute(
                    """SELECT r.* FROM agent_vlc_offline_install_requests r
                       WHERE r.rowid=(
                         SELECT r2.rowid FROM agent_vlc_offline_install_requests r2
                         WHERE r2.agent_id=r.agent_id
                         ORDER BY r2.requested_at DESC,r2.rowid DESC LIMIT 1
                       )"""
                ).fetchall()
            }
        for row in rows:
            raw=row.pop("capabilities_json",None)
            try: row["Capabilities"]=json.loads(raw) if raw else {}
            except Exception: row["Capabilities"]={}
            diag_raw=row.pop("diagnostics_json",None)
            try: row["Diagnostics"]=redact(json.loads(diag_raw)) if diag_raw else {}
            except Exception as exc:
                row["Diagnostics"]={"state":{"status":"DIAGNOSTIC_ERROR"},"last_error":redact_error(exc)}
            aid = str(row.get("agent_id") or "")
            row["DesiredConfigVersion"] = int(desired_versions.get(aid, 0))
            row["ConfigStatus"] = config_status.get(aid) or {
                "agent_id": aid, "applied_version": 0, "status": "UNKNOWN", "detail": "", "reported_at": ""
            }
            row["UpdateRequest"] = latest_update_requests.get(aid) or {}
            row["OfflineVlcInstallRequest"] = latest_offline_vlc_requests.get(aid) or {}
        return rows

    def put_job(
        self, job_id: str, target: str, site_name: str, package: bytes, expected_hash: str,
        package_signature: str = "", package_key_id: str = "", site_code_hint: str = "",
    ) -> dict[str, Any]:
        temp = self.incoming_dir / f"job-{os.getpid()}-{threading.get_ident()}-{secrets.token_hex(4)}.part"
        temp.write_bytes(package)
        try:
            return self.put_job_file(
                job_id, target, site_name, temp, expected_hash,
                package_signature=package_signature,
                package_key_id=package_key_id,
                site_code_hint=site_code_hint,
                actual_hash=sha256_bytes(package),
            )
        finally:
            temp.unlink(missing_ok=True)

    def put_job_file(
        self, job_id: str, target: str, site_name: str, package: Path, expected_hash: str,
        package_signature: str = "", package_key_id: str = "", site_code_hint: str = "",
        actual_hash: str = "",
    ) -> dict[str, Any]:
        agent = self.resolve_agent_target(target)
        if agent is None:
            raise ValueError(f"AGENT_TARGET_NOT_FOUND_OR_AMBIGUOUS: {target}")
        agent_id = str(agent["agent_id"])
        site_code = str(site_code_hint or agent["site_code"] or "").strip()
        if site_code_hint and site_code != str(agent["site_code"]):
            raise ValueError(
                f"AGENT_SITE_MISMATCH: AgentId {agent_id} pertenece a {agent['site_code']}, no a {site_code_hint}"
            )
        package = Path(package)
        actual = str(actual_hash or sha256_file(package)).lower()
        if expected_hash and not consteq(actual.lower(), expected_hash.lower()):
            raise ValueError("Package SHA256 mismatch at gateway")
        job_dir = self.packages_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        path = job_dir / f"{agent_id}.zip"
        os.replace(package, path)
        stamp = now_iso()
        with self.connect() as con:
            con.execute(
                """INSERT INTO jobs(job_id,agent_id,site_code,site_name,status,created_at,updated_at,package_path,package_sha256,package_signature,package_key_id,cancel_requested)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,0)
                   ON CONFLICT(job_id,agent_id) DO UPDATE SET
                     site_code=excluded.site_code,site_name=excluded.site_name,status='QUEUED',created_at=excluded.created_at,
                     updated_at=excluded.updated_at,package_path=excluded.package_path,
                     package_sha256=excluded.package_sha256,package_signature=excluded.package_signature,
                     package_key_id=excluded.package_key_id,result_path=NULL,result_sha256=NULL,
                     cancel_requested=0,last_status_json=NULL,error=NULL,claimed_at=NULL,finished_at=NULL""",
                (job_id, agent_id, site_code, site_name or str(agent["site_name"] or ""), "QUEUED", stamp, stamp, str(path), actual, package_signature, package_key_id),
            )
        return {
            "JobId": job_id, "AgentId": agent_id, "SiteCode": site_code, "Status": "QUEUED",
            "PackageSha256": actual, "PackageSigned": bool(package_signature), "PackageKeyId": package_key_id,
        }

    def next_job(self, agent_id: str) -> Optional[dict[str, Any]]:
        with self.connect() as con:
            row = con.execute(
                """SELECT job_id,agent_id,site_code,site_name,status,created_at,package_sha256,package_signature,package_key_id,cancel_requested
                   FROM jobs WHERE agent_id=? AND status IN ('QUEUED','CLAIMED','RUNNING')
                   ORDER BY created_at LIMIT 1""",
                (agent_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_job(self, job_id: str, target: str) -> Optional[sqlite3.Row]:
        value = str(target or "").strip()
        with self.connect() as con:
            row = con.execute(
                "SELECT * FROM jobs WHERE job_id=? AND agent_id=?", (job_id, value)
            ).fetchone()
            if row is not None:
                return row
            rows = con.execute(
                "SELECT * FROM jobs WHERE job_id=? AND site_code=? ORDER BY agent_id", (job_id, value)
            ).fetchall()
            return rows[0] if len(rows) == 1 else None

    def list_job(self, job_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM jobs WHERE job_id=? ORDER BY site_code,agent_id", (job_id,)
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            status_json = item.pop("last_status_json", None)
            try:
                item["AgentStatus"] = json.loads(status_json) if status_json else None
            except Exception:
                item["AgentStatus"] = None
            item["ResultReady"] = bool(item.get("result_path"))
            out.append(item)
        return out

    def list_jobs(
        self, *, limit: int = 300, status: str = "", agent_id: str = "", job_id: str = ""
    ) -> list[dict[str, Any]]:
        """List recent job targets for administrative dashboards/Web Admin.

        Package/result filesystem paths are deliberately removed from the public
        administrative payload. Result download remains an authenticated endpoint.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status).upper())
        if agent_id:
            clauses.append("agent_id=?")
            params.append(str(agent_id))
        if job_id:
            clauses.append("job_id=?")
            params.append(str(job_id))
        sql = "SELECT * FROM jobs"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY COALESCE(updated_at,created_at) DESC, job_id DESC, site_code, agent_id LIMIT ?"
        params.append(max(1, min(int(limit), 2000)))
        with self.connect() as con:
            rows = con.execute(sql, tuple(params)).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item.pop("package_path", None)
            item.pop("result_path", None)
            raw = item.pop("last_status_json", None)
            try:
                item["AgentStatus"] = json.loads(raw) if raw else None
            except Exception:
                item["AgentStatus"] = None
            item["ResultReady"] = bool(row["result_path"])
            out.append(item)
        return out

    def put_release(self, platform_name: str, architecture: str, channel: str, version: str, payload: bytes, *, protocol_version: str = "2.0", signature: str = "", key_id: str = "", notes: str = "", expected_hash: str = "") -> dict[str, Any]:
        temp = self.incoming_dir / f"release-{os.getpid()}-{threading.get_ident()}-{secrets.token_hex(4)}.part"
        temp.write_bytes(payload)
        try:
            return self.put_release_file(
                platform_name, architecture, channel, version, temp,
                protocol_version=protocol_version, signature=signature, key_id=key_id,
                notes=notes, actual_hash=sha256_bytes(payload), expected_hash=expected_hash,
            )
        finally:
            temp.unlink(missing_ok=True)

    def put_release_file(
        self, platform_name: str, architecture: str, channel: str, version: str, payload: Path,
        *, protocol_version: str = "2.0", signature: str = "", key_id: str = "",
        notes: str = "", actual_hash: str = "", expected_hash: str = "",
    ) -> dict[str, Any]:
        release_dir = self.data_dir / "releases" / platform_name / architecture / channel
        release_dir.mkdir(parents=True, exist_ok=True)
        path = release_dir / f"{version}.zip"
        payload = Path(payload)
        digest = str(actual_hash or sha256_file(payload)).lower()
        if expected_hash and not consteq(digest, str(expected_hash).lower()):
            raise ValueError("Release SHA256 mismatch at gateway")
        os.replace(payload, path)
        stamp = now_iso()
        with self.connect() as con:
            # Re-uploading bytes always invalidates a previous approval. A stable
            # release must be explicitly approved after its final signed artifact
            # is stored in the Gateway.
            con.execute(
                """INSERT INTO agent_releases(platform,architecture,channel,version,protocol_version,bundle_path,bundle_sha256,signature,key_id,notes,created_at,approval_state,approved_at,approved_by,approval_note)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,'DRAFT',NULL,NULL,NULL)
                   ON CONFLICT(platform,architecture,channel,version) DO UPDATE SET
                     protocol_version=excluded.protocol_version,bundle_path=excluded.bundle_path,
                     bundle_sha256=excluded.bundle_sha256,signature=excluded.signature,key_id=excluded.key_id,
                     notes=excluded.notes,created_at=excluded.created_at,approval_state='DRAFT',
                     approved_at=NULL,approved_by=NULL,approval_note=NULL""",
                (platform_name,architecture,channel,version,protocol_version,str(path),digest,signature,key_id,notes,stamp),
            )
        return {
            "Platform":platform_name,"Architecture":architecture,"Channel":channel,"Version":version,
            "Sha256":digest,"Signature":signature,"KeyId":key_id,"CreatedAt":stamp,"ApprovalState":"DRAFT",
        }

    def list_releases(self) -> list[dict[str, Any]]:
        with self.connect() as con:
            return [dict(x) for x in con.execute("SELECT * FROM agent_releases ORDER BY created_at DESC").fetchall()]

    def get_release(self, platform_name: str, architecture: str, channel: str, version: str) -> Optional[dict[str, Any]]:
        with self.connect() as con:
            row=con.execute(
                "SELECT * FROM agent_releases WHERE platform=? AND architecture=? AND channel=? AND version=?",
                (platform_name,architecture,channel,version),
            ).fetchone()
        return dict(row) if row is not None else None

    def set_release_approval(self, platform_name: str, architecture: str, channel: str, version: str, *, approved: bool, approved_by: str = "console", note: str = "") -> Optional[dict[str, Any]]:
        state = "APPROVED" if approved else "REVOKED"
        stamp = now_iso() if approved else None
        with self.connect() as con:
            row=con.execute(
                "SELECT * FROM agent_releases WHERE platform=? AND architecture=? AND channel=? AND version=?",
                (platform_name,architecture,channel,version),
            ).fetchone()
            if row is None:
                return None
            item=dict(row)
            if approved:
                if not str(item.get("bundle_sha256") or "").strip() or not str(item.get("signature") or "").strip() or not str(item.get("key_id") or "").strip():
                    raise ValueError("RELEASE_NOT_SIGNED: el release requiere SHA-256, firma Ed25519 y KeyId antes de aprobarse")
                path=Path(str(item.get("bundle_path") or ""))
                if not path.is_file() or sha256_file(path).lower()!=str(item.get("bundle_sha256") or "").lower():
                    raise ValueError("RELEASE_INTEGRITY: el bundle publicado no coincide con su SHA-256")
            con.execute(
                """UPDATE agent_releases SET approval_state=?,approved_at=?,approved_by=?,approval_note=?
                   WHERE platform=? AND architecture=? AND channel=? AND version=?""",
                (state,stamp,approved_by if approved else None,note,platform_name,architecture,channel,version),
            )
        return self.get_release(platform_name,architecture,channel,version)

    def cleanup_releases(self, *, keep_per_target: int = 2, actor: str = "console", dry_run: bool = False) -> dict[str, Any]:
        """Remove old release rows and bundles without touching live releases.

        APPROVED releases, active update targets, and the newest N versions per
        platform/architecture/channel are protected from this maintenance action.
        """
        keep = max(1, min(int(keep_per_target or 2), 20))
        release_root = (self.data_dir / "releases").resolve()
        with self.connect() as con:
            rows = [dict(row) for row in con.execute("SELECT * FROM agent_releases ORDER BY created_at DESC").fetchall()]
            try:
                protected_versions = {str(row[0] or "") for row in con.execute(
                    "SELECT target_version FROM agent_update_requests WHERE status IN ('REQUESTED','DELIVERED','CHECKING','DOWNLOADING','VERIFYING','UPDATING')"
                ).fetchall()}
            except sqlite3.OperationalError:
                protected_versions = set()
            groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
            for row in rows:
                groups.setdefault((str(row.get("platform") or ""), str(row.get("architecture") or ""), str(row.get("channel") or "")), []).append(row)
            protected: set[tuple[str, str, str, str]] = set()
            for key, group in groups.items():
                group.sort(key=lambda item: (version_key(str(item.get("version") or "0")), str(item.get("created_at") or "")), reverse=True)
                for row in group[:keep]:
                    protected.add((*key, str(row.get("version") or "")))
                for row in group:
                    version = str(row.get("version") or "")
                    if str(row.get("approval_state") or "").upper() == "APPROVED" or version in protected_versions:
                        protected.add((*key, version))
            deleted: list[dict[str, Any]] = []
            for row in rows:
                key = (str(row.get("platform") or ""), str(row.get("architecture") or ""), str(row.get("channel") or ""), str(row.get("version") or ""))
                if key in protected:
                    continue
                item = {k: v for k, v in row.items() if k != "bundle_path"}
                path = Path(str(row.get("bundle_path") or "")).resolve()
                item["bytes"] = path.stat().st_size if path.is_file() and release_root in path.parents else 0
                deleted.append(item)
            if not dry_run:
                for item in deleted:
                    con.execute("DELETE FROM agent_releases WHERE platform=? AND architecture=? AND channel=? AND version=?", (item.get("platform"), item.get("architecture"), item.get("channel"), item.get("version")))
        removed_bytes = 0
        if not dry_run:
            for item in deleted:
                path = Path(str(next((r.get("bundle_path") for r in rows if r.get("platform") == item.get("platform") and r.get("architecture") == item.get("architecture") and r.get("channel") == item.get("channel") and r.get("version") == item.get("version")), "") or "")).resolve()
                if release_root in path.parents and path.is_file():
                    try:
                        removed_bytes += path.stat().st_size
                        path.unlink()
                    except OSError:
                        pass
        return {"Ok": True, "DryRun": bool(dry_run), "KeepPerTarget": keep, "Deleted": deleted, "DeletedCount": len(deleted), "DeletedBytes": removed_bytes}

    def best_release(self, platform_name: str, architecture: str, channel: str, *, approved_only: bool = True) -> Optional[dict[str, Any]]:
        with self.connect() as con:
            sql="SELECT * FROM agent_releases WHERE platform=? AND architecture=? AND channel=?"
            params=[platform_name,architecture,channel]
            if approved_only:
                sql += " AND approval_state='APPROVED'"
            rows=[dict(x) for x in con.execute(sql,tuple(params)).fetchall()]
        return max(rows,key=lambda row: version_key(str(row.get("version") or "0"))) if rows else None

    def purge_agent(self, agent_id: str) -> bool:
        with self.connect() as con:
            active=con.execute(
                "SELECT 1 FROM jobs WHERE agent_id=? AND status IN ('QUEUED','CLAIMED','RUNNING') LIMIT 1", (agent_id,)
            ).fetchone()
            if active is not None:
                return False
            cur=con.execute("DELETE FROM agents WHERE agent_id=?",(agent_id,))
            if int(cur.rowcount or 0)>0:
                con.execute("DELETE FROM agent_configurations WHERE agent_id=?", (agent_id,))
                con.execute("DELETE FROM agent_config_status WHERE agent_id=?", (agent_id,))
                con.execute("DELETE FROM agent_update_requests WHERE agent_id=?", (agent_id,))
                return True
            return False

    def claim_with_capacity(self, job_id: str, agent_id: str, *, max_active_jobs: int = 20) -> dict[str, Any]:
        """Atomically claim a queued target while enforcing fleet backpressure.

        The previous GET/claim flow allowed every endpoint in a large campaign to
        start at once.  This transaction serializes only the short claim decision,
        so 90 queued targets can coexist while the configured active window is
        respected without holding a long-lived database lock.
        """
        stamp = now_iso()
        limit = max(1, min(int(max_active_jobs or 20), 500))
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT status FROM jobs WHERE job_id=? AND agent_id=?",
                (job_id, agent_id),
            ).fetchone()
            if row is None:
                return {"Ok": False, "Reason": "NOT_FOUND", "RetryAfterSeconds": 0}
            current = str(row["status"] or "").upper()
            if current in {"CLAIMED", "RUNNING"}:
                return {"Ok": True, "AlreadyClaimed": True, "ActiveLimit": limit}
            if current != "QUEUED":
                return {"Ok": False, "Reason": f"STATE_{current or 'UNKNOWN'}", "RetryAfterSeconds": 0}
            active = int(con.execute(
                "SELECT COUNT(*) FROM jobs WHERE status IN ('CLAIMED','RUNNING')"
            ).fetchone()[0])
            if active >= limit:
                return {
                    "Ok": False,
                    "Deferred": True,
                    "Reason": "FLEET_CAPACITY",
                    "Active": active,
                    "ActiveLimit": limit,
                    "RetryAfterSeconds": 3,
                }
            cur = con.execute(
                """UPDATE jobs SET status='CLAIMED',claimed_at=COALESCE(claimed_at,?),updated_at=?
                   WHERE job_id=? AND agent_id=? AND status='QUEUED'""",
                (stamp, stamp, job_id, agent_id),
            )
            if int(cur.rowcount or 0) != 1:
                return {"Ok": False, "Deferred": True, "Reason": "CLAIM_RACE", "RetryAfterSeconds": 2}
            return {"Ok": True, "Active": active + 1, "ActiveLimit": limit}

    def claim(self, job_id: str, agent_id: str) -> bool:
        # Compatibility method used by unit tests and older internal callers.
        return bool(self.claim_with_capacity(job_id, agent_id, max_active_jobs=500).get("Ok"))

    def update_status(self, job_id: str, agent_id: str, payload: dict[str, Any]) -> None:
        state = str(payload.get("State") or payload.get("RemoteState") or "RUNNING").upper()
        terminal = state in {"RESULT_READY", "RESULT_READY_WITH_ERRORS", "FAILED", "CANCELLED"} or state.startswith("FAILED_")
        gateway_state = (
            "FAILED" if state == "FAILED" or state.startswith("FAILED_") else
            "CANCELLED" if state == "CANCELLED" else
            "RESULT_READY" if state in {"RESULT_READY", "RESULT_READY_WITH_ERRORS"} else
            "RUNNING"
        )
        stamp = now_iso()
        with self.connect() as con:
            con.execute(
                """UPDATE jobs SET status=?,updated_at=?,finished_at=CASE WHEN ? THEN ? ELSE finished_at END,
                   last_status_json=?,error=? WHERE job_id=? AND agent_id=?""",
                (
                    gateway_state, stamp, 1 if terminal else 0, stamp,
                    json.dumps(payload, ensure_ascii=False), payload.get("Error"),
                    job_id, agent_id,
                ),
            )

    def request_cancel(self, job_id: str, target: str) -> bool:
        row = self.get_job(job_id, target)
        if row is None:
            return False
        agent_id = str(row["agent_id"])
        stamp = now_iso()
        with self.connect() as con:
            current = str(row["status"]).upper()
            if current in {"QUEUED", "CLAIMED"}:
                # CLAIMED can fail before a worker exists (download/signature/
                # freshness validation).  Make admin cancellation terminal so
                # that stale pre-worker jobs cannot block next_job() forever.
                cur = con.execute(
                    "UPDATE jobs SET cancel_requested=1,status='CANCELLED',updated_at=?,finished_at=? WHERE job_id=? AND agent_id=?",
                    (stamp, stamp, job_id, agent_id),
                )
            elif current in {"RESULT_READY", "FAILED", "CANCELLED"}:
                cur = con.execute(
                    "UPDATE jobs SET cancel_requested=1,updated_at=? WHERE job_id=? AND agent_id=?",
                    (stamp, job_id, agent_id),
                )
            else:
                cur = con.execute(
                    "UPDATE jobs SET cancel_requested=1,updated_at=? WHERE job_id=? AND agent_id=?",
                    (stamp, job_id, agent_id),
                )
        return cur.rowcount > 0

    def store_result(self, job_id: str, agent_id: str, payload: bytes, expected_hash: str = "") -> dict[str, Any]:
        temp = self.incoming_dir / f"result-{os.getpid()}-{threading.get_ident()}-{secrets.token_hex(4)}.part"
        temp.write_bytes(payload)
        try:
            return self.store_result_file(
                job_id, agent_id, temp, expected_hash,
                actual_hash=sha256_bytes(payload),
            )
        finally:
            temp.unlink(missing_ok=True)

    def store_result_file(
        self, job_id: str, agent_id: str, payload: Path, expected_hash: str = "", *, actual_hash: str = ""
    ) -> dict[str, Any]:
        payload = Path(payload)
        actual = str(actual_hash or sha256_file(payload)).lower()
        if expected_hash and not consteq(actual.lower(), expected_hash.lower()):
            raise ValueError("Result SHA256 mismatch")
        result_dir = self.results_dir / job_id
        result_dir.mkdir(parents=True, exist_ok=True)
        path = result_dir / f"{agent_id}.zip"
        size = payload.stat().st_size
        os.replace(payload, path)
        stamp = now_iso()
        with self.connect() as con:
            con.execute(
                """UPDATE jobs SET result_path=?,result_sha256=?,status='RESULT_READY',updated_at=?,finished_at=COALESCE(finished_at,?)
                   WHERE job_id=? AND agent_id=?""",
                (str(path), actual, stamp, stamp, job_id, agent_id),
            )
        return {"ResultSha256": actual, "ResultBytes": size, "AgentId": agent_id}


def resolve_gateway_data_dir(cfg: dict[str, Any], config_path: Path | None = None) -> Path:
    """Resolve the Gateway state directory safely and portably.

    Older portable releases could omit ``data_dir`` from agent_gateway.json.
    The Gateway must never crash for that reason: missing/blank values fall back
    to ``<application-root>/gateway-data``. Relative configured paths are also
    anchored to the application root instead of the caller's current directory.
    """
    raw = str(cfg.get("data_dir") or "").strip()
    if config_path is not None:
        config_path = Path(config_path).resolve()
        # Normal layout is <root>/config/agent_gateway.json.
        base = config_path.parent.parent if config_path.parent.name.casefold() == "config" else config_path.parent
    else:
        base = Path(__file__).resolve().parent
    if not raw:
        return (base / "gateway-data").resolve()
    expanded = os.path.expanduser(os.path.expandvars(raw))
    path = Path(expanded)
    if not path.is_absolute():
        path = base / path
    return path.resolve()


class GatewayApp:
    def __init__(self, cfg: dict[str, Any], *, config_path: Path | None = None) -> None:
        self.cfg = cfg
        self.config_path = config_path.resolve() if config_path else None
        self._config_mtime_ns = 0
        self.last_hot_reload = now_iso()
        self.db = GatewayDB(resolve_gateway_data_dir(cfg, self.config_path))
        self.admin_api_key = str(cfg.get("admin_api_key") or os.environ.get(str(cfg.get("admin_api_key_env", "GIDEON_AGENT_ADMIN_TOKEN")), ""))
        self.enrollment_secret = str(cfg.get("enrollment_secret") or os.environ.get(str(cfg.get("enrollment_secret_env", "GIDEON_AGENT_ENROLL_SECRET")), ""))
        if not self.admin_api_key:
            raise RuntimeError("Admin API key missing. Configure admin_api_key or GIDEON_AGENT_ADMIN_TOKEN.")
        if not self.enrollment_secret:
            raise RuntimeError("Enrollment secret missing. Configure enrollment_secret or GIDEON_AGENT_ENROLL_SECRET.")
        self.require_agent_mtls = bool(cfg.get("require_agent_mtls", False))
        self.tunnels = GatewayTunnelBroker(
            enabled=bool(cfg.get("reverse_tunnel_enabled", True)),
            listen_host=str(cfg.get("reverse_tunnel_listen_host") or "0.0.0.0"),
            advertised_host=str(cfg.get("reverse_tunnel_advertised_host") or ("host.docker.internal" if os.name == "nt" else "gideon-gateway")),
            open_ttl_seconds=int(cfg.get("reverse_tunnel_open_ttl_seconds") or 45),
            max_reservations=int(cfg.get("reverse_tunnel_max_reservations") or 64),
            max_streams_per_agent=int(cfg.get("reverse_tunnel_max_streams_per_agent") or 4),
        )
        self.security_profile = {
            "TLSMinimum": "TLSv1.2",
            "TLS13Preferred": True,
            "AgentMTLS": self.require_agent_mtls,
            "PackageSigning": "Ed25519",
            "Digest": "SHA-256",
            "HotReload": bool(cfg.get("hot_reload_enabled", True)),
            "ReverseTunnel": bool(cfg.get("reverse_tunnel_enabled", True)),
            "ReverseTunnelProtocol": TUNNEL_VERSION,
        }
        if self.config_path and self.config_path.exists():
            try:
                self._config_mtime_ns = self.config_path.stat().st_mtime_ns
            except OSError:
                pass

    def reload_runtime_config(self, *, force: bool = False) -> bool:
        """Reload request-time settings without restarting the HTTP listener.

        Listener address/port and TLS certificate are socket-level settings and still
        require a selective Gateway process restart. Credentials, public URL and
        request-time security flags are refreshed here atomically from JSON.
        """
        if not self.config_path or not bool(self.cfg.get("hot_reload_enabled", True)):
            return False
        try:
            stat = self.config_path.stat()
            if not force and stat.st_mtime_ns == self._config_mtime_ns:
                return False
            fresh = load_config(self.config_path)
            admin = str(fresh.get("admin_api_key") or os.environ.get(str(fresh.get("admin_api_key_env", "GIDEON_AGENT_ADMIN_TOKEN")), ""))
            enroll = str(fresh.get("enrollment_secret") or os.environ.get(str(fresh.get("enrollment_secret_env", "GIDEON_AGENT_ENROLL_SECRET")), ""))
            if not admin or not enroll:
                return False
            old_data_dir = resolve_gateway_data_dir(self.cfg, self.config_path)
            new_data_dir = resolve_gateway_data_dir(fresh, self.config_path)
            self.cfg = fresh
            self.admin_api_key = admin
            self.enrollment_secret = enroll
            self.require_agent_mtls = bool(fresh.get("require_agent_mtls", False))
            self.security_profile["AgentMTLS"] = self.require_agent_mtls
            self.security_profile["HotReload"] = bool(fresh.get("hot_reload_enabled", True))
            self.tunnels.reconfigure(fresh)
            self.security_profile["ReverseTunnel"] = bool(self.tunnels.enabled)
            self.security_profile["ReverseTunnelProtocol"] = TUNNEL_VERSION
            if new_data_dir != old_data_dir:
                self.db = GatewayDB(new_data_dir)
            self._config_mtime_ns = stat.st_mtime_ns
            self.last_hot_reload = now_iso()
            return True
        except Exception as exc:
            print(f"[{now_iso()}] hot-reload ignored: {type(exc).__name__}: {exc}")
            return False

    def admin_ok(self, bearer: str) -> bool:
        return consteq(bearer, self.admin_api_key)


class Handler(BaseHTTPRequestHandler):
    server_version = f"GIDEONAgentGateway/{VERSION}"
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> GatewayApp:
        app = self.server.app  # type: ignore[attr-defined]
        app.reload_runtime_config()
        return app

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{now_iso()}] {self.address_string()} {fmt % args}")

    def bearer(self) -> str:
        raw = self.headers.get("Authorization", "")
        return raw[7:].strip() if raw.lower().startswith("bearer ") else ""

    def read_body(self, max_bytes: int = 128 * 1024 * 1024) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length < 0 or length > max_bytes:
            raise ValueError("Request too large")
        return self.rfile.read(length) if length else b""

    def read_body_to_file(self, *, max_bytes: int) -> tuple[Path, str, int]:
        """Stream a bounded request body to Gateway-owned quarantine storage."""
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length <= 0 or length > max(1, int(max_bytes)):
            raise ValueError("Request too large or empty")
        target = self.app.db.incoming_dir / (
            f"upload-{int(time.time())}-{os.getpid()}-{threading.get_ident()}-{secrets.token_hex(4)}.part"
        )
        digest = hashlib.sha256()
        remaining = length
        try:
            with target.open("xb") as stream:
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ConnectionError("Request body ended before Content-Length")
                    stream.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            return target, digest.hexdigest(), length
        except BaseException:
            target.unlink(missing_ok=True)
            raise

    def json_body(self) -> dict[str, Any]:
        raw = self.read_body(4 * 1024 * 1024)
        if not raw:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def send_json(self, status: int, payload: Any) -> None:
        data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def send_bytes(self, status: int, payload: bytes, content_type: str = "application/octet-stream") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def send_file(self, status: int, path: Path, content_type: str = "application/octet-stream") -> None:
        source = Path(path)
        size = source.stat().st_size
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        with source.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def error_json(self, status: int, message: str) -> None:
        self.send_json(status, {"Ok": False, "Error": message})

    def require_admin(self) -> bool:
        if not self.app.admin_ok(self.bearer()):
            self.error_json(HTTPStatus.UNAUTHORIZED, "Admin authentication failed")
            return False
        return True

    def peer_cert(self) -> Optional[dict[str, Any]]:
        try:
            return self.connection.getpeercert()  # type: ignore[attr-defined]
        except Exception:
            return None

    def peer_cert_fingerprint(self) -> str:
        """Return the authenticated TLS leaf fingerprint, never a certificate body."""
        try:
            raw = self.connection.getpeercert(binary_form=True)  # type: ignore[attr-defined]
        except Exception:
            return ""
        if not raw:
            return ""
        return hashlib.sha256(raw).hexdigest().lower()

    def require_agent(self, *, allow_mtls_migration: bool = False) -> Optional[sqlite3.Row]:
        token = self.bearer()
        row = self.app.db.authenticate_agent(token) if token else None
        if row is None:
            self.error_json(HTTPStatus.UNAUTHORIZED, "Agent authentication failed")
            return None
        peer_fingerprint = self.peer_cert_fingerprint()
        registered_fingerprint = "".join(str(row["mtls_fingerprint"] or "").split()).lower() if "mtls_fingerprint" in row.keys() else ""
        if peer_fingerprint and registered_fingerprint and not hmac.compare_digest(peer_fingerprint, registered_fingerprint):
            self.error_json(HTTPStatus.UNAUTHORIZED, "Agent mTLS certificate does not match enrolled identity")
            return None
        # The migration endpoint is the deliberately narrow exception that lets
        # an already-enrolled Agent obtain its first client certificate after the
        # Gateway requirement has been enabled.  It still requires the bearer
        # token, is never used for jobs/tunnels, and is removed automatically on
        # the next Agent restart once the certificate is persisted.
        if self.app.require_agent_mtls and not self.peer_cert() and not allow_mtls_migration:
            self.error_json(HTTPStatus.UNAUTHORIZED, "Agent mTLS client certificate required")
            return None
        return row

    def handle_agent_tunnel_websocket(self) -> None:
        """Upgrade an authenticated Agent request to the reverse-tunnel WebSocket."""
        agent = self.require_agent()
        if agent is None:
            return
        if not self.app.tunnels.enabled:
            self.error_json(HTTPStatus.SERVICE_UNAVAILABLE, "Reverse tunnel disabled")
            return
        upgrade = str(self.headers.get("Upgrade") or "").strip().lower()
        connection = str(self.headers.get("Connection") or "").lower()
        key = str(self.headers.get("Sec-WebSocket-Key") or "").strip()
        version = str(self.headers.get("Sec-WebSocket-Version") or "").strip()
        if upgrade != "websocket" or "upgrade" not in connection or not key or version != "13":
            self.error_json(HTTPStatus.BAD_REQUEST, "Valid WebSocket upgrade required")
            return

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", _ws_accept(key))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.flush()
        except Exception:
            pass

        self.close_connection = True
        try:
            _configure_tcp_keepalive(self.connection)
            # A short read timeout lets the broker's forwarding thread acquire
            # WebSocketPeer's TLS I/O lock promptly for keyboard/mouse input.
            self.connection.settimeout(0.25)
        except Exception:
            pass
        ws = WebSocketPeer(self.connection, client_side=False)
        agent_id = str(agent["agent_id"])
        channel = self.app.tunnels.register(
            agent_id,
            ws,
            peer_ip=str(self.client_address[0] if self.client_address else ""),
        )
        last_ping = time.monotonic()
        try:
            while not ws.closed:
                try:
                    opcode, payload = ws.recv_frame()
                except socket.timeout:
                    if time.monotonic() - last_ping >= 20.0:
                        try:
                            ws.send_ping(b"gideon")
                            last_ping = time.monotonic()
                        except Exception:
                            break
                    continue
                except (ConnectionError, OSError, ValueError) as exc:
                    # A normal Agent disconnect must end the upgraded socket
                    # here.  Letting it escape made do_GET attempt to emit an
                    # HTTP 500 after the WebSocket 101 response was committed.
                    LOG.warning(
                        "reverse tunnel websocket ended agent=%s peer=%s error=%s: %s",
                        agent_id,
                        str(self.client_address[0] if self.client_address else ""),
                        type(exc).__name__,
                        str(exc)[:300],
                    )
                    break
                if opcode == 0x8:
                    break
                if opcode == 0xA:
                    channel.last_seen = time.time()
                    continue
                if opcode == 0x1:
                    channel.handle_text(payload)
                elif opcode == 0x2:
                    channel.handle_binary(payload)
        finally:
            LOG.info(
                "reverse tunnel websocket unregister agent=%s peer=%s",
                agent_id,
                str(self.client_address[0] if self.client_address else ""),
            )
            self.app.tunnels.unregister(agent_id, channel)

    def do_GET(self) -> None:
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            parts = [x for x in path.split("/") if x]

            if path == "/api/v1/agent/tunnel/ws":
                self.handle_agent_tunnel_websocket()
                return

            if path in {"/", "/health"}:
                public_url = str(self.app.cfg.get("advertised_endpoint") or self.app.cfg.get("public_url") or "").rstrip("/")
                if path == "/health":
                    schema = self.app.db.schema_status()
                    self.send_json(200, {
                        "Ok": True,
                        "Service": "GIDEON Agent Gateway",
                        "Status": "RUNNING",
                        "Gateway": public_url,
                        "Version": VERSION,
                        "ProtocolVersion": "2.0",
                        "SchemaVersion": schema.get("SchemaVersion", 0),
                        "SchemaReady": bool(schema.get("Ready")),
                        "Capabilities": {
                            "ReleaseApproval": True,
                            "ReleaseApprovalApiVersion": 2,
                            "ReleaseApprovalEndpoint": "/api/v2/admin/releases/approval",
                            "ReleaseApprovalPathCompat": True,
                            "WebAdminApi": True,
                            "JobsListEndpoint": "/api/v1/admin/jobs",
                            "EnrollmentGrantEndpoint": "/api/v1/admin/enrollment-grants",
                            "EnrollmentGrantRevocation": True,
                            "AgentConfiguration": True,
                            "AgentConfigurationEndpoint": "/api/v1/agent/config",
                            "AgentMediaPlayer": True,
                            "AgentMediaManifestEndpoint": "/api/v1/agent/media/manifest",
                            "AgentMediaReportEndpoint": "/api/v1/agent/media/report",
                            "AgentUpdateRequest": True,
                            "AgentUpdateRequestEndpoint": "/api/v1/admin/agents/{agent_id}/update",
                            "AgentUpdateRequestStates": ["REQUESTED", "DELIVERED", "COMPLETED", "FAILED", "SUPERSEDED"],
                            "AgentOfflineVlcInstall": True,
                            "AgentOfflineVlcInstallEndpoint": "/api/v1/admin/agents/{agent_id}/vlc-offline/install",
                            "AgentOfflineVlcInstallStates": ["REQUESTED", "DELIVERED", "DEFERRED", "RUNNING", "INSTALLED", "FAILED", "EXPIRED", "SUPERSEDED"],
                            "AgentMTLSEnrollment": True,
                            "AgentMTLSIdentityBinding": True,
                            "AgentRdpCapabilitySchema": "gideon-rdp-capability/v1",
                        "ReverseTunnel": bool(self.app.tunnels.enabled),
                        "ReverseTunnelProtocol": TUNNEL_VERSION,
                        },
                        "HTTPS": True,
                        "Time": now_iso(),
                    })
                    return
                safe_url = html.escape(public_url or "(no configurada)")
                safe_time = html.escape(now_iso())
                page = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GIDEON Agent Gateway</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#111820;color:#e8eef5;margin:0;padding:40px}}.card{{max-width:760px;margin:auto;background:#17222c;border:1px solid #304252;border-radius:14px;padding:28px}}.ok{{color:#55d88a;font-weight:700}}code{{background:#0d141a;padding:4px 7px;border-radius:6px}}small{{color:#9fb0bf}}</style></head>
<body><div class="card"><h1>GIDEON Agent Gateway</h1><p class="ok">● Gateway funcionando</p>
<p>Servicio HTTPS/PULL disponible para agentes GIDEON.</p>
<p><b>Endpoint:</b> <code>{safe_url}</code></p><p><b>Versión:</b> {VERSION} &nbsp; <b>Protocolo:</b> 2.0</p>
<p><b>Estado público JSON:</b> <code>/health</code> &nbsp; <b>Información pública:</b> <code>/api/v1/public/info</code></p>
<small>{safe_time}. Los endpoints administrativos requieren autenticación.</small></div></body></html>"""
                self.send_bytes(200, page.encode("utf-8"), "text/html; charset=utf-8")
                return

            if path == "/api/v1/public/info":
                public_url = str(self.app.cfg.get("advertised_endpoint") or self.app.cfg.get("public_url") or "").rstrip("/")
                self.send_json(200, {"Ok": True, "Gateway": public_url, "ProtocolVersion": "2.0", "HTTPS": True, "Time": now_iso()})
                return

            if path == "/api/v1/admin/health":
                if not self.require_admin(): return
                schema = self.app.db.schema_status()
                self.send_json(200, {
                    "Ok": True,
                    "Version": VERSION,
                    "ProtocolVersion": "2.0",
                    "Schema": schema,
                    "Capabilities": {
                        "ReleaseApproval": True,
                        "ReleaseApprovalApiVersion": 2,
                        "ReleaseApprovalEndpoint": "/api/v2/admin/releases/approval",
                        "ReleaseApprovalPathCompat": True,
                        "WebAdminApi": True,
                        "JobsListEndpoint": "/api/v1/admin/jobs",
                        "EnrollmentGrantEndpoint": "/api/v1/admin/enrollment-grants",
                        "EnrollmentGrantRevocation": True,
                        "AgentConfiguration": True,
                        "AgentConfigurationEndpoint": "/api/v1/agent/config",
                        "AgentMediaPlayer": True,
                        "AgentMediaManifestEndpoint": "/api/v1/agent/media/manifest",
                        "AgentMediaReportEndpoint": "/api/v1/agent/media/report",
                        "AgentUpdateRequest": True,
                        "AgentUpdateRequestEndpoint": "/api/v1/admin/agents/{agent_id}/update",
                        "AgentUpdateRequestStates": ["REQUESTED", "DELIVERED", "COMPLETED", "FAILED", "SUPERSEDED"],
                        "AgentOfflineVlcInstall": True,
                        "AgentOfflineVlcInstallEndpoint": "/api/v1/admin/agents/{agent_id}/vlc-offline/install",
                        "AgentOfflineVlcInstallStates": ["REQUESTED", "DELIVERED", "DEFERRED", "RUNNING", "INSTALLED", "FAILED", "EXPIRED", "SUPERSEDED"],
                        "AgentMTLSEnrollment": True,
                        "AgentMTLSIdentityBinding": True,
                        "AgentRdpCapabilitySchema": "gideon-rdp-capability/v1",
                        "ReverseTunnel": bool(self.app.tunnels.enabled),
                        "ReverseTunnelProtocol": TUNNEL_VERSION,
                    },
                    "Security": self.app.security_profile,
                    "ConfigReloadAt": self.app.last_hot_reload,
                    "Time": now_iso(),
                })
                return

            if path == "/api/v1/admin/agents":
                if not self.require_admin(): return
                rows = self.app.db.list_agents()
                for row in rows:
                    aid = str(row.get("agent_id") or "")
                    status = self.app.tunnels.status(aid)
                    row["reverse_tunnel_online"] = bool(status.get("Online"))
                    row["reverse_tunnel_last_seen_unix"] = int(status.get("LastSeenUnix") or 0)
                    row["reverse_tunnel_peer_ip"] = str(status.get("PeerIP") or "")
                self.send_json(200, {"Agents": rows, "Time": now_iso(), "ReverseTunnelProtocol": TUNNEL_VERSION})
                return

            if path == "/api/v1/admin/tunnels/status":
                if not self.require_admin(): return
                q = parse_qs(parsed_url.query)
                aid = str((q.get("agent_id") or [""])[0]).strip()
                if not aid:
                    self.error_json(400, "agent_id required"); return
                payload = self.app.tunnels.status(aid)
                payload.update({"Ok": True, "BrokerEnabled": bool(self.app.tunnels.enabled)})
                self.send_json(200, payload)
                return

            if path == "/api/v1/admin/enrollment-grants":
                if not self.require_admin(): return
                self.send_json(200, {"Grants": self.app.db.list_enrollment_grants(), "Time": now_iso()})
                return

            if path == "/api/v1/admin/media/player-reports":
                if not self.require_admin(): return
                q = parse_qs(parsed_url.query)
                agent_id = str((q.get("agent_id") or [""])[0]).strip()
                try:
                    limit = int(str((q.get("limit") or ["200"])[0]) or 200)
                except ValueError:
                    limit = 200
                self.send_json(200, {
                    "Reports": self.app.db.list_agent_media_player_reports(agent_id=agent_id, limit=limit),
                    "Time": now_iso(),
                })
                return

            if len(parts) == 7 and parts[:4] == ["api", "v1", "admin", "agents"] and parts[5:] == ["vlc-offline", "install"]:
                if not self.require_admin(): return
                request = self.app.db.get_agent_offline_vlc_install_request(parts[4])
                self.send_json(200, {"AgentId": parts[4], "OfflineVlcInstallRequest": request or {}, "Time": now_iso()})
                return

            if len(parts) == 6 and parts[:4] == ["api", "v1", "admin", "agents"] and parts[5] == "config":
                if not self.require_admin(): return
                agent_id = parts[4]
                desired = self.app.db.get_agent_configuration(agent_id)
                self.send_json(200, {
                    "AgentId": agent_id,
                    "Configuration": desired,
                    "Status": self.app.db.get_agent_config_status(agent_id),
                    "Time": now_iso(),
                })
                return

            if len(parts) == 7 and parts[:4] == ["api", "v1", "admin", "agents"] and parts[5:] == ["config", "history"]:
                if not self.require_admin(): return
                agent_id = parts[4]
                self.send_json(200, {"AgentId": agent_id, "History": self.app.db.list_agent_configuration_history(agent_id), "Time": now_iso()})
                return

            if path == "/api/v1/admin/jobs":
                if not self.require_admin(): return
                q = parse_qs(urlparse(self.path).query)
                def qv(name: str, default: str = "") -> str:
                    return str((q.get(name) or [default])[0])
                try:
                    limit = int(qv("limit", "300") or 300)
                except ValueError:
                    limit = 300
                self.send_json(200, {
                    "Jobs": self.app.db.list_jobs(
                        limit=limit, status=qv("status"), agent_id=qv("agent_id"), job_id=qv("job_id")
                    ),
                    "Time": now_iso(),
                })
                return

            if len(parts) == 5 and parts[:3] == ["api", "v1", "admin"] and parts[3] == "jobs":
                if not self.require_admin(): return
                job_id = parts[4]
                self.send_json(200, {"JobId": job_id, "Sites": self.app.db.list_job(job_id)})
                return

            if len(parts) == 7 and parts[:3] == ["api", "v1", "admin"] and parts[3] == "jobs" and parts[6] == "result":
                if not self.require_admin(): return
                job_id, target = parts[4], parts[5]
                row = self.app.db.get_job(job_id, target)
                if row is None or not row["result_path"]:
                    self.error_json(404, "Result not ready")
                    return
                self.send_file(200, Path(row["result_path"]), "application/zip")
                return

            if path == "/api/v1/agent/config":
                agent = self.require_agent()
                if agent is None: return
                q = parse_qs(urlparse(self.path).query)
                try:
                    current = int(str((q.get("current") or ["0"])[0]) or 0)
                except (TypeError, ValueError):
                    current = 0
                response = self.app.db.configuration_response(str(agent["agent_id"]), current)
                response["AgentId"] = str(agent["agent_id"])
                response["Time"] = now_iso()
                self.send_json(200, response)
                return

            if path == "/api/v1/agent/media/manifest":
                agent = self.require_agent()
                if agent is None: return
                manifest = self.app.db.get_agent_media_manifest(str(agent["agent_id"]))
                if manifest is None:
                    self.send_json(200, {"Ok": True, "NoManifest": True, "Time": now_iso()})
                else:
                    self.send_json(200, {"Ok": True, "Manifest": manifest, "Time": now_iso()})
                return

            if path == "/api/v1/agent/jobs/next":
                agent = self.require_agent()
                if agent is None: return
                job = self.app.db.next_job(str(agent["agent_id"]))
                self.send_json(200, {"Job": job})
                return

            if len(parts) == 7 and parts[:3] == ["api", "v1", "agent"] and parts[3] == "jobs" and parts[6] == "package":
                agent = self.require_agent()
                if agent is None: return
                job_id, target = parts[4], parts[5]
                row = self.app.db.get_job(job_id, str(agent["agent_id"]))
                if row is None:
                    self.error_json(404, "Job not found")
                    return
                if target not in {str(agent["agent_id"]), str(agent["site_code"])}:
                    self.error_json(403, "Agent target mismatch")
                    return
                self.send_file(200, Path(row["package_path"]), "application/zip")
                return

            if path == "/api/v2/admin/releases":
                if not self.require_admin(): return
                self.send_json(200, {"Releases": self.app.db.list_releases(), "Time": now_iso()})
                return

            # Authenticated release download. Only explicitly APPROVED artifacts
            # can be fetched by an Agent.
            if len(parts) == 9 and parts[:3] == ["api", "v2", "agent"] and parts[3] == "releases" and parts[8] == "bundle":
                agent = self.require_agent()
                if agent is None: return
                platform_name, architecture, channel, version = parts[4], parts[5], parts[6], parts[7]
                row = self.app.db.get_release(platform_name, architecture, channel, version)
                if row is None or str(row.get("approval_state") or "").upper() != "APPROVED":
                    self.error_json(404, "Approved release not found")
                    return
                bundle_path = Path(str(row.get("bundle_path") or ""))
                if not bundle_path.is_file():
                    self.error_json(404, "Release bundle missing")
                    return
                if sha256_file(bundle_path).lower()!=str(row.get("bundle_sha256") or "").lower():
                    self.error_json(409, "Release bundle integrity mismatch")
                    return
                self.send_file(200, bundle_path, "application/zip")
                return

            if path == "/api/v2/agent/release":
                agent = self.require_agent()
                if agent is None: return
                q = parse_qs(urlparse(self.path).query)
                platform_name = str((q.get("platform") or [agent["platform"] or ""])[0])
                architecture = str((q.get("arch") or [agent["architecture"] or ""])[0])
                channel = str((q.get("channel") or ["stable"])[0])
                current = str((q.get("current") or [agent["agent_version"] or ""])[0])
                update_request = self.app.db.observe_agent_update_request(str(agent["agent_id"]), current)
                row = self.app.db.best_release(platform_name, architecture, channel, approved_only=True)
                if row is None:
                    self.send_json(200, {"Status":"NO_APPROVED_RELEASE","Current":current,"Platform":platform_name,"Architecture":architecture,"Channel":channel,"UpdateRequest":update_request or {}})
                else:
                    public_release = dict(row)
                    bundle_path = Path(str(row.get("bundle_path") or ""))
                    public_release["bundle_bytes"] = bundle_path.stat().st_size if bundle_path.is_file() else 0
                    public_release.pop("bundle_path", None)
                    best=version_key(str(row.get("version") or "0")); cur=version_key(current)
                    status="UPDATE_AVAILABLE" if best>cur else "CURRENT" if best==cur else "AHEAD"
                    self.send_json(200, {"Status":status,"Current":current,"Release":public_release,"UpdateRequest":update_request or {}})
                return

            if len(parts) == 6 and parts[:3] == ["api", "v1", "agent"] and parts[3] == "jobs" and parts[5] == "cancel":
                agent = self.require_agent()
                if agent is None: return
                job_id = parts[4]
                row = self.app.db.get_job(job_id, str(agent["agent_id"]))
                self.send_json(200, {"CancelRequested": bool(row and row["cancel_requested"])})
                return

            self.error_json(404, "Endpoint not found")
        except Exception as exc:
            self.error_json(500, f"{type(exc).__name__}: {exc}")

    def do_POST(self) -> None:
        try:
            path = urlparse(self.path).path
            parts = [x for x in path.split("/") if x]

            if path == "/api/v1/agent/enroll":
                body = self.json_body()
                code = str(body.get("SiteCode") or "").strip()
                if not code:
                    self.error_json(400, "SiteCode required")
                    return
                presented = str(body.get("EnrollmentSecret") or "")
                legacy_ok = consteq(presented, self.app.enrollment_secret)
                grant_ok = False if legacy_ok else self.app.db.consume_enrollment_grant(presented)
                if not (legacy_ok or grant_ok):
                    self.error_json(403, "Enrollment credential invalid or expired")
                    return
                token, enrolled_agent_id = self.app.db.enroll_agent(
                    code,
                    str(body.get("SiteName") or ""),
                    str(body.get("Hostname") or ""),
                    str(body.get("AgentVersion") or ""),
                    agent_id=str(body.get("AgentId") or ""),
                    agent_name=str(body.get("AgentName") or body.get("Hostname") or ""),
                    protocol_version=str(body.get("ProtocolVersion") or ""),
                    platform_name=str(body.get("Platform") or ""),
                    architecture=str(body.get("Architecture") or ""),
                    host_profile=str(body.get("HostProfile") or ""),
                    remote_ip=str(self.client_address[0] if self.client_address else ""),
                    capabilities=body.get("Capabilities") if isinstance(body.get("Capabilities"), dict) else {},
                )
                self.send_json(200, {"Ok": True, "AgentToken": token, "AgentId": enrolled_agent_id, "SiteCode": code})
                return

            if path == "/api/v1/agent/mtls/enroll":
                agent = self.require_agent(allow_mtls_migration=True)
                if agent is None:
                    return
                body = self.json_body()
                requested_id = str(body.get("AgentId") or "").strip()
                if requested_id and requested_id != str(agent["agent_id"]):
                    self.error_json(HTTPStatus.FORBIDDEN, "Agent identity mismatch")
                    return
                try:
                    issued = issue_agent_client_certificate(
                        self.app.cfg,
                        csr_pem=str(body.get("CSR") or ""),
                        agent_id=str(agent["agent_id"]),
                        hostname=str(body.get("Hostname") or agent["hostname"] or ""),
                    )
                except (ValueError, RuntimeError, TypeError) as exc:
                    self.error_json(HTTPStatus.BAD_REQUEST, f"mTLS enrollment failed: {type(exc).__name__}: {exc}")
                    return
                try:
                    self.app.db.set_agent_mtls_fingerprint(str(agent["agent_id"]), str(issued.get("FingerprintSHA256") or ""))
                except (ValueError, KeyError) as exc:
                    self.error_json(HTTPStatus.INTERNAL_SERVER_ERROR, f"mTLS enrollment persistence failed: {type(exc).__name__}: {exc}")
                    return
                self.send_json(200, {"Ok": True, "AgentId": str(agent["agent_id"]), **issued})
                return

            if path == "/api/v1/agent/heartbeat":
                agent = self.require_agent()
                if agent is None: return
                body = self.json_body()
                self.app.db.heartbeat(
                    str(agent["agent_id"]),
                    str(body.get("Hostname") or agent["hostname"] or ""),
                    str(body.get("AgentVersion") or agent["agent_version"] or ""),
                    agent_name=str(body.get("AgentName") or agent["agent_name"] or body.get("Hostname") or ""),
                    protocol_version=str(body.get("ProtocolVersion") or agent["protocol_version"] or ""),
                    platform_name=str(body.get("Platform") or agent["platform"] or ""),
                    architecture=str(body.get("Architecture") or agent["architecture"] or ""),
                    host_profile=str(body.get("HostProfile") or agent["host_profile"] or ""),
                    remote_ip=str(self.client_address[0] if self.client_address else ""),
                    capabilities=body.get("Capabilities") if isinstance(body.get("Capabilities"), dict) else {},
                    diagnostics=body.get("Diagnostics") if isinstance(body.get("Diagnostics"), dict) else {},
                )
                self.send_json(200, {
                    "Ok": True,
                    "AgentId": str(agent["agent_id"]),
                    "SiteCode": str(agent["site_code"]),
                    "Time": now_iso(),
                    "RemoteIP": str(self.client_address[0] if self.client_address else ""),
                    "UpdateRequest": self.app.db.get_agent_update_request(str(agent["agent_id"])) or {},
                    "OfflineVlcInstallRequest": self.app.db.deliver_agent_offline_vlc_install_request(str(agent["agent_id"])) or {},
                })
                return

            if path == "/api/v1/agent/vlc-offline/install/status":
                agent = self.require_agent()
                if agent is None: return
                body = self.json_body()
                try:
                    result = self.app.db.observe_agent_offline_vlc_install(
                        str(agent["agent_id"]), str(body.get("RequestId") or ""),
                        state=str(body.get("State") or ""), detail=str(body.get("Detail") or ""),
                    )
                except ValueError as exc:
                    self.error_json(400, str(exc)); return
                self.send_json(200, {"Ok": True, "OfflineVlcInstallRequest": result or {}, "Time": now_iso()})
                return

            if path == "/api/v1/agent/media/report":
                agent = self.require_agent()
                if agent is None: return
                body = self.json_body()
                try:
                    saved = self.app.db.report_agent_media_player(str(agent["agent_id"]), body)
                except ValueError as exc:
                    self.error_json(400, str(exc)); return
                self.send_json(200, {"Ok": True, "Accepted": len(saved), "Time": now_iso()})
                return

            if path == "/api/v1/admin/tunnels/open":
                if not self.require_admin(): return
                body = self.json_body()
                agent_id = str(body.get("AgentId") or "").strip()
                purpose = str(body.get("Purpose") or "RDP").upper()
                target_host = str(body.get("TargetHost") or "127.0.0.1")
                target_port = int(body.get("TargetPort") or (3389 if purpose == "RDP" else 5900))
                session_switch = body.get("SessionSwitch") if isinstance(body.get("SessionSwitch"), dict) else {}
                if not agent_id:
                    self.error_json(400, "AgentId required"); return
                try:
                    reservation = self.app.tunnels.reserve(
                        agent_id=agent_id, purpose=purpose,
                        target_host=target_host, target_port=target_port,
                        session_switch=session_switch,
                    )
                except Exception as exc:
                    self.error_json(409, f"REVERSE_TUNNEL_OPEN_FAILED: {type(exc).__name__}: {exc}")
                    return
                self.send_json(200, {
                    "Ok": True,
                    "TunnelId": reservation.tunnel_id,
                    "AgentId": reservation.agent_id,
                    "Purpose": reservation.purpose,
                    "BrokerHost": reservation.broker_host,
                    "BrokerPort": reservation.broker_port,
                    "ExpiresUnix": reservation.expires_unix,
                    "TargetHost": reservation.target_host,
                    "TargetPort": reservation.target_port,
                    "SessionSwitch": reservation.session_switch,
                    "ProtocolVersion": TUNNEL_VERSION,
                })
                return

            if path == "/api/v1/admin/enrollment-grants":
                if not self.require_admin(): return
                body = self.json_body()
                try:
                    ttl = max(300, min(int(body.get("TtlSeconds") or 86400), 30 * 86400))
                    uses = max(1, min(int(body.get("MaxUses") or 1), 100))
                except (TypeError, ValueError):
                    self.error_json(400, "TtlSeconds/MaxUses invalid"); return
                label = str(body.get("Label") or "web-installer")[:120]
                record = self.app.db.issue_enrollment_grant_record(ttl_seconds=ttl, max_uses=uses, label=label)
                record.update({"Ok": True, "Warning": "El grant se muestra una sola vez; GrantId permite revocarlo sin conservar el secreto."})
                self.send_json(200, record)
                return

            if len(parts) == 6 and parts[:5] == ["api", "v1", "admin", "media", "manifests"]:
                if not self.require_admin(): return
                body = self.json_body()
                try:
                    result = self.app.db.put_agent_media_manifest(parts[5], body)
                except ValueError as exc:
                    self.error_json(400, str(exc)); return
                self.send_json(200, {"Ok": True, "Manifest": result, "Time": now_iso()})
                return

            if len(parts) == 6 and parts[:4] == ["api", "v1", "admin", "enrollment-grants"] and parts[5] == "revoke":
                if not self.require_admin(): return
                body = self.json_body()
                grant_id = parts[4]
                ok = self.app.db.revoke_enrollment_grant(grant_id, reason=str(body.get("Reason") or "revoked-by-admin"))
                if not ok:
                    self.error_json(404, "Enrollment grant not found, already consumed, expired or revoked")
                    return
                self.send_json(200, {"Ok": True, "GrantId": grant_id, "RevokedAt": now_iso()})
                return

            if len(parts) == 6 and parts[:4] == ["api", "v1", "admin", "agents"] and parts[5] == "config":
                if not self.require_admin(): return
                body = self.json_body()
                settings = body.get("Settings") if isinstance(body.get("Settings"), dict) else {}
                try:
                    document = self.app.db.set_agent_configuration(
                        parts[4], settings, actor=str(body.get("Actor") or "admin"), note=str(body.get("Note") or "")
                    )
                except (ValueError, CentralConfigError) as exc:
                    self.error_json(400, str(exc)); return
                self.send_json(200, {"Ok": True, "AgentId": parts[4], "Configuration": document})
                return

            if len(parts) == 6 and parts[:4] == ["api", "v1", "admin", "agents"] and parts[5] == "update":
                if not self.require_admin(): return
                body = self.json_body()
                try:
                    request = self.app.db.request_agent_update(
                        parts[4], actor=str(body.get("Actor") or "admin"),
                        target_version=str(body.get("TargetVersion") or ""),
                    )
                except ValueError as exc:
                    self.error_json(409, str(exc)); return
                self.send_json(202, {"Ok": True, "AgentId": parts[4], "UpdateRequest": request})
                return

            if len(parts) == 7 and parts[:4] == ["api", "v1", "admin", "agents"] and parts[5:] == ["vlc-offline", "install"]:
                if not self.require_admin(): return
                body = self.json_body()
                authorization = body.get("Authorization") if isinstance(body.get("Authorization"), dict) else {}
                try:
                    request = self.app.db.request_agent_offline_vlc_install(
                        parts[4], authorization, actor=str(body.get("Actor") or "admin"),
                    )
                except ValueError as exc:
                    self.error_json(409, str(exc)); return
                self.send_json(202, {"Ok": True, "AgentId": parts[4], "OfflineVlcInstallRequest": request})
                return

            if path == "/api/v1/agent/config/status":
                agent = self.require_agent()
                if agent is None: return
                body = self.json_body()
                try:
                    version = max(0, int(body.get("Version") or 0))
                except (TypeError, ValueError):
                    self.error_json(400, "Version invalid"); return
                self.app.db.report_agent_config_status(
                    str(agent["agent_id"]), version=version, status=str(body.get("Status") or "UNKNOWN"), detail=str(body.get("Detail") or "")
                )
                self.send_json(200, {"Ok": True, "AgentId": str(agent["agent_id"]), "Version": version, "Time": now_iso()})
                return

            # Nota: la ruta correcta y única de cancelación admin es la de 7
            # segmentos /api/v1/admin/jobs/<job>/<site>/cancel (abajo). Antes
            # existía aquí una rama muerta de 6 segmentos que validaba admin
            # y luego no hacía nada (caía a 404 sin `return`), arriesgando un
            # segundo intento de respuesta HTTP tras uno ya enviado. Se retiró.

            if len(parts) == 7 and parts[:3] == ["api", "v1", "admin"] and parts[3] == "jobs" and parts[6] == "cancel":
                if not self.require_admin(): return
                ok = self.app.db.request_cancel(parts[4], parts[5])
                self.send_json(200 if ok else 404, {"Ok": ok})
                return

            if len(parts) == 6 and parts[:3] == ["api", "v1", "agent"] and parts[3] == "jobs" and parts[5] == "claim":
                agent = self.require_agent()
                if agent is None: return
                result = self.app.db.claim_with_capacity(
                    parts[4], str(agent["agent_id"]),
                    max_active_jobs=int(self.app.cfg.get("fleet_max_active_jobs", 20) or 20),
                )
                # Capacity pressure is not an error.  Keep the target QUEUED and
                # let the Agent retry with jitter; this prevents thundering-herd
                # execution across a 90-endpoint campaign.
                status_code = 200 if (result.get("Ok") or result.get("Deferred")) else 404
                self.send_json(status_code, result)
                return

            if len(parts) == 6 and parts[:3] == ["api", "v1", "agent"] and parts[3] == "jobs" and parts[5] == "status":
                agent = self.require_agent()
                if agent is None: return
                body = self.json_body()
                self.app.db.update_status(parts[4], str(agent["agent_id"]), body)
                self.send_json(200, {"Ok": True})
                return

            if len(parts) == 6 and parts[:3] == ["api", "v1", "agent"] and parts[3] == "jobs" and parts[5] == "result":
                agent = self.require_agent()
                if agent is None: return
                upload, digest, _ = self.read_body_to_file(
                    max_bytes=int(self.app.cfg.get("max_job_result_bytes", 1024 * 1024 * 1024) or 1024 * 1024 * 1024)
                )
                try:
                    info = self.app.db.store_result_file(
                        parts[4], str(agent["agent_id"]), upload,
                        self.headers.get("X-GIDEON-SHA256", ""), actual_hash=digest,
                    )
                finally:
                    upload.unlink(missing_ok=True)
                self.send_json(200, {"Ok": True, **info})
                return

            # Canonical approval endpoint. Keep identity fields in JSON instead of
            # encoding them in the URL so reverse proxies and older path routers
            # cannot mis-parse architecture/version segments.
            if path == "/api/v2/admin/releases/approval":
                if not self.require_admin(): return
                body = self.json_body()
                platform_name = str(body.get("Platform") or body.get("platform") or "").strip()
                architecture = str(body.get("Architecture") or body.get("architecture") or "").strip()
                channel = str(body.get("Channel") or body.get("channel") or "").strip()
                version = str(body.get("Version") or body.get("version") or "").strip()
                raw_approved = body.get("Approved") if "Approved" in body else body.get("approved")
                if isinstance(raw_approved, str):
                    approved = raw_approved.strip().casefold() in {"1", "true", "yes", "approved", "approve"}
                else:
                    approved = bool(raw_approved)
                if not all((platform_name, architecture, channel, version)):
                    self.error_json(400, "Platform, Architecture, Channel and Version are required"); return
                row = self.app.db.set_release_approval(
                    platform_name, architecture, channel, version,
                    approved=approved,
                    approved_by=str(body.get("ApprovedBy") or body.get("approved_by") or "console"),
                    note=str(body.get("Note") or body.get("note") or ""),
                )
                if row is None:
                    self.error_json(404, "Release not found"); return
                public = dict(row); public.pop("bundle_path", None)
                self.send_json(200, {"Ok": True, "Release": public, "ApprovalEndpoint": "canonical"}); return

            if path == "/api/v2/admin/releases/cleanup":
                if not self.require_admin(): return
                body = self.json_body()
                try:
                    keep = max(1, min(int(body.get("KeepPerTarget") or 2), 20))
                except (TypeError, ValueError):
                    self.error_json(400, "KeepPerTarget invalid"); return
                result = self.app.db.cleanup_releases(
                    keep_per_target=keep, actor=str(body.get("Actor") or "console"),
                    dry_run=bool(body.get("DryRun", False)),
                )
                self.send_json(200, result); return

            # Backward-compatible path-form endpoint kept for older consoles.
            # POST /api/v2/admin/releases/<platform>/<arch>/<channel>/<version>/(approve|revoke)
            if len(parts) == 9 and parts[:4] == ["api", "v2", "admin", "releases"] and parts[8] in {"approve","revoke"}:
                if not self.require_admin(): return
                body=self.json_body()
                approved=parts[8]=="approve"
                row=self.app.db.set_release_approval(parts[4],parts[5],parts[6],parts[7],approved=approved,approved_by=str(body.get("ApprovedBy") or "console"),note=str(body.get("Note") or ""))
                if row is None:
                    self.error_json(404,"Release not found"); return
                public=dict(row); public.pop("bundle_path",None)
                self.send_json(200,{"Ok":True,"Release":public}); return

            # Remove only the Gateway enrollment record after the local Agent has
            # been uninstalled/offline. Active jobs protect against accidental purge.
            if len(parts) == 6 and parts[:4] == ["api","v1","admin","agents"] and parts[5] == "purge":
                if not self.require_admin(): return
                ok=self.app.db.purge_agent(parts[4])
                self.send_json(200 if ok else 409,{"Ok":ok,"AgentId":parts[4],"Error":"Active jobs or Agent not found" if not ok else ""}); return

            self.error_json(404, "Endpoint not found")
        except Exception as exc:
            self.error_json(500, f"{type(exc).__name__}: {exc}")

    def do_PUT(self) -> None:
        try:
            path = urlparse(self.path).path
            parts = [x for x in path.split("/") if x]
            # PUT /api/v1/admin/jobs/<job>/<site>
            if len(parts) == 6 and parts[:3] == ["api", "v1", "admin"] and parts[3] == "jobs":
                if not self.require_admin(): return
                job_id, target = parts[4], parts[5]
                upload, digest, _ = self.read_body_to_file(
                    max_bytes=int(self.app.cfg.get("max_job_package_bytes", 1024 * 1024 * 1024) or 1024 * 1024 * 1024)
                )
                try:
                    info = self.app.db.put_job_file(
                        job_id, target, self.headers.get("X-GIDEON-Site-Name", ""), upload,
                        self.headers.get("X-GIDEON-SHA256", ""),
                        self.headers.get("X-GIDEON-Signature", ""),
                        self.headers.get("X-GIDEON-Key-Id", ""),
                        self.headers.get("X-GIDEON-Site-Code", ""),
                        actual_hash=digest,
                    )
                finally:
                    upload.unlink(missing_ok=True)
                self.send_json(200, {"Ok": True, **info})
                return
            # PUT /api/v2/admin/releases/<platform>/<arch>/<channel>/<version>
            if len(parts) == 8 and parts[:3] == ["api", "v2", "admin"] and parts[3] == "releases":
                if not self.require_admin(): return
                configured_max_bytes = int(self.app.cfg.get("max_release_bundle_bytes", 256 * 1024 * 1024) or 256 * 1024 * 1024)
                upload, digest, _ = self.read_body_to_file(
                    max_bytes=max(1, min(configured_max_bytes, 256 * 1024 * 1024))
                )
                try:
                    info = self.app.db.put_release_file(
                        parts[4], parts[5], parts[6], parts[7], upload,
                        protocol_version=self.headers.get("X-GIDEON-Protocol-Version", "2.0"),
                        signature=self.headers.get("X-GIDEON-Signature", ""),
                        key_id=self.headers.get("X-GIDEON-Key-Id", ""),
                        notes=self.headers.get("X-GIDEON-Notes", ""),
                        actual_hash=digest,
                        expected_hash=self.headers.get("X-GIDEON-SHA256", ""),
                    )
                finally:
                    upload.unlink(missing_ok=True)
                self.send_json(200, {"Ok": True, **info})
                return

            self.error_json(404, "Endpoint not found")
        except Exception as exc:
            self.error_json(500, f"{type(exc).__name__}: {exc}")



class GIDEONThreadingHTTPServer(ThreadingHTTPServer):
    """Fleet-scale HTTP server with TLS handshakes isolated per worker.

    Wrapping the listening socket itself makes ``SSLSocket.accept()`` perform the
    TLS handshake on the single accept loop.  One slow/stalled client can then
    delay every Agent and even the WebAdmin health call.  RC26 accepts raw TCP
    immediately and performs the handshake inside the request worker.
    """

    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 512

    def __init__(self, *args: Any, tls_context: ssl.SSLContext | None = None,
                 handshake_timeout: float = 5.0, max_connections: int = 256, **kwargs: Any) -> None:
        self.tls_context = tls_context
        self.handshake_timeout = max(1.0, min(float(handshake_timeout or 5.0), 30.0))
        self._connection_slots = threading.BoundedSemaphore(max(16, min(int(max_connections or 256), 2048)))
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        wrapped = request
        try:
            if self.tls_context is not None:
                request.settimeout(self.handshake_timeout)
                wrapped = self.tls_context.wrap_socket(
                    request, server_side=True, do_handshake_on_connect=False
                )
                wrapped.settimeout(self.handshake_timeout)
                wrapped.do_handshake()
                wrapped.settimeout(None)
            super().process_request_thread(wrapped, client_address)
        except (ssl.SSLError, socket.timeout, TimeoutError) as exc:
            print(f"[{now_iso()}] TLS handshake rejected from {client_address}: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            try:
                wrapped.close()
            except Exception:
                pass
        finally:
            self._connection_slots.release()


def load_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("Gateway config must be JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="GIDEON Agent Gateway")
    parser.add_argument("--config", type=Path, default=DEFAULT_GATEWAY_CONFIG_PATH)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--certfile", type=Path)
    parser.add_argument("--keyfile", type=Path)
    args = parser.parse_args()

    cfg = load_config(args.config)
    app = GatewayApp(cfg, config_path=args.config)
    host = args.host or str(cfg.get("listen_host", "127.0.0.1"))
    port = int(args.port or cfg.get("listen_port", 8443))
    certfile = args.certfile or (Path(str(cfg.get("tls_certfile"))) if cfg.get("tls_certfile") else None)
    keyfile = args.keyfile or (Path(str(cfg.get("tls_keyfile"))) if cfg.get("tls_keyfile") else None)
    scheme = "http"
    if certfile and keyfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!3DES:!RC4")
        except Exception as exc:
            print(f"[GIDEON][WARN] TLS_CIPHER_POLICY_FALLBACK: {exc}", file=sys.stderr, flush=True)
        context.load_cert_chain(str(certfile), str(keyfile))
        client_ca = cfg.get("client_ca_file")
        if client_ca:
            context.load_verify_locations(cafile=str(client_ca))
            context.verify_mode = ssl.CERT_OPTIONAL
        scheme = "https"
    else:
        context = None

    server = GIDEONThreadingHTTPServer(
        (host, port), Handler,
        tls_context=context,
        handshake_timeout=float(cfg.get("tls_handshake_timeout_seconds", 5) or 5),
        max_connections=int(cfg.get("gateway_max_connections", 256) or 256),
    )
    server.app = app  # type: ignore[attr-defined]

    print(f"GIDEON Agent Gateway v{VERSION} listening on {scheme}://{host}:{port}")
    print(f"Data: {app.db.data_dir}")
    if scheme != "https":
        print("WARNING: direct TLS is disabled. Use only localhost/lab or place behind HTTPS reverse proxy.")
    try:
        server.serve_forever(poll_interval=0.10)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            app.tunnels.shutdown()
        except Exception:
            pass
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
