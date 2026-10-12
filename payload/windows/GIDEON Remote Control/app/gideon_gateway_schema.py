from __future__ import annotations

import sqlite3


def _legacy_agent_id(site_code: str, hostname: str) -> str:
    import hashlib
    seed = f"{str(site_code or '').strip().lower()}|{str(hostname or '').strip().lower()}"
    return "agt-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def _token_hash(token: str) -> str:
    import hashlib
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def ensure_gateway_schema(con: sqlite3.Connection) -> None:
    """Create/repair all Gateway tables in one schema-migration component.

    The caller owns the transaction and connection lifecycle.  Keeping schema
    repair outside ``GatewayDB`` separates migration responsibility from runtime
    repository operations while preserving the existing additive-repair behavior.
    """
    def table_exists(name: str) -> bool:
        return con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone() is not None

    def columns(name: str) -> dict[str, sqlite3.Row]:
        return {str(r[1]): r for r in con.execute(f'PRAGMA table_info("{name}")').fetchall()}

    def has_unique_key(name: str, expected: list[str]) -> bool:
        if not table_exists(name):
            return False
        cols = columns(name)
        pk = sorted(
            ((int(row[5] or 0), col) for col, row in cols.items() if int(row[5] or 0) > 0),
            key=lambda x: x[0],
        )
        if [c for _, c in pk] == expected:
            return True
        for idx in con.execute(f'PRAGMA index_list("{name}")').fetchall():
            # PRAGMA index_list: seq,name,unique,origin,partial
            if not int(idx[2] or 0):
                continue
            idx_name = str(idx[1]).replace('"', '""')
            idx_cols = [str(r[2]) for r in con.execute(f'PRAGMA index_info("{idx_name}")').fetchall()]
            if idx_cols == expected:
                return True
        return False

    def safe_rename(name: str, base: str) -> str:
        candidate = base
        n = 1
        while table_exists(candidate):
            n += 1
            candidate = f"{base}_{n}"
        qname = name.replace('"', '""')
        qcandidate = candidate.replace('"', '""')
        con.execute(f'ALTER TABLE "{qname}" RENAME TO "{qcandidate}"')
        return candidate

    # Validate real keys before using SQLite UPSERT clauses.
    if table_exists("agents"):
        acols = columns("agents")
        if (
            not {"agent_id", "site_code", "token_hash"}.issubset(acols)
            or not has_unique_key("agents", ["agent_id"])
            or not has_unique_key("agents", ["token_hash"])
        ):
            safe_rename("agents", "agents_v2035_repair")

    if table_exists("jobs"):
        jcols = columns("jobs")
        if not {"job_id", "agent_id", "site_code"}.issubset(jcols) or not has_unique_key("jobs", ["job_id", "agent_id"]):
            safe_rename("jobs", "jobs_v2035_repair")

    if table_exists("agent_releases"):
        rcols = columns("agent_releases")
        release_key = ["platform", "architecture", "channel", "version"]
        if not set(release_key).issubset(rcols) or not has_unique_key("agent_releases", release_key):
            safe_rename("agent_releases", "agent_releases_v2035_repair")

    # Offline VLC install approvals are bearer-delivered only to their bound
    # Agent.  If an experimental/intermediate table is not exactly keyed by a
    # request id, retain it for forensic recovery but do not migrate its
    # potentially executable envelope into the live delivery queue.
    if table_exists("agent_vlc_offline_install_requests"):
        vcols = columns("agent_vlc_offline_install_requests")
        vlc_required = {
            "request_id", "agent_id", "authorization_json", "authorization_sha256",
            "catalog_sha256", "expires_at", "expires_unix", "status", "requested_at",
        }
        if not vlc_required.issubset(vcols) or not has_unique_key(
            "agent_vlc_offline_install_requests", ["request_id"]
        ):
            safe_rename("agent_vlc_offline_install_requests", "agent_vlc_offline_install_requests_v2035_repair")

    # A Player can legitimately return to a previously published resolved
    # state (for example connected -> disconnected -> connected).  Older
    # schemas made (agent_id, manifest_sha256) unique, which caused the
    # Gateway to return the stale first version instead of storing the new
    # monotonic version.  Rebuild only this append-only table and retain the
    # prior copy for forensic recovery.
    if table_exists("agent_media_manifests"):
        manifest_columns = columns("agent_media_manifests")
        manifest_required = {
            "agent_id", "manifest_version", "manifest_sha256", "key_id",
            "signature", "manifest_json", "created_at",
        }
        if (
            not manifest_required.issubset(manifest_columns)
            or not has_unique_key("agent_media_manifests", ["agent_id", "manifest_version"])
            or has_unique_key("agent_media_manifests", ["agent_id", "manifest_sha256"])
        ):
            con.execute("DROP TRIGGER IF EXISTS agent_media_manifests_no_update")
            con.execute("DROP TRIGGER IF EXISTS agent_media_manifests_no_delete")
            con.execute("DROP INDEX IF EXISTS idx_agent_media_manifests_latest")
            con.execute("DROP INDEX IF EXISTS idx_agent_media_manifests_digest")
            safe_rename("agent_media_manifests", "agent_media_manifests_v2438_reissue")

    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            site_code TEXT NOT NULL,
            site_name TEXT,
            agent_name TEXT,
            hostname TEXT,
            token_hash TEXT NOT NULL UNIQUE,
            agent_version TEXT,
            protocol_version TEXT,
            platform TEXT,
            architecture TEXT,
            host_profile TEXT,
            capabilities_json TEXT,
            diagnostics_json TEXT,
            last_remote_ip TEXT,
            last_seen TEXT,
            enrolled_at TEXT,
            status TEXT DEFAULT 'ONLINE',
            mtls_fingerprint TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_agents_site_code ON agents(site_code);
        CREATE INDEX IF NOT EXISTS idx_agents_site_seen ON agents(site_code,last_seen);

        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            site_code TEXT NOT NULL,
            site_name TEXT,
            status TEXT NOT NULL DEFAULT 'QUEUED',
            created_at TEXT,
            claimed_at TEXT,
            updated_at TEXT,
            finished_at TEXT,
            package_path TEXT NOT NULL,
            package_sha256 TEXT NOT NULL,
            package_signature TEXT,
            package_key_id TEXT,
            result_path TEXT,
            result_sha256 TEXT,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            last_status_json TEXT,
            error TEXT,
            PRIMARY KEY(job_id, agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_agent_status ON jobs(agent_id,status,created_at);
        CREATE INDEX IF NOT EXISTS idx_jobs_site_status ON jobs(site_code,status,created_at);

        CREATE TABLE IF NOT EXISTS enrollment_grants (
            token_hash TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_unix INTEGER NOT NULL,
            remaining_uses INTEGER NOT NULL,
            label TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_enrollment_grants_expiry ON enrollment_grants(expires_unix);

        CREATE TABLE IF NOT EXISTS agent_configurations (
            agent_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            config_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT,
            note TEXT,
            PRIMARY KEY(agent_id,version)
        );
        CREATE INDEX IF NOT EXISTS idx_agent_configurations_latest ON agent_configurations(agent_id,version DESC);

        CREATE TABLE IF NOT EXISTS agent_config_status (
            agent_id TEXT PRIMARY KEY,
            applied_version INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'UNKNOWN',
            detail TEXT,
            reported_at TEXT
        );

        CREATE TABLE IF NOT EXISTS agent_update_requests (
            request_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            target_version TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            requested_by TEXT,
            status TEXT NOT NULL DEFAULT 'REQUESTED',
            delivered_at TEXT,
            completed_at TEXT,
            current_version TEXT,
            detail TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_agent_update_requests_latest
            ON agent_update_requests(agent_id,requested_at DESC);
        CREATE INDEX IF NOT EXISTS idx_agent_update_requests_status
            ON agent_update_requests(status,requested_at);

        -- The Gateway is a transport/store for a short-lived, already signed
        -- VLC authorisation envelope.  It has no signing key and does not
        -- verify or transform the authorisation.  The raw JSON is deliberately
        -- excluded from all administrative listing queries; only an
        -- authenticated matching Agent can receive it during a heartbeat.
        CREATE TABLE IF NOT EXISTS agent_vlc_offline_install_requests (
            request_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            authorization_json TEXT NOT NULL,
            authorization_sha256 TEXT NOT NULL,
            catalog_sha256 TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            expires_unix INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'REQUESTED'
                CHECK(status IN ('REQUESTED','DELIVERED','DEFERRED','RUNNING','INSTALLED','FAILED','CANCELLED','EXPIRED','SUPERSEDED')),
            requested_at TEXT NOT NULL,
            requested_by TEXT,
            delivered_at TEXT,
            started_at TEXT,
            started_unix INTEGER,
            reported_at TEXT,
            reported_unix INTEGER,
            completed_at TEXT,
            detail TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_agent_vlc_offline_install_requests_active
            ON agent_vlc_offline_install_requests(agent_id,status,expires_unix,requested_at DESC);
        CREATE INDEX IF NOT EXISTS idx_agent_vlc_offline_install_requests_latest
            ON agent_vlc_offline_install_requests(agent_id,requested_at DESC);

        CREATE TABLE IF NOT EXISTS agent_releases (
            platform TEXT NOT NULL,
            architecture TEXT NOT NULL,
            channel TEXT NOT NULL,
            version TEXT NOT NULL,
            protocol_version TEXT,
            min_agent_version TEXT,
            bundle_path TEXT,
            bundle_sha256 TEXT,
            signature TEXT,
            key_id TEXT,
            notes TEXT,
            created_at TEXT,
            approval_state TEXT NOT NULL DEFAULT 'DRAFT',
            approved_at TEXT,
            approved_by TEXT,
            approval_note TEXT,
            PRIMARY KEY(platform,architecture,channel,version)
        );

        -- Phase 3 Player control-plane objects.  The Gateway stores only a
        -- signed manifest envelope issued by WebAdmin; it never receives the
        -- WebAdmin private key nor media bytes.  Rows are append-only so an
        -- Agent can keep validating a known revision while offline.
        CREATE TABLE IF NOT EXISTS agent_media_manifests (
            agent_id TEXT NOT NULL,
            manifest_version TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            key_id TEXT NOT NULL,
            signature TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(agent_id, manifest_version)
        );
        CREATE INDEX IF NOT EXISTS idx_agent_media_manifests_latest
            ON agent_media_manifests(agent_id,created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_agent_media_manifests_digest
            ON agent_media_manifests(agent_id,manifest_sha256);
        CREATE TRIGGER IF NOT EXISTS agent_media_manifests_no_update
            BEFORE UPDATE ON agent_media_manifests
            BEGIN SELECT RAISE(ABORT, 'agent media manifests are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS agent_media_manifests_no_delete
            BEFORE DELETE ON agent_media_manifests
            BEGIN SELECT RAISE(ABORT, 'agent media manifests are immutable'); END;

        -- Player reports are event records, not a remote command channel.  A
        -- separate runtime can derive current state without giving it any
        -- authority over Agent configuration, Jobs, tunnels or media files.
        CREATE TABLE IF NOT EXISTS agent_media_player_reports (
            report_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            manifest_version TEXT NOT NULL,
            screen_id TEXT NOT NULL,
            campaign_id TEXT NOT NULL DEFAULT '',
            revision_no INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL,
            video_sha256 TEXT NOT NULL DEFAULT '',
            playlist TEXT NOT NULL DEFAULT '',
            free_bytes INTEGER NOT NULL DEFAULT 0,
            vlc_version TEXT NOT NULL DEFAULT '',
            graphics_json TEXT NOT NULL DEFAULT '{}',
            detail_json TEXT NOT NULL DEFAULT '{}',
            reported_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_media_player_reports_latest
            ON agent_media_player_reports(agent_id,screen_id,reported_at DESC);
        CREATE TRIGGER IF NOT EXISTS agent_media_player_reports_no_update
            BEFORE UPDATE ON agent_media_player_reports
            BEGIN SELECT RAISE(ABORT, 'agent media player reports are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS agent_media_player_reports_no_delete
            BEFORE DELETE ON agent_media_player_reports
            BEGIN SELECT RAISE(ABORT, 'agent media player reports are immutable'); END;
        """
    )

    # Migrate every legacy/repair copy. Leaving the source tables in place
    # gives an administrator a recovery path and is harmless because inserts
    # are idempotent.
    legacy_agent_tables = [str(r[0]) for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'agents_v2032_legacy%' OR name LIKE 'agents_v2035_repair%')"
    ).fetchall()]
    for legacy in legacy_agent_tables:
        qlegacy = legacy.replace('"', '""')
        for row in con.execute(f'SELECT * FROM "{qlegacy}"').fetchall():
            item = dict(row)
            aid = str(item.get("agent_id") or "").strip() or _legacy_agent_id(str(item.get("site_code") or ""), str(item.get("hostname") or ""))
            digest = str(item.get("token_hash") or "").strip()
            if not digest:
                # A row without an authentication hash was never a usable
                # enrollment. Keep migration deterministic but avoid violating
                # token_hash UNIQUE with repeated empty strings.
                digest = _token_hash(f"legacy-unusable:{aid}")
            con.execute(
                """INSERT OR IGNORE INTO agents(
                   agent_id,site_code,site_name,agent_name,hostname,token_hash,agent_version,protocol_version,
                   platform,architecture,host_profile,capabilities_json,last_remote_ip,last_seen,enrolled_at,status
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    aid, item.get("site_code") or "", item.get("site_name"), item.get("agent_name"),
                    item.get("hostname"), digest, item.get("agent_version"), item.get("protocol_version"),
                    item.get("platform"), item.get("architecture"), item.get("host_profile"),
                    item.get("capabilities_json"), item.get("last_remote_ip"), item.get("last_seen"),
                    item.get("enrolled_at"), item.get("status") or "ONLINE",
                ),
            )

    legacy_job_tables = [str(r[0]) for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'jobs_v2032_legacy%' OR name LIKE 'jobs_v2035_repair%')"
    ).fetchall()]
    for legacy in legacy_job_tables:
        qlegacy = legacy.replace('"', '""')
        for row in con.execute(f'SELECT * FROM "{qlegacy}"').fetchall():
            item = dict(row)
            site_code = str(item.get("site_code") or "")
            aid = str(item.get("agent_id") or "").strip()
            if not aid:
                matches = con.execute(
                    "SELECT agent_id FROM agents WHERE site_code=? ORDER BY last_seen DESC", (site_code,)
                ).fetchall()
                if len(matches) != 1:
                    continue
                aid = str(matches[0]["agent_id"])
            if con.execute("SELECT 1 FROM agents WHERE agent_id=?", (aid,)).fetchone() is None:
                continue
            con.execute(
                """INSERT OR IGNORE INTO jobs(
                   job_id,agent_id,site_code,site_name,status,created_at,claimed_at,updated_at,finished_at,
                   package_path,package_sha256,package_signature,package_key_id,result_path,result_sha256,
                   cancel_requested,last_status_json,error
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    item.get("job_id"), aid, site_code, item.get("site_name"), item.get("status") or "QUEUED",
                    item.get("created_at"), item.get("claimed_at"), item.get("updated_at"), item.get("finished_at"),
                    item.get("package_path") or "", item.get("package_sha256") or "", item.get("package_signature"),
                    item.get("package_key_id"), item.get("result_path"), item.get("result_sha256"),
                    int(item.get("cancel_requested") or 0), item.get("last_status_json"), item.get("error"),
                ),
            )

    legacy_release_tables = [str(r[0]) for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'agent_releases_v2035_repair%'"
    ).fetchall()]
    for legacy in legacy_release_tables:
        qlegacy = legacy.replace('"', '""')
        for row in con.execute(f'SELECT * FROM "{qlegacy}"').fetchall():
            item = dict(row)
            con.execute(
                """INSERT OR IGNORE INTO agent_releases(
                   platform,architecture,channel,version,protocol_version,min_agent_version,bundle_path,bundle_sha256,
                   signature,key_id,notes,created_at,approval_state,approved_at,approved_by,approval_note
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    item.get("platform"), item.get("architecture"), item.get("channel"), item.get("version"),
                    item.get("protocol_version"), item.get("min_agent_version"), item.get("bundle_path"), item.get("bundle_sha256"),
                    item.get("signature"), item.get("key_id"), item.get("notes"), item.get("created_at"),
                    item.get("approval_state") or "DRAFT", item.get("approved_at"), item.get("approved_by"), item.get("approval_note"),
                ),
            )

    legacy_manifest_tables = [str(r[0]) for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'agent_media_manifests_v2438_reissue%'"
    ).fetchall()]
    manifest_required = {
        "agent_id", "manifest_version", "manifest_sha256", "key_id",
        "signature", "manifest_json", "created_at",
    }
    for legacy in legacy_manifest_tables:
        if not manifest_required.issubset(columns(legacy)):
            continue
        qlegacy = legacy.replace('"', '""')
        con.execute(
            f"""INSERT OR IGNORE INTO agent_media_manifests(
                   agent_id,manifest_version,manifest_sha256,key_id,signature,manifest_json,created_at
                ) SELECT agent_id,manifest_version,manifest_sha256,key_id,signature,manifest_json,created_at
                    FROM "{qlegacy}" ORDER BY CAST(manifest_version AS INTEGER),rowid"""
        )

    # Additive migration for valid intermediate schemas.
    for table, column, ddl in [
        ("agents","agent_name","TEXT"),
        ("agents","protocol_version","TEXT"),
        ("agents","platform","TEXT"),
        ("agents","architecture","TEXT"),
        ("agents","host_profile","TEXT"),
        ("agents","capabilities_json","TEXT"),
        ("agents","diagnostics_json","TEXT"),
        ("agents","mtls_fingerprint","TEXT"),
        ("agents","last_remote_ip","TEXT"),
        ("jobs","package_signature","TEXT"),
        ("jobs","package_key_id","TEXT"),
        ("agent_releases","approval_state","TEXT NOT NULL DEFAULT 'DRAFT'"),
        ("agent_releases","approved_at","TEXT"),
        ("agent_releases","approved_by","TEXT"),
        ("agent_releases","approval_note","TEXT"),
        # Immutable start time plus a numeric last-report time let the Gateway
        # expire abandoned VLC installers without parsing locale-dependent ISO
        # text or blocking all future approvals for the Agent.
        ("agent_vlc_offline_install_requests","started_at","TEXT"),
        ("agent_vlc_offline_install_requests","started_unix","INTEGER"),
        ("agent_vlc_offline_install_requests","reported_unix","INTEGER"),
    ]:
        cols = columns(table)
        if column not in cols:
            con.execute(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {ddl}')
    # P6 enrollment-grant metadata. Existing grants remain valid until
    # expiry; new grants receive a revocable public GrantId while the raw
    # secret itself is still stored only as SHA-256.
    for column, ddl in [
        ("grant_id", "TEXT"),
        ("revoked_at", "TEXT"),
        ("revoke_reason", "TEXT"),
    ]:
        cols = columns("enrollment_grants")
        if column not in cols:
            con.execute(f'ALTER TABLE "enrollment_grants" ADD COLUMN "{column}" {ddl}')
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_enrollment_grants_id ON enrollment_grants(grant_id) WHERE grant_id IS NOT NULL")
    con.execute("UPDATE agent_releases SET approval_state='DRAFT' WHERE approval_state IS NULL OR TRIM(approval_state)='' ")
