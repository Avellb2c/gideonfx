from __future__ import annotations

"""Focused no-network tests for the offline VLC authorization control path."""

import sys
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "payload" / "linux" / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from gideon_agent_gateway import GatewayDB  # noqa: E402
from gideon_agent_vlc_offline import OfflineVlcAuthorizationError, verify_install_authorization  # noqa: E402
from gideon_web_admin.security_assets import SecurityAssetManager  # noqa: E402
from gideon_web_admin.vlc_offline_install import build_install_authorization  # noqa: E402


class _SigningAssets:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()

    def signing_status(self):
        return {"usable": True}

    def signing_private_key_bytes(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


class OfflineVlcGatewayFlowTests(unittest.TestCase):
    @staticmethod
    def _enroll_ready_agent(db: GatewayDB, *, suffix: str, catalog: str) -> str:
        _token, agent_id = db.enroll_agent(
            "18622", "TEST", "test-host", "2.4.32", agent_id=f"agt-test-{suffix}",
            capabilities={"Player": {"OfflineVlc": {
                "State": "READY_FOR_EXPLICIT_INSTALL", "CatalogSha256": catalog,
            }}},
        )
        return agent_id

    def test_web_authorization_is_verified_byte_for_byte_by_agent(self) -> None:
        catalog = "c" * 64
        agent_id = "agt-test-crypto-contract"
        assets = _SigningAssets()
        with tempfile.TemporaryDirectory() as temp:
            public_key = Path(temp) / "release-signing-public.pem"
            public_key.write_bytes(assets.key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            envelope = build_install_authorization(
                agent_id=agent_id,
                catalog_sha256=catalog,
                security_assets=assets,
                gpl_acknowledged=True,
                request_id="vlc-contract-test-0001",
            )
            verified = verify_install_authorization(
                envelope,
                public_key_path=public_key,
                agent_id=agent_id,
                catalog_sha256=catalog,
            )
            self.assertEqual("vlc-contract-test-0001", verified["RequestId"])

            envelope["Payload"]["AgentId"] = "agt-tampered"
            with self.assertRaisesRegex(OfflineVlcAuthorizationError, "SIGNATURE_INVALID"):
                verify_install_authorization(
                    envelope,
                    public_key_path=public_key,
                    agent_id=agent_id,
                    catalog_sha256=catalog,
                )

    def test_external_openssh_ed25519_key_status_and_authorization_are_compatible(self) -> None:
        catalog = "d" * 64
        agent_id = "agt-test-openssh-contract"
        key = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_path = root / "release-signing-ed25519"
            private_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            ))
            assets = SecurityAssetManager(root / "security", {})
            assets.configure_external_signing_key(str(private_path.resolve()))
            self.assertTrue(assets.signing_status()["usable"])
            envelope = build_install_authorization(
                agent_id=agent_id,
                catalog_sha256=catalog,
                security_assets=assets,
                gpl_acknowledged=True,
                request_id="vlc-openssh-test-0001",
            )
            public_key = root / "release-signing-public.pem"
            public_key.write_bytes(assets.signing_public_key_bytes())
            verified = verify_install_authorization(
                envelope,
                public_key_path=public_key,
                agent_id=agent_id,
                catalog_sha256=catalog,
            )
            self.assertEqual("vlc-openssh-test-0001", verified["RequestId"])

    def test_signed_request_is_agent_bound_private_and_stateful(self) -> None:
        catalog = "a" * 64
        assets = _SigningAssets()
        with tempfile.TemporaryDirectory() as temp:
            db = GatewayDB(Path(temp))
            _token, agent_id = db.enroll_agent(
                "18622", "TEST", "test-host", "2.4.32", agent_id="agt-test-offline-vlc",
                capabilities={"Player": {"OfflineVlc": {
                    "State": "READY_FOR_EXPLICIT_INSTALL", "CatalogSha256": catalog,
                }}},
            )
            envelope = build_install_authorization(
                agent_id=agent_id, catalog_sha256=catalog, security_assets=assets, gpl_acknowledged=True,
            )
            created = db.request_agent_offline_vlc_install(agent_id, envelope, actor="tester")
            self.assertEqual(created["Status"], "REQUESTED")
            self.assertNotIn("Authorization", created)
            delivered = db.deliver_agent_offline_vlc_install_request(agent_id)
            self.assertEqual(delivered["State"], "DELIVERED")
            self.assertEqual(delivered["Authorization"]["Payload"]["AgentId"], agent_id)
            running = db.observe_agent_offline_vlc_install(
                agent_id, delivered["RequestId"], state="RUNNING", detail="VLC_OFFLINE_INSTALL_STARTED",
            )
            self.assertEqual(running["Status"], "RUNNING")
            installed = db.observe_agent_offline_vlc_install(
                agent_id, delivered["RequestId"], state="INSTALLED", detail="VLC_OFFLINE_INSTALLED",
            )
            self.assertEqual(installed["Status"], "INSTALLED")
            self.assertEqual(db.deliver_agent_offline_vlc_install_request(agent_id), {})

    def test_rejects_catalog_not_reported_by_authenticated_agent(self) -> None:
        assets = _SigningAssets()
        with tempfile.TemporaryDirectory() as temp:
            db = GatewayDB(Path(temp))
            _token, agent_id = db.enroll_agent("18622", "TEST", "test-host", "2.4.32", agent_id="agt-test-catalog")
            envelope = build_install_authorization(
                agent_id=agent_id, catalog_sha256="b" * 64, security_assets=assets, gpl_acknowledged=True,
            )
            with self.assertRaisesRegex(ValueError, "VLC_OFFLINE_AGENT_CATALOG_NOT_READY_OR_CHANGED"):
                db.request_agent_offline_vlc_install(agent_id, envelope, actor="tester")

    def test_every_active_state_blocks_reauthorization_and_ui_hides_action(self) -> None:
        catalog = "e" * 64
        assets = _SigningAssets()
        for active_state in ("REQUESTED", "DELIVERED", "DEFERRED", "RUNNING"):
            with self.subTest(active_state=active_state), tempfile.TemporaryDirectory() as temp:
                db = GatewayDB(Path(temp))
                agent_id = self._enroll_ready_agent(db, suffix=f"active-{active_state.lower()}", catalog=catalog)
                first = build_install_authorization(
                    agent_id=agent_id, catalog_sha256=catalog, security_assets=assets,
                    gpl_acknowledged=True, request_id=f"vlc-active-{active_state.lower()}-0001",
                )
                db.request_agent_offline_vlc_install(agent_id, first, actor="tester")
                delivered = None
                if active_state != "REQUESTED":
                    delivered = db.deliver_agent_offline_vlc_install_request(agent_id)
                if active_state in {"DEFERRED", "RUNNING"}:
                    db.observe_agent_offline_vlc_install(
                        agent_id, str(delivered["RequestId"]), state=active_state,
                        detail=f"VLC_OFFLINE_{active_state}",
                    )
                second = build_install_authorization(
                    agent_id=agent_id, catalog_sha256=catalog, security_assets=assets,
                    gpl_acknowledged=True, request_id=f"vlc-active-{active_state.lower()}-0002",
                )
                with self.assertRaisesRegex(ValueError, "VLC_OFFLINE_INSTALL_ALREADY_ACTIVE"):
                    db.request_agent_offline_vlc_install(agent_id, second, actor="tester")

        template = (APP / "gideon_web_admin" / "templates" / "agent_detail.html").read_text(encoding="utf-8")
        self.assertIn(
            "offline_request.Status not in ['REQUESTED','DELIVERED','DEFERRED','RUNNING']",
            template,
        )

    def test_concurrent_authorizations_preserve_single_active_request(self) -> None:
        catalog = "3" * 64
        assets = _SigningAssets()
        with tempfile.TemporaryDirectory() as temp:
            db = GatewayDB(Path(temp))
            agent_id = self._enroll_ready_agent(db, suffix="concurrent", catalog=catalog)
            envelopes = [
                build_install_authorization(
                    agent_id=agent_id,
                    catalog_sha256=catalog,
                    security_assets=assets,
                    gpl_acknowledged=True,
                    request_id=f"vlc-concurrent-test-000{index}",
                )
                for index in (1, 2)
            ]
            barrier = threading.Barrier(2)
            outcomes: list[str] = []
            outcome_lock = threading.Lock()

            def submit(envelope: dict) -> None:
                barrier.wait(timeout=5)
                try:
                    db.request_agent_offline_vlc_install(agent_id, envelope, actor="tester")
                    outcome = "CREATED"
                except ValueError as exc:
                    outcome = str(exc)
                with outcome_lock:
                    outcomes.append(outcome)

            threads = [threading.Thread(target=submit, args=(envelope,)) for envelope in envelopes]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())

            self.assertEqual(1, outcomes.count("CREATED"))
            self.assertEqual(1, outcomes.count("VLC_OFFLINE_INSTALL_ALREADY_ACTIVE"))
            with db.connect() as con:
                active = con.execute(
                    """SELECT COUNT(*) FROM agent_vlc_offline_install_requests
                       WHERE agent_id=? AND status IN ('REQUESTED','DELIVERED','DEFERRED','RUNNING')""",
                    (agent_id,),
                ).fetchone()[0]
            self.assertEqual(1, active)

    def test_running_watchdog_expires_stale_request_and_allows_new_signed_request(self) -> None:
        catalog = "f" * 64
        assets = _SigningAssets()
        with tempfile.TemporaryDirectory() as temp:
            db = GatewayDB(Path(temp))
            self.assertEqual(10, db.schema_status()["SchemaVersion"])
            agent_id = self._enroll_ready_agent(db, suffix="watchdog", catalog=catalog)
            first = build_install_authorization(
                agent_id=agent_id, catalog_sha256=catalog, security_assets=assets,
                gpl_acknowledged=True, request_id="vlc-watchdog-old-0001",
            )
            db.request_agent_offline_vlc_install(agent_id, first, actor="tester")
            delivered = db.deliver_agent_offline_vlc_install_request(agent_id)
            db.observe_agent_offline_vlc_install(
                agent_id, delivered["RequestId"], state="RUNNING", detail="VLC_OFFLINE_INSTALL_STARTED",
            )
            now_unix = int(time.time())
            with db.connect() as con:
                con.execute(
                    "UPDATE agent_vlc_offline_install_requests SET started_unix=?,reported_unix=? WHERE request_id=?",
                    (now_unix - 60, now_unix - 601, delivered["RequestId"]),
                )
                db._expire_offline_vlc_requests(con, now_unix=now_unix)
            expired = db.get_agent_offline_vlc_install_request(agent_id)
            self.assertEqual("EXPIRED", expired["Status"])
            self.assertNotIn("Authorization", expired)

            replacement = build_install_authorization(
                agent_id=agent_id, catalog_sha256=catalog, security_assets=assets,
                gpl_acknowledged=True, request_id="vlc-watchdog-new-0002",
            )
            created = db.request_agent_offline_vlc_install(agent_id, replacement, actor="tester")
            self.assertEqual("REQUESTED", created["Status"])
            self.assertNotIn("Authorization", created)

    def test_running_watchdog_has_absolute_ceiling_even_with_recent_reports(self) -> None:
        catalog = "2" * 64
        assets = _SigningAssets()
        with tempfile.TemporaryDirectory() as temp:
            db = GatewayDB(Path(temp))
            agent_id = self._enroll_ready_agent(db, suffix="watchdog-ceiling", catalog=catalog)
            envelope = build_install_authorization(
                agent_id=agent_id, catalog_sha256=catalog, security_assets=assets,
                gpl_acknowledged=True, request_id="vlc-watchdog-ceiling-0001",
            )
            db.request_agent_offline_vlc_install(agent_id, envelope, actor="tester")
            delivered = db.deliver_agent_offline_vlc_install_request(agent_id)
            db.observe_agent_offline_vlc_install(
                agent_id, delivered["RequestId"], state="RUNNING", detail="VLC_OFFLINE_INSTALL_RUNNING",
            )
            now_unix = int(time.time())
            with db.connect() as con:
                con.execute(
                    "UPDATE agent_vlc_offline_install_requests SET started_unix=?,reported_unix=? WHERE request_id=?",
                    (now_unix - (45 * 60) - 1, now_unix, delivered["RequestId"]),
                )
                db._expire_offline_vlc_requests(con, now_unix=now_unix)
            self.assertEqual("EXPIRED", db.get_agent_offline_vlc_install_request(agent_id)["Status"])

    def test_schema_v8_request_table_is_additively_upgraded_without_data_loss(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "gateway.sqlite3"
            con = sqlite3.connect(database)
            con.executescript(
                """
                CREATE TABLE agent_vlc_offline_install_requests (
                    request_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    authorization_json TEXT NOT NULL,
                    authorization_sha256 TEXT NOT NULL,
                    catalog_sha256 TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    expires_unix INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    requested_by TEXT,
                    delivered_at TEXT,
                    reported_at TEXT,
                    completed_at TEXT,
                    detail TEXT
                );
                INSERT INTO agent_vlc_offline_install_requests(
                    request_id,agent_id,authorization_json,authorization_sha256,catalog_sha256,
                    expires_at,expires_unix,status,requested_at
                ) VALUES('vlc-preserved-0001','agt-preserved','{}','hash','catalog','2099-01-01T00:00:00+00:00',
                         4070908800,'REQUESTED','2026-01-01T00:00:00+00:00');
                """
            )
            con.commit()
            con.close()
            db = GatewayDB(Path(temp))
            self.assertEqual(10, db.schema_status()["SchemaVersion"])
            with db.connect() as checked:
                columns = {str(row[1]) for row in checked.execute(
                    'PRAGMA table_info("agent_vlc_offline_install_requests")'
                ).fetchall()}
                preserved = checked.execute(
                    "SELECT request_id FROM agent_vlc_offline_install_requests WHERE request_id='vlc-preserved-0001'"
                ).fetchone()
            self.assertTrue({"started_at", "started_unix", "reported_unix"}.issubset(columns))
            self.assertIsNotNone(preserved)

    def test_pending_states_expire_at_signed_authorization_deadline(self) -> None:
        catalog = "1" * 64
        assets = _SigningAssets()
        for pending_state in ("REQUESTED", "DELIVERED", "DEFERRED"):
            with self.subTest(pending_state=pending_state), tempfile.TemporaryDirectory() as temp:
                db = GatewayDB(Path(temp))
                agent_id = self._enroll_ready_agent(db, suffix=f"expiry-{pending_state.lower()}", catalog=catalog)
                envelope = build_install_authorization(
                    agent_id=agent_id, catalog_sha256=catalog, security_assets=assets,
                    gpl_acknowledged=True, request_id=f"vlc-expiry-{pending_state.lower()}-0001",
                )
                db.request_agent_offline_vlc_install(agent_id, envelope, actor="tester")
                delivered = None
                if pending_state != "REQUESTED":
                    delivered = db.deliver_agent_offline_vlc_install_request(agent_id)
                if pending_state == "DEFERRED":
                    db.observe_agent_offline_vlc_install(
                        agent_id, str(delivered["RequestId"]), state="DEFERRED", detail="VLC_OFFLINE_DEFERRED_JOB",
                    )
                now_unix = int(time.time())
                with db.connect() as con:
                    con.execute(
                        "UPDATE agent_vlc_offline_install_requests SET expires_unix=? WHERE agent_id=?",
                        (now_unix - 1, agent_id),
                    )
                    db._expire_offline_vlc_requests(con, now_unix=now_unix)
                current = db.get_agent_offline_vlc_install_request(agent_id)
                self.assertEqual("EXPIRED", current["Status"])
                self.assertNotIn("Authorization", current)


if __name__ == "__main__":
    unittest.main()
