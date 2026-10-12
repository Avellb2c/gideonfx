"""Regression tests for fresh-machine users and cloned Agent sanitization."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing


ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = ROOT / "payload" / "windows" / "GIDEON Remote Control" / "app"
BOOTSTRAP = ROOT / "installers" / "tools" / "bootstrap_webadmin_users.py"
SANITIZER_PATH = ROOT / "installers" / "tools" / "sanitize_cloned_runtime_state.py"
LINUX_MASTER = ROOT / "installers" / "LINUX" / "install-gideon-master-linux.sh"
LINUX_NATIVE = ROOT / "payload" / "linux" / "app" / "deploy" / "aws" / "install_gideon_aws.sh"
CLAMAV_PREPARER = ROOT / "payload" / "linux" / "app" / "deploy" / "aws" / "prepare_gideon_clamav_db.sh"
CLAMD_UNIT = ROOT / "payload" / "linux" / "app" / "deploy" / "ubuntu" / "gideon-clamd.service"
CLAMD_CONFIG = ROOT / "payload" / "linux" / "app" / "deploy" / "ubuntu" / "gideon-clamd.conf"
CLAMAV_UPDATE_UNIT = ROOT / "payload" / "linux" / "app" / "deploy" / "aws" / "systemd" / "gideon-clamav-update.service"
DIAGNOSTICS = ROOT / "installers" / "LINUX" / "collect-gideon-install-diagnostics.sh"


def load_sanitizer():
    spec = importlib.util.spec_from_file_location("gideon_clone_sanitizer", SANITIZER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class BootstrapUsersTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gideon-fresh-bootstrap-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "web"
        self.config = self.root / "web_admin.json"
        self.users = self.root / "users.json"
        self.config.write_text(
            json.dumps({"data_dir": str(self.data_dir)}), encoding="utf-8"
        )
        self.users.write_text(
            json.dumps(
                [
                    {
                        "username": "dchaskypp",
                        "display_name": "Administrador GIDEON",
                        "role": "SUPERADMIN",
                        "password_env": "GIDEON_TEST_PWD_1",
                    },
                    {
                        "username": "damautapp",
                        "display_name": "DAMAUTAPP",
                        "role": "ADMIN",
                        "password_env": "GIDEON_TEST_PWD_2",
                    },
                ]
            ),
            encoding="utf-8",
        )

    def run_bootstrap(self, password_1: str, password_2: str, *, rotate=False):
        env = os.environ.copy()
        env["GIDEON_TEST_PWD_1"] = password_1
        env["GIDEON_TEST_PWD_2"] = password_2
        command = [
            sys.executable,
            str(BOOTSTRAP),
            "--app-root",
            str(APP_ROOT),
            "--config",
            str(self.config),
            "--users-json",
            str(self.users),
        ]
        if rotate:
            command.append("--rotate-existing")
        result = subprocess.run(command, env=env, text=True, capture_output=True)
        self.assertEqual(
            result.returncode,
            0,
            msg=f"bootstrap stderr:\n{result.stderr}\nbootstrap stdout:\n{result.stdout}",
        )
        self.assertNotIn(password_1, result.stdout)
        self.assertNotIn(password_2, result.stdout)
        return json.loads(result.stdout)

    def test_both_temporary_users_require_password_change(self):
        first_1 = "A9!Fresh-Dchaskypp-Password-01"
        first_2 = "A9!Fresh-Damautapp-Password-02"
        result = self.run_bootstrap(first_1, first_2)
        self.assertEqual(
            [(x["username"], x["status"]) for x in result["users"]],
            [("dchaskypp", "CREATED"), ("damautapp", "CREATED")],
        )

        db = self.data_dir / "security.sqlite3"
        with closing(sqlite3.connect(db)) as con:
            rows = con.execute(
                "SELECT username,role,must_change_password,mfa_enabled "
                "FROM users ORDER BY id"
            ).fetchall()
        self.assertEqual(
            rows,
            [
                ("dchaskypp", "SUPERADMIN", 1, 0),
                ("damautapp", "ADMIN", 1, 0),
            ],
        )

    def test_new_machine_rotation_discards_old_mfa_and_recovery(self):
        self.run_bootstrap(
            "A9!First-Dchaskypp-Password-01",
            "A9!First-Damautapp-Password-02",
        )
        db = self.data_dir / "security.sqlite3"
        with closing(sqlite3.connect(db)) as con:
            user_id = con.execute(
                "SELECT id FROM users WHERE username='dchaskypp'"
            ).fetchone()[0]
            con.execute(
                "UPDATE users SET mfa_enabled=1,mfa_secret='legacy-secret' WHERE id=?",
                (user_id,),
            )
            con.execute(
                "INSERT INTO recovery_codes(user_id,token_hash,created_at,expires_unix,used_at) "
                "VALUES(?,?,?,?,NULL)",
                (user_id, "legacy-token-hash", "2026-01-01T00:00:00Z", 4102444800),
            )
            con.commit()

        result = self.run_bootstrap(
            "A9!Rotated-Dchaskypp-Password-03",
            "A9!Rotated-Damautapp-Password-04",
            rotate=True,
        )
        self.assertTrue(all(x["status"] == "ROTATED" for x in result["users"]))
        with closing(sqlite3.connect(db)) as con:
            row = con.execute(
                "SELECT mfa_enabled,mfa_secret,must_change_password "
                "FROM users WHERE username='dchaskypp'"
            ).fetchone()
            recovery = con.execute(
                "SELECT COUNT(*) FROM recovery_codes WHERE user_id=?", (user_id,)
            ).fetchone()[0]
        self.assertEqual(row, (0, None, 1))
        self.assertEqual(recovery, 0)


class AgentSanitizerTests(unittest.TestCase):
    def test_new_machine_removes_cloned_agent_authorization_only(self):
        sanitizer = load_sanitizer()
        with tempfile.TemporaryDirectory(prefix="gideon-agent-sanitize-") as td:
            db = Path(td) / "gateway.sqlite3"
            with closing(sqlite3.connect(db)) as con:
                con.executescript(
                    """
                    CREATE TABLE agents(agent_id TEXT);
                    CREATE TABLE enrollment_grants(token_hash TEXT);
                    CREATE TABLE jobs(job_id TEXT);
                    CREATE TABLE agent_configurations(agent_id TEXT);
                    CREATE TABLE agent_config_status(agent_id TEXT);
                    CREATE TABLE agent_releases(version TEXT);
                    INSERT INTO agents VALUES('old-agent');
                    INSERT INTO enrollment_grants VALUES('old-grant');
                    INSERT INTO jobs VALUES('old-job');
                    INSERT INTO agent_configurations VALUES('old-agent');
                    INSERT INTO agent_config_status VALUES('old-agent');
                    INSERT INTO agent_releases VALUES('6.3.4');
                    """
                )
                con.commit()

            report = sanitizer.sanitize_database(db, reset_agent_state=True)
            self.assertEqual(report["agent_rows_deleted"], 5)
            with closing(sqlite3.connect(db)) as con:
                for table in (
                    "agents",
                    "enrollment_grants",
                    "jobs",
                    "agent_configurations",
                    "agent_config_status",
                ):
                    self.assertEqual(
                        con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0
                    )
                self.assertEqual(
                    con.execute("SELECT COUNT(*) FROM agent_releases").fetchone()[0], 1
                )


class LinuxClamavBootstrapTests(unittest.TestCase):
    def test_oneclick_requires_updater_and_rechecks_private_database(self):
        master = LINUX_MASTER.read_text(encoding="utf-8")
        native = LINUX_NATIVE.read_text(encoding="utf-8")
        helper = CLAMAV_PREPARER.read_text(encoding="utf-8")
        clamd_unit = CLAMD_UNIT.read_text(encoding="utf-8")
        clamd_config = CLAMD_CONFIG.read_text(encoding="utf-8")
        update_unit = CLAMAV_UPDATE_UNIT.read_text(encoding="utf-8")
        diagnostics = DIAGNOSTICS.read_text(encoding="utf-8")

        self.assertIn("clamav clamav-freshclam", master)
        self.assertIn("clamav-daemon clamdscan", master)
        self.assertIn('CLAMAV_PREPARER="$APPROOT/source/app/deploy/aws/prepare_gideon_clamav_db.sh"', master)
        self.assertIn('"$CLAMAV_PREPARER" --ensure', master)
        self.assertIn('CLAMAV_PREPARER="$ROOT/deploy/aws/prepare_gideon_clamav_db.sh"', native)
        self.assertIn("gideon-clamav-update.timer", native)
        self.assertIn("gideon-clamd.service", native)
        self.assertIn("gideon-clamd.apparmor", native)
        self.assertIn("gideon-freshclam.apparmor", native)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", clamd_unit)
        self.assertIn("LocalSocket /run/gideon-clamd/clamd.sock", clamd_config)
        self.assertIn("SelfCheck 0", clamd_config)
        self.assertIn("systemctl try-restart gideon-clamd.service", update_unit)
        self.assertIn("MemoryMax=1536M", update_unit)
        self.assertIn("CLAMAV_SYSTEM_DB_IMPORT=PASS", helper)
        self.assertIn("for attempt in 1 2 3", helper)
        self.assertIn("clamav-update-tail.txt", diagnostics)
        self.assertIn("clamav-database-inventory.txt", diagnostics)


if __name__ == "__main__":
    unittest.main(verbosity=2)
