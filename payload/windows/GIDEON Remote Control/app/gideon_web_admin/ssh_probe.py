from __future__ import annotations

"""Constrained SSH + SFTP connectivity probe for WebAdmin.

The browser-facing probe only accepts canonical GIDEON site codes.  A lower-level
``probe_host`` entry point is used internally by the trusted Agentless launcher
for hosts already selected from a GIDEON site group.  Both paths materialize one
vault identity only for the duration of the operation, use ``IdentitiesOnly``
and a GIDEON-owned ``known_hosts`` file, and never touch the system ssh-agent.

For SFTP the probe is deliberately read-only: it executes only ``pwd`` and
``quit``.  It does not create, upload, delete or rename remote files.
"""

import csv
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Callable

from .ssh_vault import SshIdentityVault, SshVaultError


class SshProbeError(RuntimeError):
    pass


class SshConnectionProbe:
    def __init__(self, app_root: Path, data_dir: Path, vault: SshIdentityVault) -> None:
        self.app_root = Path(app_root).resolve()
        self.data_dir = Path(data_dir).resolve()
        self.vault = vault
        self.known_hosts = self.data_dir / "security-assets" / "ssh-known-hosts"
        self.known_hosts.parent.mkdir(parents=True, exist_ok=True)

    def sites(self) -> list[dict[str, str]]:
        path = self.app_root / "config" / "sites.csv"
        rows: list[dict[str, str]] = []
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as fh:
                for raw in csv.DictReader(fh):
                    code = str(raw.get("SiteCode") or "").strip()
                    name = str(raw.get("SiteName") or "").strip()
                    host = str(raw.get("ServerIP") or "").strip()
                    if code and name and host:
                        rows.append({"code": code, "name": name, "host": host})
        except OSError:
            return []
        return sorted(rows, key=lambda x: (x["code"], x["name"]))

    def _site(self, site_code: str) -> dict[str, str]:
        clean = str(site_code or "").strip()
        row = next((x for x in self.sites() if x["code"] == clean), None)
        if row is None:
            raise SshProbeError("La sede no existe en config/sites.csv o no tiene ServerIP.")
        return row

    @staticmethod
    def _validate_user_port(username: str, port: int) -> tuple[str, int]:
        user = str(username or "").strip()
        if not user or len(user) > 64 or any(ch.isspace() for ch in user):
            raise SshProbeError("Usuario SSH inválido.")
        try:
            port_value = int(port)
        except (TypeError, ValueError) as exc:
            raise SshProbeError("Puerto SSH inválido.") from exc
        if not (1 <= port_value <= 65535):
            raise SshProbeError("Puerto SSH fuera de rango.")
        return user, port_value

    def _common_options(self, *, private_key: Path, timeout: int) -> list[str]:
        return [
            "-i", str(private_key),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=1",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null" if os.name != "nt" else "GlobalKnownHostsFile=NUL",
        ]

    @staticmethod
    def _run(
        runner: Callable[..., subprocess.CompletedProcess[str]],
        cmd: list[str],
        *,
        timeout: int,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "timeout": timeout + 5,
            "shell": False,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if input_text is not None:
            kwargs["input"] = input_text
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        return runner(cmd, **kwargs)

    @staticmethod
    def _detail(cp: subprocess.CompletedProcess[str], *, ok_text: str) -> str:
        value = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()[-3000:]
        return value or ok_text

    def probe_host(
        self,
        *,
        identity_id: str,
        host: str,
        site_code: str,
        site_name: str,
        username: str,
        port: int = 22,
        timeout_seconds: int = 12,
        require_sftp: bool = True,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> dict[str, Any]:
        """Validate authentication and protocol availability for a trusted host.

        ``host`` must come from trusted GIDEON inventory when this method is used
        outside tests.  Browser routes intentionally call :meth:`probe` instead,
        which resolves the host from ``config/sites.csv`` and does not accept an
        arbitrary destination.
        """
        user, port_value = self._validate_user_port(username, port)
        target = str(host or "").strip()
        if not target or len(target) > 255 or any(ch.isspace() for ch in target):
            raise SshProbeError("Host SSH inválido.")
        ssh = shutil.which("ssh.exe") or shutil.which("ssh")
        if not ssh:
            raise SshProbeError("SSH_CLIENT_MISSING: OpenSSH Client no está disponible en el servidor WebAdmin.")
        sftp = shutil.which("sftp.exe") or shutil.which("sftp")
        if require_sftp and not sftp:
            raise SshProbeError("SFTP_CLIENT_MISSING: sftp.exe/OpenSSH SFTP Client no está disponible en el servidor WebAdmin.")

        timeout = max(3, min(int(timeout_seconds), 30))
        self.known_hosts.touch(exist_ok=True)
        try:
            os.chmod(self.known_hosts, 0o600)
        except OSError:
            pass

        ssh_result: dict[str, Any]
        sftp_result: dict[str, Any]
        try:
            with self.vault.temporary_private_key(identity_id) as private_key:
                common = self._common_options(private_key=private_key, timeout=timeout)
                ssh_cmd = [
                    ssh,
                    "-T",
                    "-p", str(port_value),
                    *common,
                    f"{user}@{target}",
                    "echo GIDEON_SSH_PROBE_OK",
                ]
                try:
                    cp_ssh = self._run(runner, ssh_cmd, timeout=timeout)
                    ssh_ok = cp_ssh.returncode == 0 and "GIDEON_SSH_PROBE_OK" in (cp_ssh.stdout or "")
                    ssh_result = {
                        "ok": bool(ssh_ok),
                        "returncode": int(cp_ssh.returncode),
                        "detail": self._detail(cp_ssh, ok_text="SSH OK" if ssh_ok else f"ssh rc={cp_ssh.returncode}"),
                    }
                except subprocess.TimeoutExpired as exc:
                    ssh_result = {"ok": False, "returncode": 124, "detail": f"SSH_TIMEOUT: {target}:{port_value}"}
                    cp_ssh = None

                if not require_sftp:
                    sftp_result = {"ok": True, "returncode": 0, "detail": "SFTP_NOT_REQUIRED_FOR_PROFILE"}
                elif not ssh_result["ok"]:
                    # Authentication/control channel already failed. Repeating the
                    # same credential negotiation with SFTP would double timeout
                    # without adding diagnostic value.
                    sftp_result = {
                        "ok": False,
                        "returncode": int(ssh_result["returncode"]),
                        "detail": "SFTP_SKIPPED_DUE_TO_SSH_FAILURE",
                    }
                else:
                    assert sftp is not None
                    sftp_cmd = [
                        sftp,
                        "-b", "-",
                        "-P", str(port_value),
                        *common,
                        f"{user}@{target}",
                    ]
                    try:
                        cp_sftp = self._run(
                            runner,
                            sftp_cmd,
                            timeout=timeout,
                            input_text="pwd\nquit\n",
                        )
                        sftp_ok = cp_sftp.returncode == 0
                        sftp_result = {
                            "ok": bool(sftp_ok),
                            "returncode": int(cp_sftp.returncode),
                            "detail": self._detail(cp_sftp, ok_text="SFTP OK" if sftp_ok else f"sftp rc={cp_sftp.returncode}"),
                        }
                    except subprocess.TimeoutExpired:
                        sftp_result = {"ok": False, "returncode": 124, "detail": f"SFTP_TIMEOUT: {target}:{port_value}"}
        except SshVaultError:
            raise

        ok = bool(ssh_result.get("ok")) and bool(sftp_result.get("ok"))
        first_rc = 0 if ok else int(ssh_result.get("returncode") or sftp_result.get("returncode") or 1)
        summary = (
            f"SSH={'OK' if ssh_result.get('ok') else 'FAIL'}(rc={ssh_result.get('returncode')}); "
            f"SFTP={'OK' if sftp_result.get('ok') else 'FAIL'}(rc={sftp_result.get('returncode')})"
        )
        if not ok:
            fail_detail = ssh_result.get("detail") if not ssh_result.get("ok") else sftp_result.get("detail")
            summary += f" · {str(fail_detail or '')[:1200]}"
        return {
            "ok": ok,
            "site_code": str(site_code or "").strip(),
            "site_name": str(site_name or "").strip(),
            "host": target,
            "port": port_value,
            "username": user,
            "returncode": first_rc,
            "ssh": ssh_result,
            "sftp": sftp_result,
            "detail": summary,
        }

    def probe(
        self,
        *,
        identity_id: str,
        site_code: str,
        username: str,
        port: int = 22,
        timeout_seconds: int = 12,
        require_sftp: bool = True,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> dict[str, Any]:
        site = self._site(site_code)
        return self.probe_host(
            identity_id=identity_id,
            host=site["host"],
            site_code=site["code"],
            site_name=site["name"],
            username=username,
            port=port,
            timeout_seconds=timeout_seconds,
            require_sftp=require_sftp,
            runner=runner,
        )
