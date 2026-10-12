from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from gideon_domain import HostTarget, Outcome, RiskLevel, ScriptManifest


class ScriptRegistry:
    """Registro tipado de scripts y sus requisitos operativos."""

    def __init__(self, scripts_root: Path) -> None:
        self._scripts_root: Path = Path(scripts_root).resolve()

    @staticmethod
    def sidecar_path(script_path: Path) -> Path:
        return script_path.with_suffix(".execution.json")

    @staticmethod
    def _risk(value: object) -> RiskLevel:
        raw: str = str(value or "LOW").strip().upper()
        try:
            return RiskLevel(raw)
        except ValueError:
            return RiskLevel.LOW

    def load(self, script_path: Path) -> ScriptManifest:
        path: Path = Path(script_path).resolve()
        sidecar: Path = self.sidecar_path(path)
        data: dict[str, object] = {}

        if sidecar.exists():
            try:
                parsed: object = json.loads(sidecar.read_text(encoding="utf-8-sig"))
                if isinstance(parsed, dict):
                    data = dict(parsed)
            except (OSError, json.JSONDecodeError):
                data = {}

        execution_raw: object = data.get("Execution")
        execution: dict[str, object] = dict(execution_raw) if isinstance(execution_raw, dict) else {}

        supported_raw: object = data.get("supported_platforms", data.get("platforms", ["windows"]))
        supported: tuple[str, ...]
        if isinstance(supported_raw, list):
            supported = tuple(str(x).strip().lower() for x in supported_raw if str(x).strip())
        else:
            supported = ("windows",)

        profiles_raw: object = data.get("host_profiles", [])
        host_profiles: tuple[str, ...]
        if isinstance(profiles_raw, list):
            host_profiles = tuple(str(x).strip() for x in profiles_raw if str(x).strip())
        else:
            host_profiles = ()

        return ScriptManifest(
            script_id=str(data.get("id") or path.stem),
            name=str(data.get("name") or path.stem),
            version=str(data.get("version") or "1.0.0"),
            path=path,
            risk=self._risk(data.get("risk")),
            minimum_powershell=str(data.get("minimum_powershell") or data.get("minimumPowerShell") or "5.1"),
            requires_admin=bool(data.get("requires_admin", data.get("requiresAdmin", True))),
            requires_network=bool(data.get("requires_network", data.get("requiresNetwork", False))),
            requires_reboot=bool(data.get("requires_reboot", data.get("requiresReboot", False))),
            timeout_seconds=max(
                1,
                int(
                    data.get("timeout_seconds")
                    or data.get("timeoutSeconds")
                    or execution.get("TimeoutSeconds")
                    or 1800
                ),
            ),
            continue_on_error=bool(
                data.get(
                    "continue_on_error",
                    data.get("continueOnError", execution.get("ContinueOnError", True)),
                )
            ),
            supported_platforms=supported or ("windows",),
            host_profiles=host_profiles,
            description=str(data.get("description") or ""),
        )

    def list_manifests(self) -> list[ScriptManifest]:
        manifests: list[ScriptManifest] = []
        if not self._scripts_root.exists():
            return manifests
        for path in sorted(self._scripts_root.iterdir()):
            if path.is_file() and path.suffix.lower() in {".ps1", ".py", ".sh", ".command", ".cmd", ".bat"}:
                manifests.append(self.load(path))
        return manifests


class ScriptCompatibilityService:
    def validate(self, script: ScriptManifest, site: HostTarget) -> Outcome[None]:
        if not script.path.is_file():
            return Outcome.failure("SCRIPT_NOT_FOUND", str(script.path))

        if site.platform.lower() not in {x.lower() for x in script.supported_platforms}:
            return Outcome.failure(
                "SCRIPT_PLATFORM_INCOMPATIBLE",
                f"{script.name} no soporta {site.platform}.",
            )

        if script.host_profiles and site.host_profile not in script.host_profiles:
            return Outcome.failure(
                "SCRIPT_HOST_PROFILE_INCOMPATIBLE",
                f"{script.name} no está habilitado para {site.host_profile}.",
            )

        return Outcome.success(None)
