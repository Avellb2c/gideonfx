from __future__ import annotations

from gideon_common.observability import best_effort_warning

from pathlib import Path

from gideon_application.ports import ScriptInteractionAnalyzerPort
from gideon_application.script_registry import ScriptRegistry
from gideon_core.launch import LaunchPlan, LaunchRequest, LaunchService
from gideon_domain import RiskLevel
from gideon_io import atomic_write_json, read_json_retry


class LegacyScriptLaunchAdapter:
    """Adapter SOLID sobre el FAN-OUT existente.

    Mantiene el motor probado, pero aplica el Script Registry antes del launch.
    """

    def __init__(
        self,
        service: LaunchService,
        script_registry: ScriptRegistry,
        interaction_analyzer: ScriptInteractionAnalyzerPort,
    ) -> None:
        self._service: LaunchService = service
        self._script_registry: ScriptRegistry = script_registry
        self._interaction_analyzer: ScriptInteractionAnalyzerPort = interaction_analyzer

    def _apply_script_contracts(self, plan: LaunchPlan) -> None:
        for script_path in plan.request.scripts:
            path: Path = Path(script_path).resolve()
            manifest = self._script_registry.load(path)
            plan.preflight.add(
                f"Script manifest · {manifest.name}",
                True,
                f"v{manifest.version} · riesgo {manifest.risk.value} · timeout {manifest.timeout_seconds}s",
            )
            if manifest.risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
                plan.preflight.add(
                    f"Riesgo · {manifest.name}",
                    False,
                    f"Script clasificado {manifest.risk.value}; requiere revisión/confirmación operativa.",
                    warning=True,
                )
            if manifest.requires_reboot:
                plan.preflight.add(
                    f"Reinicio · {manifest.name}",
                    False,
                    "El manifest declara posible reinicio del host.",
                    warning=True,
                )

            if path.suffix.lower() == ".ps1" and path.is_file():
                findings = self._interaction_analyzer.analyze(path)
                details: list[str] = [
                    f"{finding.label} (línea {finding.line})"
                    for finding in findings
                ]
                plan.preflight.add(
                    f"No interactivo · {manifest.name}",
                    not findings,
                    (
                        "OK · sin comandos de entrada interactiva"
                        if not findings
                        else "comandos interactivos detectados: " + ", ".join(details)
                    ),
                )

    def build_plan(self, request: LaunchRequest) -> LaunchPlan:
        plan: LaunchPlan = self._service.build_plan(request)
        self._apply_script_contracts(plan)
        return plan

    def bootstrap_manifest(self, plan: LaunchPlan) -> dict[str, object]:
        manifest: dict[str, object] = dict(self._service.bootstrap_manifest(plan))
        manifests: list[dict[str, object]] = []
        for script_path in plan.request.scripts:
            script = self._script_registry.load(Path(script_path))
            manifests.append(
                {
                    "Id": script.script_id,
                    "Name": script.name,
                    "Version": script.version,
                    "Risk": script.risk.value,
                    "TimeoutSeconds": script.timeout_seconds,
                    "RequiresAdmin": script.requires_admin,
                    "RequiresNetwork": script.requires_network,
                    "RequiresReboot": script.requires_reboot,
                    "MinimumPowerShell": script.minimum_powershell,
                }
            )
        manifest["ScriptRegistry"] = manifests
        try:
            persisted: object = read_json_retry(plan.manifest_path, retries=3)
            if isinstance(persisted, dict):
                persisted["ScriptRegistry"] = manifests
                atomic_write_json(plan.manifest_path, persisted, lock_timeout=2.0, retries=8)
                manifest = dict(persisted)
        except Exception as exc:
            # El metadata adicional nunca debe bloquear el Job principal.
            best_effort_warning("No se pudo persistir metadata adicional del launch manifest", exc)
        return manifest

    def mark_started(self, plan: LaunchPlan, pid: int) -> dict[str, object]:
        return dict(self._service.mark_started(plan, pid))

    def mark_failed(
        self,
        plan: LaunchPlan,
        *,
        error: str,
        return_code: int | None = None,
        log_tail: str | None = None,
    ) -> dict[str, object]:
        return dict(
            self._service.mark_failed(
                plan,
                error=error,
                return_code=return_code,
                log_tail=log_tail,
            )
        )
