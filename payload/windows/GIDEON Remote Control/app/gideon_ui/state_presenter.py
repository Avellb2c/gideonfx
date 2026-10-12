from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StatePresentation:
    label: str
    kind: str


_JOB_STATES: dict[str, StatePresentation] = {
    "CREATED": StatePresentation("Creado", "neutral"),
    "PREFLIGHT": StatePresentation("Validando", "info"),
    "STARTING": StatePresentation("Iniciando", "info"),
    "DISPATCHING": StatePresentation("Distribuyendo", "info"),
    "RUNNING": StatePresentation("Ejecutando", "info"),
    "COLLECTING": StatePresentation("Recolectando", "info"),
    "WAITING_REMOTE_REPORTS": StatePresentation("Esperando resultados", "warning"),
    "MONITORING": StatePresentation("Supervisando", "info"),
    "WAITING_CONNECTIVITY": StatePresentation("Esperando conectividad", "warning"),
    "WAITING_CONNECTION": StatePresentation("Esperando conexión", "warning"),
    "COMPLETED": StatePresentation("Completado", "success"),
    "COMPLETED_WITH_WARNINGS": StatePresentation("Completado con advertencias", "warning"),
    "COMPLETED_WITH_ERRORS": StatePresentation("Completado con errores", "warning"),
    "COMPLETED_WITH_SKIPPED": StatePresentation("Completado con omitidos", "warning"),
    "PARTIAL": StatePresentation("Parcial", "warning"),
    "FAILED": StatePresentation("Fallido", "danger"),
    "LAUNCH_FAILED": StatePresentation("No pudo iniciar", "danger"),
    "CANCEL_REQUESTED": StatePresentation("Cancelación solicitada", "warning"),
    "CANCELLING": StatePresentation("Cancelando", "warning"),
    "CANCELLED": StatePresentation("Cancelado", "neutral"),
    "CANCELLED_WITH_ERRORS": StatePresentation("Cancelado con errores", "warning"),
    "INTERRUPTED": StatePresentation("Interrumpido", "danger"),
    "ACTION_REQUIRED": StatePresentation("Requiere acción", "warning"),
}


def present_job_state(value: object) -> StatePresentation:
    raw = str(value or "UNKNOWN").strip().upper()
    return _JOB_STATES.get(raw, StatePresentation(raw.replace("_", " ").title(), "neutral"))


def friendly_job_state(value: object) -> str:
    return present_job_state(value).label
