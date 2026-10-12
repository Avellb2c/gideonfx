from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .agent_installers import AgentInstallerError


class AgentInstallerPort(Protocol):
    def resolve_builder_selection(self, **kwargs: Any) -> dict[str, str]: ...
    def start_build(self, **kwargs: Any) -> dict[str, Any]: ...


class GatewayEndpointPort(Protocol):
    def endpoints(self) -> list[dict[str, Any]]: ...
    def resolve_selection(self, endpoint_id: str, gateway_input: str, gateway_mode: str) -> tuple[str, str]: ...


@dataclass(slots=True)
class InstallerBuildOrchestrator:
    """Application service that converts Web form intent into one installer build.

    The service depends on narrow protocols rather than FastAPI or concrete
    repositories.  HTTP concerns (CSRF, redirects and HTML errors) remain in the
    presentation layer.
    """

    installers: AgentInstallerPort
    endpoints: GatewayEndpointPort

    def queue(self, form: Mapping[str, Any], *, actor: str, remote_ip: str) -> dict[str, Any]:
        os_family = str(form.get("os_family") or "").strip()
        os_variant = str(form.get("os_variant") or "").strip()
        architecture = str(form.get("architecture") or "").strip()
        builder_profile = str(form.get("builder_profile") or "custom").strip()
        offline_vlc_distribution = ""
        offline_vlc_codename = ""
        # ``detached`` keeps the operational installer deployable while moving
        # the GPL corresponding-source closure into a separately signed legal
        # companion. ``bundled`` remains the larger all-in-one fallback.  The
        # obsolete ``component`` value described a non-playing core and stays
        # rejected before a queue row or enrollment grant can be created.
        vlc_delivery = str(form.get("vlc_delivery") or "detached").strip().lower()
        if vlc_delivery == "component":
            raise AgentInstallerError(
                "AGENT_VLC_COMPONENT_DELIVERY_UNAVAILABLE: seleccione detached para conservar "
                "VLC operativo y descargar las fuentes legales como paquete separado."
            )
        if vlc_delivery not in {"detached", "bundled"}:
            raise AgentInstallerError("Entrega VLC no permitida. Seleccione instalador operativo o kit completo.")

        if os_family:
            selection = self.installers.resolve_builder_selection(
                builder_profile=builder_profile,
                os_family=os_family,
                os_variant=os_variant,
                architecture=architecture,
                package_choice=str(form.get("package_choice") or "native"),
            )
            target_id = selection["target_id"]
            package_choice = selection["package_choice"]
            os_family = selection["os_family"]
            os_variant = selection["os_variant"]
            architecture = selection["architecture"]
            builder_profile = selection["builder_profile"]
            offline_vlc_distribution = selection["offline_vlc_distribution"]
            offline_vlc_codename = selection["offline_vlc_codename"]
        else:
            combined = str(form.get("target_package") or "")
            if "|" not in combined:
                raise AgentInstallerError("Seleccione un sistema operativo y formato de instalador.")
            target_id, package_choice = combined.split("|", 1)

        endpoint_id = str(form.get("gateway_endpoint_id") or "")
        gateway_input = str(form.get("gateway_url") or "")
        requested_mode = str(
            form.get("connectivity_mode") or form.get("gateway_mode") or "automatic"
        ).strip().lower()
        if requested_mode == "custom":
            requested_mode = "personalized"
        if requested_mode not in {"automatic", "production", "lan", "local_test", "personalized"}:
            raise AgentInstallerError("Modo de conectividad no permitido.")

        if str(form.get("build_action") or "") == "local_test" or requested_mode == "local_test":
            local_row = next(
                (x for x in self.endpoints.endpoints() if x.get("role") == "LOCAL_TEST" and x.get("selectable")),
                None,
            )
            if local_row is None:
                raise AgentInstallerError("No se pudo determinar el puerto local del Gateway para generar la prueba.")
            endpoint_id = str(local_row.get("id") or "")
            gateway_input = str(local_row.get("url") or "")
            requested_mode = "local_test"

        try:
            resolved_gateway, registry_mode = self.endpoints.resolve_selection(
                endpoint_id,
                gateway_input,
                "local_test" if requested_mode == "local_test" else ("manual" if endpoint_id == "manual" else requested_mode),
            )
        except ValueError as exc:
            raise AgentInstallerError(str(exc)) from exc

        if requested_mode == "local_test":
            resolved_mode = "local_test"
        elif registry_mode == "local_test":
            raise AgentInstallerError("El endpoint local solo puede usarse con 'Prueba local - esta PC'.")
        elif requested_mode in {"lan", "production", "personalized"}:
            resolved_mode = requested_mode
        else:
            resolved_mode = "automatic"

        enrollment_mode = str(form.get("enrollment_mode") or "individual")
        uses_default = {"individual": 1, "group": 10, "mass": 100}.get(enrollment_mode, 1)
        row = self.installers.start_build(
            target_id=target_id,
            package_choice=package_choice,
            gateway_url=resolved_gateway,
            gateway_mode=resolved_mode,
            channel=str(form.get("channel") or "stable"),
            ttl_hours=int(form.get("ttl_hours") or 24),
            max_uses=int(form.get("max_uses") or uses_default),
            actor=actor,
            remote_ip=remote_ip,
            site_code=str(form.get("site_code") or ""),
            site_name=str(form.get("site_name") or ""),
            agent_name=str(form.get("agent_name") or ""),
            builder_profile=builder_profile,
            os_family=os_family,
            os_variant=os_variant,
            architecture=architecture,
            offline_vlc_distribution=offline_vlc_distribution,
            offline_vlc_codename=offline_vlc_codename,
            enrollment_mode=enrollment_mode,
            agent_name_mode=str(form.get("agent_name_mode") or "automatic"),
            vlc_delivery=vlc_delivery,
        )
        return {
            "row": row,
            "target_id": target_id,
            "package_choice": package_choice,
            "builder_profile": builder_profile,
            "vlc_delivery": vlc_delivery,
        }
