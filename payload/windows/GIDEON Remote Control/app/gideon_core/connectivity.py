from __future__ import annotations

from gideon_common.observability import best_effort_warning

import asyncio
import contextlib
import datetime as dt
import ipaddress
import re
import sys
from dataclasses import dataclass, asdict
from typing import Iterable, Any


@dataclass(slots=True)
class ConnectivitySnapshot:
    State: str
    Mode: str
    Reachable: bool
    SuccessCount: int
    TargetCount: int
    SourceIPs: list[str]
    ReachableTargets: list[str]
    FailedTargets: list[str]
    CheckedAt: str
    SuccessRatio: float = 0.0
    RequiredSuccesses: int = 1

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ConnectivityGate:
    """Comprueba el camino real TCP/22 hacia servidores GIDEON.

    No depende de FortiClient ni del nombre del adaptador. Si la IP origen cae
    dentro de vpn_source_networks se etiqueta VPN; cualquier otro camino válido
    se etiqueta DIRECT.
    """

    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        self.cfg = dict(cfg or {})
        self.port = int(self.cfg.get("port", 22) or 22)
        self.timeout = max(0.3, float(self.cfg.get("probe_timeout_seconds", 2.0) or 2.0))
        self.sample_size = max(1, int(self.cfg.get("sample_targets", 5) or 5))
        self.check_every = max(1.0, float(self.cfg.get("recheck_seconds", 5) or 5))
        self.online_min_success_targets = max(1, int(self.cfg.get("online_min_success_targets", 2) or 2))
        self.online_min_success_ratio = min(1.0, max(0.0, float(self.cfg.get("online_min_success_ratio", 0.40) or 0.40)))
        self.vpn_networks = []
        for raw in self.cfg.get("vpn_source_networks", ["10.213.10.0/24"]):
            try:
                self.vpn_networks.append(ipaddress.ip_network(str(raw), strict=False))
            except Exception as exc:
                best_effort_warning(f"Red VPN inválida ignorada: {raw}", exc)

    def _mode(self, source_ips: Iterable[str]) -> str:
        has_vpn = False
        has_other = False
        for raw in source_ips:
            try:
                ip = ipaddress.ip_address(raw)
            except Exception:
                continue
            if any(ip in network for network in self.vpn_networks):
                has_vpn = True
            else:
                has_other = True
        if has_vpn and has_other:
            return "MIXED"
        if has_vpn:
            return "VPN"
        if has_other:
            return "DIRECT"
        return "UNKNOWN"

    async def _probe_one(self, target: str) -> tuple[str, bool, str | None]:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, self.port),
                timeout=self.timeout,
            )
            sockname = writer.get_extra_info("sockname")
            source = str(sockname[0]) if sockname else None
            return target, True, source
        except Exception:
            return target, False, None
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as exc:
                    best_effort_warning(f"No se pudo cerrar socket de prueba hacia {target}", exc)

    async def probe(self, targets: Iterable[str]) -> ConnectivitySnapshot:
        unique = []
        for value in targets:
            text = str(value).strip()
            if text and text not in unique:
                unique.append(text)
            if len(unique) >= self.sample_size:
                break
        if not unique:
            return ConnectivitySnapshot(
                State="UNKNOWN", Mode="UNKNOWN", Reachable=False,
                SuccessCount=0, TargetCount=0, SourceIPs=[],
                ReachableTargets=[], FailedTargets=[],
                CheckedAt=dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            )
        rows = await asyncio.gather(*(self._probe_one(t) for t in unique))
        reachable = [t for t, ok, _ in rows if ok]
        failed = [t for t, ok, _ in rows if not ok]
        sources = []
        for _, ok, src in rows:
            if ok and src and src not in sources:
                sources.append(src)
        successes = len(reachable)
        target_count = len(unique)
        ratio = (float(successes) / float(target_count)) if target_count else 0.0
        ratio_required = max(1, int((target_count * self.online_min_success_ratio) + 0.9999))
        required = min(target_count, max(1, min(self.online_min_success_targets, ratio_required)))
        if successes <= 0:
            state = "OFFLINE"
        elif successes >= required and ratio >= self.online_min_success_ratio:
            state = "ONLINE"
        else:
            state = "DEGRADED"
        return ConnectivitySnapshot(
            State=state,
            Mode=self._mode(sources),
            Reachable=successes > 0,
            SuccessCount=successes,
            TargetCount=target_count,
            SourceIPs=sources,
            ReachableTargets=reachable,
            FailedTargets=failed,
            CheckedAt=dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            SuccessRatio=ratio,
            RequiredSuccesses=required,
        )


@dataclass(slots=True)
class PingResult:
    Target: str
    Reachable: bool
    LatencyMs: float | None
    Output: str
    CheckedAt: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class PingProbe:
    """Test de conexión por PING (ICMP) hacia una lista de destinos.

    Invoca el binario `ping` nativo del sistema operativo (Windows, Linux o
    macOS) exactamente como lo haría un administrador desde la terminal, por
    lo que no requiere sockets crudos ni privilegios elevados. Es un chequeo
    independiente del `ConnectivityGate` (que valida TCP/22 para detectar
    VPN/DIRECT): PING solo confirma si el destino responde a nivel de red.
    """

    def __init__(
        self,
        *,
        count: int = 1,
        timeout_seconds: float = 2.0,
        max_concurrency: int = 20,
    ) -> None:
        self.count = max(1, int(count))
        self.timeout_seconds = max(0.5, float(timeout_seconds))
        self.max_concurrency = max(1, int(max_concurrency))

    def _build_command(self, target: str) -> list[str]:
        if sys.platform.startswith("win"):
            timeout_ms = int(self.timeout_seconds * 1000)
            return ["ping", "-n", str(self.count), "-w", str(timeout_ms), target]
        timeout_s = max(1, int(round(self.timeout_seconds)))
        return ["ping", "-c", str(self.count), "-W", str(timeout_s), target]

    @staticmethod
    def _extract_latency_ms(output: str) -> float | None:
        for pattern in (r"time[=<]\s*([\d.]+)\s*ms", r"tiempo[=<]\s*([\d.]+)\s*ms"):
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    continue
        return None

    async def _ping_one(self, target: str, semaphore: asyncio.Semaphore) -> PingResult:
        text = str(target).strip()
        checked_at = dt.datetime.now().astimezone().isoformat(timespec="seconds")
        if not text:
            return PingResult(Target=text, Reachable=False, LatencyMs=None, Output="IP/host vacío", CheckedAt=checked_at)
        async with semaphore:
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *self._build_command(text),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=(self.timeout_seconds * self.count) + 3.0,
                    )
                except asyncio.TimeoutError:
                    with contextlib.suppress(Exception):
                        proc.kill()
                    return PingResult(
                        Target=text, Reachable=False, LatencyMs=None,
                        Output="Timeout esperando respuesta del ping", CheckedAt=checked_at,
                    )
                output = (
                    (stdout or b"").decode("utf-8", errors="replace")
                    + (stderr or b"").decode("utf-8", errors="replace")
                )
                reachable = proc.returncode == 0
                latency = self._extract_latency_ms(output) if reachable else None
                return PingResult(
                    Target=text, Reachable=reachable, LatencyMs=latency,
                    Output=output.strip()[-400:], CheckedAt=checked_at,
                )
            except FileNotFoundError:
                return PingResult(
                    Target=text, Reachable=False, LatencyMs=None,
                    Output="Binario 'ping' no disponible en este sistema", CheckedAt=checked_at,
                )
            except Exception as exc:
                return PingResult(
                    Target=text, Reachable=False, LatencyMs=None,
                    Output=f"{type(exc).__name__}: {exc}", CheckedAt=checked_at,
                )

    async def probe_many(self, targets: Iterable[str]) -> list[PingResult]:
        semaphore = asyncio.Semaphore(self.max_concurrency)
        unique: list[str] = []
        for value in targets:
            text = str(value).strip()
            if text and text not in unique:
                unique.append(text)
        if not unique:
            return []
        return list(await asyncio.gather(*(self._ping_one(t, semaphore) for t in unique)))
