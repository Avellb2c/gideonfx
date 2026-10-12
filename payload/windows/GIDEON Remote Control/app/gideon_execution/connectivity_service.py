from __future__ import annotations

from gideon_common.observability import best_effort_warning

import asyncio
import json
import subprocess
import time
from typing import Any, Optional

from gideon_admin import command_exists, now_iso
from gideon_common.process import windows_hidden_kwargs

def _run_local_powershell_json(script: str) -> Any:
    ps = command_exists("powershell.exe") or command_exists("powershell")
    if not ps:
        raise RuntimeError("No se encontró powershell.exe para medir la VPN.")
    cp = subprocess.run([ps,"-NoLogo","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",script],text=True,capture_output=True,encoding="utf-8",errors="replace",**windows_hidden_kwargs())
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout.strip() or "No se pudo consultar la interfaz VPN.")
    out=cp.stdout.strip()
    return json.loads(out) if out else None

def _vpn_snapshot(
    adaptive_cfg: dict[str, Any],
    target_ips: Optional[list[str]] = None,
) -> dict[str, Any]:
    "Detecta la interfaz que Windows usa realmente para llegar a las tiendas."
    targets = []
    for value in target_ips or []:
        value = str(value).strip()
        if value and value not in targets:
            targets.append(value)

    hints = adaptive_cfg.get("adapter_description_hints")
    if not isinstance(hints, list):
        hints = [
            "VPN", "Fortinet", "FortiClient", "Cisco", "AnyConnect",
            "Secure Client", "GlobalProtect", "Palo Alto", "WireGuard",
            "OpenVPN", "TAP", "TUN", "Pulse", "Juniper", "Check Point",
            "SonicWall", "Zscaler",
        ]

    exclude_hints = adaptive_cfg.get("adapter_exclude_hints")
    if not isinstance(exclude_hints, list):
        exclude_hints = ["Bluetooth", "Loopback"]

    ps_targets = ",".join("'" + ps_single_quote(str(x)) + "'" for x in targets[:12])
    ps_hints = ",".join("'" + ps_single_quote(str(x)) + "'" for x in hints)
    ps_excludes = ",".join("'" + ps_single_quote(str(x)) + "'" for x in exclude_hints)

    script = rf'''
$ErrorActionPreference = 'Stop'
$targets = @({ps_targets})
$hints = @({ps_hints})
$excludeHints = @({ps_excludes})

$adapter = $null
$ip = $null
$detectionMethod = $null
$routeTarget = $null
$routePrefix = $null
$selectedSource = $null

function Test-ExcludedAdapter {{
    param([object]$Adapter)
    if ($null -eq $Adapter) {{ return $true }}
    $text = (($Adapter.Name + ' ' + $Adapter.InterfaceDescription) + '').ToLowerInvariant()
    foreach ($hint in $excludeHints) {{
        if (-not [string]::IsNullOrWhiteSpace($hint)) {{
            if ($text.Contains($hint.ToLowerInvariant())) {{ return $true }}
        }}
    }}
    return $false
}}

# 1) Ruta real hacia una tienda.
$findNetRoute = Get-Command Find-NetRoute -ErrorAction SilentlyContinue

foreach ($target in $targets) {{
    if ([string]::IsNullOrWhiteSpace($target)) {{ continue }}

    if ($null -ne $findNetRoute) {{
        try {{
            $routeInfo = Find-NetRoute -RemoteIPAddress $target -ErrorAction Stop | Select-Object -First 1
            if ($null -ne $routeInfo -and $null -ne $routeInfo.InterfaceIndex) {{
                $candidate = Get-NetAdapter -InterfaceIndex $routeInfo.InterfaceIndex -ErrorAction SilentlyContinue
                if ($null -ne $candidate -and $candidate.Status.ToString() -eq 'Up' -and -not (Test-ExcludedAdapter -Adapter $candidate)) {{
                    $adapter = $candidate
                    $routeTarget = $target
                    $detectionMethod = 'Find-NetRoute'
                    if ($routeInfo.PSObject.Properties.Name -contains 'IPAddress') {{
                        $selectedSource = [string]$routeInfo.IPAddress
                    }}
                    if ($routeInfo.PSObject.Properties.Name -contains 'DestinationPrefix') {{
                        $routePrefix = [string]$routeInfo.DestinationPrefix
                    }}
                    break
                }}
            }}
        }}
        catch {{}}
    }}

    if ($null -eq $adapter) {{
        try {{
            $diag = Test-NetConnection -ComputerName $target -DiagnoseRouting -InformationLevel Detailed -WarningAction SilentlyContinue -ErrorAction Stop
            $idx = $null
            if ($diag.PSObject.Properties.Name -contains 'OutgoingInterfaceIndex') {{
                $idx = $diag.OutgoingInterfaceIndex
            }}
            if ($null -ne $idx) {{
                $candidate = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue
                if ($null -ne $candidate -and $candidate.Status.ToString() -eq 'Up' -and -not (Test-ExcludedAdapter -Adapter $candidate)) {{
                    $adapter = $candidate
                    $routeTarget = $target
                    $detectionMethod = 'Test-NetConnection-DiagnoseRouting'
                    if ($diag.PSObject.Properties.Name -contains 'SelectedSourceAddress') {{
                        $selectedSource = [string]$diag.SelectedSourceAddress
                    }}
                    break
                }}
            }}
        }}
        catch {{}}
    }}

    if ($null -ne $adapter) {{ break }}
}}

# 2) Fallback multi-vendor por nombre/descripcion.
if ($null -eq $adapter) {{
    $candidates = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{
        $_.Status.ToString() -eq 'Up' -and -not (Test-ExcludedAdapter -Adapter $_)
    }})
    $scored = @()
    foreach ($candidate in $candidates) {{
        $score = 0
        $text = (($candidate.Name + ' ' + $candidate.InterfaceDescription) + '').ToLowerInvariant()
        foreach ($hint in $hints) {{
            if (-not [string]::IsNullOrWhiteSpace($hint) -and $text.Contains($hint.ToLowerInvariant())) {{
                $score += 25
            }}
        }}
        $ips = @(Get-NetIPAddress -InterfaceIndex $candidate.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{
            $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1'
        }})
        if ($ips.Count -gt 0) {{ $score += 3 }}
        $iface = Get-NetIPInterface -InterfaceIndex $candidate.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $metric = 99999
        if ($null -ne $iface) {{ $metric = [int]$iface.InterfaceMetric }}
        $scored += [pscustomobject]@{{Adapter=$candidate;Score=$score;Metric=$metric}}
    }}
    $winner = $scored | Sort-Object @{{Expression='Score';Descending=$true}},@{{Expression='Metric';Ascending=$true}} | Select-Object -First 1
    if ($null -ne $winner -and $winner.Score -gt 0) {{
        $adapter = $winner.Adapter
        $detectionMethod = 'AdapterHintFallback'
    }}
}}

# 3) Ultimo fallback: ruta por defecto.
if ($null -eq $adapter) {{
    $routeRows = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    $ranked = @()
    foreach ($route in $routeRows) {{
        $iface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $ifMetric = 0
        if ($null -ne $iface) {{ $ifMetric = [int]$iface.InterfaceMetric }}
        $ranked += [pscustomobject]@{{Route=$route;Cost=([int]$route.RouteMetric+$ifMetric)}}
    }}
    $best = $ranked | Sort-Object Cost | Select-Object -First 1
    if ($null -ne $best) {{
        $candidate = Get-NetAdapter -InterfaceIndex $best.Route.InterfaceIndex -ErrorAction SilentlyContinue
        if ($null -ne $candidate -and $candidate.Status.ToString() -eq 'Up') {{
            $adapter = $candidate
            $detectionMethod = 'DefaultRouteFallback'
            $routePrefix = [string]$best.Route.DestinationPrefix
        }}
    }}
}}

if ($null -eq $adapter) {{
    throw 'No active network adapter could be selected for VPN/path measurement.'
}}

if (-not [string]::IsNullOrWhiteSpace($selectedSource)) {{
    $ip = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {{ $_.IPAddress -eq $selectedSource }} | Select-Object -First 1
}}
if ($null -eq $ip) {{
    $ip = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {{ $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' }} |
        Sort-Object PrefixLength -Descending | Select-Object -First 1
}}

$stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue | Select-Object -First 1

if ($null -eq $stats) {{
    # Algunos drivers VPN exponen Get-NetAdapter pero no resuelven
    # Get-NetAdapterStatistics correctamente por Name. Usamos CIM/InterfaceIndex.
    $stats = Get-CimInstance `
        -Namespace 'root/StandardCimv2' `
        -ClassName 'MSFT_NetAdapterStatisticsSettingData' `
        -ErrorAction SilentlyContinue |
        Where-Object {{
            (
                $_.PSObject.Properties.Name -contains 'InterfaceIndex' -and
                $_.InterfaceIndex -eq $adapter.InterfaceIndex
            ) -or (
                $_.PSObject.Properties.Name -contains 'Name' -and
                $_.Name -eq $adapter.Name
            ) -or (
                $_.PSObject.Properties.Name -contains 'InterfaceDescription' -and
                $_.InterfaceDescription -eq $adapter.InterfaceDescription
            )
        }} |
        Select-Object -First 1
}}

if ($null -eq $stats) {{
    try {{
        $ni = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object {{ $_.Name -eq $adapter.Name -or $_.Description -eq $adapter.InterfaceDescription }} |
            Select-Object -First 1
        if ($null -ne $ni) {{
            $ipStats = $ni.GetIPv4Statistics()
            if ($null -ne $ipStats) {{
                $stats = [pscustomobject]@{{
                    ReceivedBytes=[int64]$ipStats.BytesReceived
                    SentBytes=[int64]$ipStats.BytesSent
                    CounterSource='System.Net.NetworkInformation'
                }}
            }}
        }}
    }} catch {{}}
}}
if ($null -eq $stats) {{
    throw "No se pudieron leer contadores RX/TX de la interfaz seleccionada '$($adapter.Name)' (Index=$($adapter.InterfaceIndex))."
}}

$localAddresses = @(Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty IPAddress)
$sshCount = @(Get-NetTCPConnection -RemotePort 22 -State Established -ErrorAction SilentlyContinue |
    Where-Object {{ $localAddresses -contains $_.LocalAddress }}).Count

$ifaceInfo = Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object -First 1
$metric = $null
if ($null -ne $ifaceInfo) {{ $metric = $ifaceInfo.InterfaceMetric }}

$hintMatched = $false
$adapterText = (($adapter.Name + ' ' + $adapter.InterfaceDescription) + '').ToLowerInvariant()
foreach ($hint in $hints) {{
    if (-not [string]::IsNullOrWhiteSpace($hint) -and $adapterText.Contains($hint.ToLowerInvariant())) {{
        $hintMatched = $true
        break
    }}
}}

[pscustomobject]@{{
    InterfaceAlias=$adapter.Name
    InterfaceDescription=$adapter.InterfaceDescription
    InterfaceIndex=$adapter.InterfaceIndex
    IPAddress=$(if($null -ne $ip){{$ip.IPAddress}}else{{$null}})
    Status=$adapter.Status.ToString()
    LinkSpeed=$adapter.LinkSpeed
    ReceivedBytes=[int64]$stats.ReceivedBytes
    SentBytes=[int64]$stats.SentBytes
    ActiveSSH=[int]$sshCount
    DetectionMethod=$detectionMethod
    RouteTarget=$routeTarget
    RoutePrefix=$routePrefix
    InterfaceMetric=$metric
    HintMatched=[bool]$hintMatched
    Timestamp=(Get-Date).ToString('o')
}} | ConvertTo-Json -Compress
'''
    value = _run_local_powershell_json(script)
    if not isinstance(value, dict):
        raise RuntimeError("La detección automática de interfaz no devolvió un objeto válido.")
    return value

def _ping_health(targets:list[str],*,count:int,timeout_ms:int)->list[dict[str,Any]]:
    targets=[str(x) for x in targets if x]
    if not targets:return []
    ps_targets=','.join("'"+ps_single_quote(t)+"'" for t in targets)
    script=rf'''
$ErrorActionPreference='SilentlyContinue'
$targets=@({ps_targets});$count={max(1,int(count))};$timeoutMs={max(100,int(timeout_ms))};$rows=@()
foreach($target in $targets){{
 $success=0;$totalMs=[double]0;$ping=New-Object System.Net.NetworkInformation.Ping
 for($i=0;$i -lt $count;$i++){{try{{$reply=$ping.Send($target,$timeoutMs);if($null -ne $reply -and $reply.Status.ToString() -eq 'Success'){{$success++;$totalMs += [double]$reply.RoundtripTime}}}}catch{{}}}}
 $loss=[math]::Round((($count-$success)/[double]$count)*100,1);$avg=$null;if($success -gt 0){{$avg=[math]::Round($totalMs/$success,1)}}
 $rows += [pscustomobject]@{{Target=$target;Sent=$count;Received=$success;LossPct=$loss;AvgLatencyMs=$avg}}
}}
$rows | ConvertTo-Json -Compress
'''
    value=_run_local_powershell_json(script)
    if value is None:return []
    if isinstance(value,dict):return [value]
    return [x for x in value if isinstance(x,dict)] if isinstance(value,list) else []

async def measure_vpn_health(
    adaptive_cfg: dict[str, Any],
    target_ips: list[str],
    *,
    sample_seconds: Optional[float] = None,
) -> dict[str, Any]:
    seconds = float(
        sample_seconds if sample_seconds is not None
        else adaptive_cfg.get("sample_seconds", 2.0)
    )
    seconds = max(0.5, min(seconds, 15.0))

    unique_targets: list[str] = []
    for ip in target_ips:
        value = str(ip).strip()
        if value and value not in unique_targets:
            unique_targets.append(value)

    first = await asyncio.to_thread(_vpn_snapshot, adaptive_cfg, unique_targets)
    t0 = time.perf_counter()
    await asyncio.sleep(seconds)
    second = await asyncio.to_thread(_vpn_snapshot, adaptive_cfg, unique_targets)
    elapsed = max(0.001, time.perf_counter() - t0)

    same_interface = first.get("InterfaceIndex") == second.get("InterfaceIndex")
    if same_interface:
        rx = max(0, int(second.get("ReceivedBytes", 0)) - int(first.get("ReceivedBytes", 0)))
        tx = max(0, int(second.get("SentBytes", 0)) - int(first.get("SentBytes", 0)))
    else:
        rx = 0
        tx = 0

    rx_mbps = (rx * 8.0 / elapsed) / 1_000_000.0
    tx_mbps = (tx * 8.0 / elapsed) / 1_000_000.0
    total = rx_mbps + tx_mbps

    ping_targets = unique_targets[:max(1, int(adaptive_cfg.get("ping_targets", 3)))]
    pings = await asyncio.to_thread(
        _ping_health,
        ping_targets,
        count=max(1, int(adaptive_cfg.get("ping_count", 2))),
        timeout_ms=max(100, int(adaptive_cfg.get("ping_timeout_ms", 800))),
    )

    lats = [float(x["AvgLatencyMs"]) for x in pings if x.get("AvgLatencyMs") is not None]
    losses = [float(x.get("LossPct", 100.0)) for x in pings]
    avg = round(sum(lats) / len(lats), 1) if lats else None
    maxloss = round(max(losses), 1) if losses else None

    capacity = adaptive_cfg.get("vpn_capacity_mbps")
    util = None
    try:
        if capacity is not None and float(capacity) > 0:
            util = round((total / float(capacity)) * 100.0, 1)
    except Exception as exc:
        best_effort_warning("No se pudo calcular utilización de capacidad de red", exc)

    return {
        "MeasuredAt": now_iso(),
        "InterfaceAlias": second.get("InterfaceAlias"),
        "InterfaceDescription": second.get("InterfaceDescription"),
        "InterfaceIndex": second.get("InterfaceIndex"),
        "IPAddress": second.get("IPAddress"),
        "Status": second.get("Status"),
        "LinkSpeed": second.get("LinkSpeed"),
        "DetectionMethod": second.get("DetectionMethod"),
        "RouteTarget": second.get("RouteTarget"),
        "RoutePrefix": second.get("RoutePrefix"),
        "InterfaceMetric": second.get("InterfaceMetric"),
        "HintMatched": second.get("HintMatched"),
        "InterfaceChangedDuringSample": not same_interface,
        "RxMbps": round(rx_mbps, 3),
        "TxMbps": round(tx_mbps, 3),
        "TotalMbps": round(total, 3),
        "CapacityMbps": capacity,
        "UtilizationPct": util,
        "ActiveSSH": int(second.get("ActiveSSH", 0) or 0),
        "AvgLatencyMs": avg,
        "MaxLossPct": maxloss,
        "Ping": pings,
        "SampleSeconds": round(elapsed, 2),
    }

def recommend_vpn_concurrency(health:dict[str,Any],adaptive_cfg:dict[str,Any],*,max_workers:int,recent_timeouts:int=0)->tuple[int,str]:
    minimum=max(1,int(adaptive_cfg.get("min_workers",2)));maximum=max(minimum,min(int(adaptive_cfg.get("max_workers",6)),max(1,int(max_workers))));normal=max(minimum,min(int(adaptive_cfg.get("normal_workers",4)),maximum))
    total=float(health.get("TotalMbps",0) or 0);lat=health.get("AvgLatencyMs");lat=float(lat) if lat is not None else None;loss=health.get("MaxLossPct");loss=float(loss) if loss is not None else None;ssh=int(health.get("ActiveSSH",0) or 0);util=health.get("UtilizationPct");util=float(util) if util is not None else None
    low=float(adaptive_cfg.get("low_traffic_mbps",1));soft=float(adaptive_cfg.get("soft_traffic_mbps",3));crit=float(adaptive_cfg.get("critical_traffic_mbps",6));lw=float(adaptive_cfg.get("latency_warn_ms",120));lc=float(adaptive_cfg.get("latency_critical_ms",250));pw=float(adaptive_cfg.get("loss_warn_pct",2));pc=float(adaptive_cfg.get("loss_critical_pct",5));sw=int(adaptive_cfg.get("active_ssh_warn",4));sc=int(adaptive_cfg.get("active_ssh_critical",7));uw=float(adaptive_cfg.get("utilization_warn_pct",55));uc=float(adaptive_cfg.get("utilization_critical_pct",75))
    critical=[];warning=[]
    if total>=crit:critical.append(f"tráfico={total:.2f}Mbps")
    elif total>=soft:warning.append(f"tráfico={total:.2f}Mbps")
    if lat is not None:
        if lat>=lc:critical.append(f"latencia={lat:.0f}ms")
        elif lat>=lw:warning.append(f"latencia={lat:.0f}ms")
    if loss is not None:
        if loss>=pc:critical.append(f"pérdida={loss:.1f}%")
        elif loss>=pw:warning.append(f"pérdida={loss:.1f}%")
    if ssh>=sc:critical.append(f"SSH activos={ssh}")
    elif ssh>=sw:warning.append(f"SSH activos={ssh}")
    if util is not None:
        if util>=uc:critical.append(f"uso estimado={util:.0f}%")
        elif util>=uw:warning.append(f"uso estimado={util:.0f}%")
    if recent_timeouts>=2:critical.append(f"timeouts ola anterior={recent_timeouts}")
    elif recent_timeouts==1:warning.append("1 timeout ola anterior")
    if critical:return minimum,"CRITICO: "+', '.join(critical)
    if warning:return max(minimum,min(normal-1,maximum)),"PRECAUCION: "+', '.join(warning)
    healthy=total<=low and (lat is None or lat<min(lw,80)) and (loss is None or loss<=.1) and ssh<=1
    if healthy:return maximum,"SALUDABLE: tráfico/latencia/pérdida bajos"
    return normal,"NORMAL: sin señales de congestión"

def print_vpn_health(health:dict[str,Any],workers:int,reason:str,*,phase:str)->None:
    print();print('-'*78);print(f"VPN/PATH HEALTH - {phase}");print('-'*78);print(f"Adaptador seleccionado : {health.get('InterfaceAlias')}");print(f"Descripción            : {health.get('InterfaceDescription')}");print(f"IP local               : {health.get('IPAddress')}");print(f"Detección              : {health.get('DetectionMethod')}");print(f"Ruta objetivo          : {health.get('RouteTarget')}");print(f"LinkSpeed informativo  : {health.get('LinkSpeed')}");print(f"RX                     : {float(health.get('RxMbps',0)):.2f} Mbps");print(f"TX                     : {float(health.get('TxMbps',0)):.2f} Mbps");print(f"Tráfico total observado: {float(health.get('TotalMbps',0)):.2f} Mbps")
    if health.get("UtilizationPct") is not None:print(f"Uso capacidad config.  : {float(health['UtilizationPct']):.1f} %")
    else:print("Uso capacidad config.  : N/D (vpn_capacity_mbps no configurado)")
    print(f"Sesiones TCP/22        : {health.get('ActiveSSH')}");print(f"Latencia promedio      : {health.get('AvgLatencyMs')} ms");print(f"Pérdida máxima         : {health.get('MaxLossPct')} %");print(f"Concurrencia elegida   : {workers}");print(f"Motivo                 : {reason}");print('-'*78)
