from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


LOOPBACKS = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::", ""}


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return default


def env_map(container: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in container.get("environment") or []:
        name = str(item.get("name") or "")
        value = str(item.get("value") or "")
        if name:
            out[name] = value
    return out


def published_port(container: dict, container_port: str) -> list[dict]:
    return [
        p for p in (container.get("ports") or [])
        if str(p.get("container_port") or "") == container_port
    ]


def common_networks(a: dict, b: dict) -> set[str]:
    an = {str(x.get("name") or "") for x in (a.get("networks") or [])}
    bn = {str(x.get("name") or "") for x in (b.get("networks") or [])}
    return {x for x in an & bn if x}


def bridge_guacd_evidence(bridge: dict, guacd: dict) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    env = env_map(bridge)

    host_hits: list[tuple[str, str]] = []
    port_hits: list[tuple[str, str]] = []

    for name, value in env.items():
        upper = name.upper()

        if "GUACD" in upper and "HOST" in upper:
            host_hits.append((name, value))
        elif "GUACD" in upper and "PORT" in upper:
            port_hits.append((name, value))
        elif value in {str(guacd.get("name") or ""), "gideon-guacd"}:
            host_hits.append((name, value))
        elif value == "4822":
            port_hits.append((name, value))

    networks = common_networks(bridge, guacd)
    guacd_name = str(guacd.get("name") or "")

    host_ok = any(
        value in {guacd_name, "gideon-guacd", "127.0.0.1", "localhost"}
        for _, value in host_hits
    )
    port_ok = any(value == "4822" for _, value in port_hits)

    if host_hits:
        evidence.append(
            "bridge_env_host="
            + ",".join(f"{k}={v}" for k, v in host_hits)
        )
    if port_hits:
        evidence.append(
            "bridge_env_port="
            + ",".join(f"{k}={v}" for k, v in port_hits)
        )
    if networks:
        evidence.append("common_networks=" + ",".join(sorted(networks)))

    # Strong proof if bridge declares both guacd host/port and shares Docker
    # network with guacd. Also accept explicit loopback host/4822.
    strong = port_ok and host_ok and (
        bool(networks)
        or any(v in {"127.0.0.1", "localhost"} for _, v in host_hits)
    )
    return strong, evidence


def text_files(root: Path) -> list[Path]:
    exts = {
        ".py", ".json", ".toml", ".yaml", ".yml", ".ini",
        ".conf", ".cfg", ".txt", ".ps1", ".psm1",
    }
    rows: list[Path] = []
    if not root.exists():
        return rows

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in exts:
            continue
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                continue
        except OSError:
            continue
        rows.append(path)
    return rows


def scan_webadmin_endpoint(
    app_root: Path,
    config_root: Path,
    port: int,
    kind: str,
) -> tuple[bool, list[dict]]:
    evidence: list[dict] = []
    token = str(port)

    # Strong textual forms. We avoid treating a bare port occurrence as proof.
    patterns = [
        re.compile(
            rf"(?i)(127\.0\.0\.1|localhost|\[::1\])\s*[:/]\s*{port}\b"
        ),
        re.compile(
            rf"(?i)(bridge|guacamole|guacd).{{0,120}}\b{port}\b"
        ),
        re.compile(
            rf"(?i)\b{port}\b.{{0,120}}(bridge|guacamole|guacd)"
        ),
    ]

    roots = [
        ("app", app_root),
        ("config", config_root),
    ]

    for source_kind, root in roots:
        for path in text_files(root):
            try:
                text = path.read_text(encoding="utf-8-sig", errors="ignore")
            except Exception:
                continue

            if token not in text:
                continue

            lines = text.splitlines()
            for line_no, line in enumerate(lines, 1):
                if not any(p.search(line) for p in patterns):
                    continue

                snippet = line.strip()
                if len(snippet) > 400:
                    snippet = snippet[:400] + "…"

                evidence.append(
                    {
                        "source": source_kind,
                        "file": str(path),
                        "line": line_no,
                        "snippet": snippet,
                        "endpoint_kind": kind,
                        "port": port,
                    }
                )
                if len(evidence) >= 20:
                    return True, evidence

    return bool(evidence), evidence


def runtime_connection_evidence(
    connections: list[dict],
    port: int,
) -> list[dict]:
    rows: list[dict] = []
    for item in connections:
        try:
            remote_port = int(item.get("remote_port") or 0)
        except Exception:
            remote_port = 0

        if remote_port != port:
            continue

        path = str(item.get("process_path") or "")
        cmd = str(item.get("command_line") or "")
        name = str(item.get("process_name") or "")
        haystack = " ".join([path, cmd, name]).lower()

        if "gideon remote control" not in haystack and "gideon_web_admin" not in haystack:
            continue

        rows.append(item)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-root", required=True)
    ap.add_argument("--config-root", required=True)
    ap.add_argument("--docker-json", required=True)
    ap.add_argument("--connections-json", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    app_root = Path(args.app_root).resolve()
    config_root = Path(args.config_root).resolve()
    docker_json = Path(args.docker_json).resolve()
    connections_json = Path(args.connections_json).resolve()
    output = Path(args.output).resolve()

    docker = read_json(docker_json, {})
    connections = read_json(connections_json, [])

    containers = list(docker.get("guacamole") or [])
    guacd = next(
        (c for c in containers if bool(c.get("is_guacd"))),
        None,
    )
    bridge = next(
        (c for c in containers if not bool(c.get("is_guacd"))),
        None,
    )

    report: dict[str, Any] = {
        "status": "UNRESOLVED",
        "topology_mode": "UNKNOWN",
        "webadmin_endpoint": {},
        "bridge_to_guacd": {},
        "runtime_connections": {},
        "evidence": [],
        "notes": [],
    }

    if not guacd:
        report["notes"].append("guacd container not found")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(json.dumps(report, ensure_ascii=False))
        return 2

    guacd_bindings = published_port(guacd, "4822/tcp")
    guacd_host_port = None
    for item in guacd_bindings:
        try:
            hp = int(item.get("host_port") or 0)
        except Exception:
            hp = 0
        if hp:
            guacd_host_port = hp
            break

    # Direct WebAdmin -> guacd proof.
    direct_runtime = (
        runtime_connection_evidence(connections, guacd_host_port)
        if guacd_host_port
        else []
    )
    direct_static, direct_static_rows = (
        scan_webadmin_endpoint(
            app_root,
            config_root,
            guacd_host_port,
            "GUACD",
        )
        if guacd_host_port
        else (False, [])
    )

    if direct_runtime or direct_static:
        report["status"] = "PASS"
        report["topology_mode"] = "WEBADMIN_DIRECT_GUACD"
        report["webadmin_endpoint"] = {
            "host": "127.0.0.1",
            "port": guacd_host_port,
            "type": "GUACD",
            "proof": (
                "RUNTIME_TCP"
                if direct_runtime
                else "CODE_OR_CONFIG"
            ),
        }
        report["runtime_connections"]["webadmin_to_guacd"] = direct_runtime
        report["evidence"].extend(direct_static_rows)

    # WebAdmin -> bridge -> guacd proof.
    if report["status"] != "PASS" and bridge:
        bridge_bindings = published_port(bridge, "8090/tcp")
        bridge_host_port = None
        for item in bridge_bindings:
            try:
                hp = int(item.get("host_port") or 0)
            except Exception:
                hp = 0
            if hp:
                bridge_host_port = hp
                break

        bridge_runtime = (
            runtime_connection_evidence(connections, bridge_host_port)
            if bridge_host_port
            else []
        )
        bridge_static, bridge_static_rows = (
            scan_webadmin_endpoint(
                app_root,
                config_root,
                bridge_host_port,
                "BRIDGE",
            )
            if bridge_host_port
            else (False, [])
        )
        bridge_guacd_ok, bridge_guacd_rows = bridge_guacd_evidence(
            bridge,
            guacd,
        )

        report["bridge_to_guacd"] = {
            "status": "PASS" if bridge_guacd_ok else "REVIEW",
            "evidence": bridge_guacd_rows,
            "common_networks": sorted(common_networks(bridge, guacd)),
        }
        report["runtime_connections"]["webadmin_to_bridge"] = bridge_runtime
        report["evidence"].extend(bridge_static_rows)

        webadmin_bridge_ok = bool(bridge_runtime) or bridge_static

        if webadmin_bridge_ok and bridge_guacd_ok:
            report["status"] = "PASS"
            report["topology_mode"] = "WEBADMIN_BRIDGE_GUACD"
            report["webadmin_endpoint"] = {
                "host": "127.0.0.1",
                "port": bridge_host_port,
                "type": "BRIDGE",
                "proof": (
                    "RUNTIME_TCP"
                    if bridge_runtime
                    else "CODE_OR_CONFIG"
                ),
            }
        else:
            report["status"] = "REVIEW"
            report["topology_mode"] = "WEBADMIN_BRIDGE_GUACD_CANDIDATE"
            report["webadmin_endpoint"] = {
                "host": "127.0.0.1",
                "port": bridge_host_port,
                "type": "BRIDGE",
                "proof": (
                    "RUNTIME_TCP"
                    if bridge_runtime
                    else (
                        "CODE_OR_CONFIG"
                        if bridge_static
                        else "UNPROVEN"
                    )
                ),
            }
            if not webadmin_bridge_ok:
                report["notes"].append(
                    "WebAdmin->bridge endpoint not proven"
                )
            if not bridge_guacd_ok:
                report["notes"].append(
                    "bridge->guacd relationship not proven"
                )

    # If still unresolved, expose what is definitely true from Docker only.
    if report["status"] == "UNRESOLVED":
        report["status"] = "REVIEW"
        report["topology_mode"] = "DOCKER_ONLY"
        report["notes"].append(
            "Docker guacd runtime is visible, but WebAdmin path is unproven"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
