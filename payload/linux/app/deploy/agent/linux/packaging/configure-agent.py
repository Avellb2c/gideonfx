#!/usr/bin/env python3
"""Configura la identidad (site_code, gateway, secreto) de un GIDEON Agent
ya instalado por el paquete .deb/.rpm. No descarga nada: solo escribe
/etc/gideon-agent/agent.json a partir de la plantilla incluida en el paquete."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--template", type=Path, default=Path("/usr/lib/gideon-agent/agent.template.json"))
p.add_argument("--out", type=Path, default=Path("/etc/gideon-agent/agent.json"))
p.add_argument("--site-code", required=True)
p.add_argument("--site-name", required=True)
p.add_argument("--gateway", help="URL HTTPS del gateway, ej: https://agent.midominio.com")
p.add_argument("--enrollment-secret")
a = p.parse_args()

cfg = json.loads(a.template.read_text(encoding="utf-8-sig"))
cfg["site_code"] = a.site_code.strip()
cfg["site_name"] = a.site_name.strip()
if a.gateway:
    cp = cfg["control_plane"]
    old = str(cp.get("base_url") or "").rstrip("/")
    new = a.gateway.rstrip("/")
    cp["base_url"] = new
    rows = cp.get("endpoints") if isinstance(cp.get("endpoints"), list) else []
    replaced = False
    for row in rows:
        if isinstance(row, dict) and not replaced and (str(row.get("role") or "").lower() == "primary" or str(row.get("url") or "").rstrip("/") == old):
            row.update({"url": new, "role": "primary", "priority": 10})
            replaced = True
    if not replaced:
        rows.insert(0, {"url": new, "role": "primary", "priority": 10, "label": "Configurado en instalación"})
    cp["endpoints"] = rows
if a.enrollment_secret:
    cfg["enrollment_secret"] = a.enrollment_secret

a.out.parent.mkdir(parents=True, exist_ok=True)
a.out.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
a.out.chmod(0o600)
print(f"Identidad escrita en {a.out}. Ahora ejecute: sudo systemctl enable --now gideon-agent")
