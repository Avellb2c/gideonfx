#!/usr/bin/env python3
"""Configura el Gateway central y genera automáticamente su URL HTTPS.

Uso:
  python configure_gateway.py
  python configure_gateway.py --host gateway.midominio.com
  python configure_gateway.py --force-tls
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from gideon_gateway_bootstrap import GATEWAY_CONFIG_PATH, ensure_gateway_configuration

p=argparse.ArgumentParser()
p.add_argument('--host', help='DNS/IP que usarán los agentes. También puede definirse con GIDEON_GATEWAY_PUBLIC_HOST.')
p.add_argument('--force-tls', action='store_true', help='Regenera CA y certificado del Gateway.')
a=p.parse_args()
if a.host:
    cfg=json.loads(GATEWAY_CONFIG_PATH.read_text(encoding='utf-8-sig')) if GATEWAY_CONFIG_PATH.exists() else {}
    cfg['public_host']=a.host.strip()
    GATEWAY_CONFIG_PATH.write_text(json.dumps(cfg,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
info=ensure_gateway_configuration(force_tls=a.force_tls)
print(json.dumps(info,ensure_ascii=False,indent=2))
