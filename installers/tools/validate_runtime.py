from __future__ import annotations
import argparse, importlib, json, os, sys
from pathlib import Path

MODULES=['fastapi','uvicorn','cryptography','jinja2']

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--app-root',required=True); ap.add_argument('--config',required=False)
    a=ap.parse_args(); root=Path(a.app_root).resolve(); sys.path.insert(0,str(root))
    out={'python':sys.version,'executable':sys.executable,'imports':{},'app_root':str(root)}
    failed=0
    for m in MODULES:
        try: importlib.import_module(m); out['imports'][m]='PASS'
        except Exception as exc: out['imports'][m]=f'FAIL:{type(exc).__name__}:{exc}'; failed+=1
    try:
        import gideon_web_admin.auth; out['imports']['gideon_web_admin.auth']='PASS'
    except Exception as exc:
        out['imports']['gideon_web_admin.auth']=f'FAIL:{type(exc).__name__}:{exc}'; failed+=1
    print(json.dumps(out,ensure_ascii=False))
    return 0 if failed==0 else 2
if __name__=='__main__': raise SystemExit(main())
