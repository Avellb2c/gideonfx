from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path


def load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--app-root', required=True)
    ap.add_argument('--config', required=True)
    ap.add_argument('--users-json', required=True)
    ap.add_argument('--rotate-existing', action='store_true')
    args=ap.parse_args()

    app_root=Path(args.app_root).resolve()
    sys.path.insert(0, str(app_root))
    # A portable Windows bundle can invoke this helper with a host Python
    # during preflight. Make the bundle's pinned dependencies visible without
    # importing or modifying that host interpreter.
    dependency_roots = [app_root.parent / 'venv' / 'Lib' / 'site-packages']
    dependency_roots.extend((app_root.parent / 'venv' / 'lib').glob('python*/site-packages'))
    for dependency_root in dependency_roots:
        if dependency_root.is_dir():
            sys.path.insert(0, str(dependency_root))
    cfg=load_config(Path(args.config))
    data_dir=Path(os.path.expandvars(str(cfg.get('data_dir') or ''))).expanduser().resolve()
    if not str(data_dir):
        raise SystemExit('data_dir missing')

    from gideon_web_admin.auth import SecurityStore
    store=SecurityStore(data_dir/'security.sqlite3')
    users=json.loads(Path(args.users_json).read_text(encoding='utf-8-sig'))

    existing={str(x.get('username') or '').casefold(): x for x in store.list_users()}
    created=[]
    try:
        for idx,item in enumerate(users):
            username=str(item['username']).strip()
            display=str(item.get('display_name') or username).strip()
            role=str(item.get('role') or 'ADMIN').strip().upper()
            env_name=str(item['password_env'])
            password=os.environ.get(env_name,'')
            if not password:
                raise RuntimeError(f'Missing password env: {env_name}')
            if username.casefold() in existing:
                row = existing[username.casefold()]
                if args.rotate_existing:
                    user_id = int(row.get("id") or 0)
                    if user_id <= 0:
                        raise RuntimeError(f"Existing WebAdmin user has no valid id: {username}")
                    store.reset_password(
                        user_id,
                        password,
                        actor="installer",
                        remote_ip="local",
                    )
                    # A bundle cloned onto a new server must not retain the
                    # previous machine's TOTP secret or recovery codes.  The
                    # temporary password therefore starts a new, mandatory MFA
                    # enrollment instead of asking for an unknown old token.
                    store.disable_mfa(
                        user_id,
                        actor="installer",
                        remote_ip="local",
                    )
                    with store.connect() as con:
                        con.execute(
                            "DELETE FROM recovery_codes WHERE user_id=?",
                            (user_id,),
                        )
                    created.append(
                        {
                            "username": username,
                            "status": "ROTATED",
                            "role": str(row.get("role") or role).upper(),
                        }
                    )
                else:
                    created.append(
                        {
                            "username": username,
                            "status": "EXISTS",
                            "role": str(row.get("role") or ""),
                        }
                    )
                continue
            if store.user_count()==0:
                if role!='SUPERADMIN':
                    raise RuntimeError('First WebAdmin account must be SUPERADMIN')
                store.bootstrap_admin(
                    username,
                    password,
                    display,
                    must_change_password=True,
                    allow_temporary_password=True,
                )
            else:
                store.create_user(username,display,password,role,actor='installer',remote_ip='local')
            created.append({'username':username,'status':'CREATED','role':role})
    finally:
        # SecurityStore uses short-lived SQLite connections; no persistent connection is kept here.
        # Explicitly release our references before Windows backup/cleanup stages.
        store=None

    print(json.dumps({'ok':True,'users':created}, ensure_ascii=False))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
