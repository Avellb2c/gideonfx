from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def resolve_data_dir(config_path: Path) -> Path:
    cfg = load_json(config_path)
    raw = str(cfg.get("data_dir") or "").strip()
    if not raw:
        # GIDEON standard layout: ...\ProgramData\GIDEON Remote Control\config\web_admin.json
        return config_path.parent.parent.resolve()
    return Path(os.path.expandvars(raw)).expanduser().resolve()


def export_via_security_store(app_root: Path, db_path: Path) -> list[dict]:
    sys.path.insert(0, str(app_root))
    from gideon_web_admin.auth import SecurityStore

    store = SecurityStore(db_path)
    rows: list[dict] = []
    try:
        for item in store.list_users():
            rows.append(
                {
                    "username": str(item.get("username") or ""),
                    "display_name": str(
                        item.get("display_name")
                        or item.get("name")
                        or item.get("username")
                        or ""
                    ),
                    "role": str(item.get("role") or "").upper(),
                    "active": bool(item.get("active", True)),
                }
            )
    finally:
        store = None
    return rows


def find_column(columns: set[str], *candidates: str) -> str | None:
    lookup = {name.casefold(): name for name in columns}
    for candidate in candidates:
        value = lookup.get(candidate.casefold())
        if value:
            return value
    return None


def export_via_sqlite(db_path: Path) -> list[dict]:
    uri = f"file:{db_path.as_posix()}?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=5.0)
    con.row_factory = sqlite3.Row

    try:
        tables = {
            str(row[0])
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        user_table = None
        for candidate in ("users", "web_users", "security_users"):
            if candidate in tables:
                user_table = candidate
                break
        if not user_table:
            raise RuntimeError("No compatible users table found")

        info = con.execute(f'PRAGMA table_info("{user_table}")').fetchall()
        columns = {str(row[1]) for row in info}

        username_col = find_column(columns, "username", "user_name", "login")
        display_col = find_column(
            columns, "display_name", "name", "full_name", "username"
        )
        role_col = find_column(columns, "role", "role_name")
        active_col = find_column(columns, "active", "is_active", "enabled")

        if not username_col:
            raise RuntimeError("users table has no username-compatible column")

        quoted = lambda value: f'"{value}"'
        select_cols = [quoted(username_col)]
        if display_col:
            select_cols.append(quoted(display_col))
        if role_col:
            select_cols.append(quoted(role_col))
        if active_col:
            select_cols.append(quoted(active_col))

        result: list[dict] = []
        query = f'SELECT {", ".join(select_cols)} FROM "{user_table}"'
        for row in con.execute(query):
            username = str(row[username_col] or "")
            display_name = (
                str(row[display_col] or username)
                if display_col
                else username
            )
            role = str(row[role_col] or "").upper() if role_col else ""
            active = bool(row[active_col]) if active_col else True
            result.append(
                {
                    "username": username,
                    "display_name": display_name,
                    "role": role,
                    "active": active,
                }
            )
        return result
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-root", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    app_root = Path(args.app_root).resolve()
    config_path = Path(args.config).resolve()
    output_path = Path(args.output).resolve()
    data_dir = resolve_data_dir(config_path)
    db_path = data_dir / "security.sqlite3"

    if not db_path.exists():
        raise SystemExit(f"security.sqlite3 not found: {db_path}")

    method = ""
    warnings: list[str] = []

    try:
        rows = export_via_security_store(app_root, db_path)
        method = "SecurityStore"
    except Exception as exc:
        warnings.append(
            f"SecurityStore unavailable: {type(exc).__name__}: {exc}"
        )
        rows = export_via_sqlite(db_path)
        method = "SQLiteReadOnlyFallback"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(rows, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "ok": True,
                "count": len(rows),
                "method": method,
                "warnings": warnings,
                "output": str(output_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
