from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


def columns(con: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {
            str(row[1])
            for row in con.execute(f'PRAGMA table_info("{table}")').fetchall()
        }
    except sqlite3.DatabaseError:
        return set()


def tables(con: sqlite3.Connection) -> set[str]:
    try:
        return {
            str(row[0])
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    except sqlite3.DatabaseError:
        return set()


def sanitize_database(path: Path, *, reset_agent_state: bool = False) -> dict:
    result = {
        "path": str(path),
        "sessions_deleted": 0,
        "remote_sessions_closed": 0,
        "agent_rows_deleted": 0,
        "web_groups_cleared": 0,
        "tables_seen": [],
    }

    con = sqlite3.connect(str(path), timeout=10.0)
    try:
        names = tables(con)
        result["tables_seen"] = sorted(names)

        # Authenticated browser sessions never migrate to another installation.
        for table in ("sessions", "step_up_sessions", "mfa_step_up", "step_up_cache"):
            if table in names:
                before = con.total_changes
                con.execute(f'DELETE FROM "{table}"')
                result["sessions_deleted"] += con.total_changes - before

        # A cloned server must not inherit ACTIVE/PENDING RDP/VNC tickets.
        if "remote_sessions" in names:
            cols = columns(con, "remote_sessions")
            if "status" in cols:
                assignments = ["status='CLOSED'"]
                if "end_reason" in cols:
                    assignments.append("end_reason='CLONE_SANITIZED'")
                if "closed_reason" in cols:
                    assignments.append("closed_reason='CLONE_SANITIZED'")
                sql = (
                    "UPDATE remote_sessions SET "
                    + ", ".join(assignments)
                    + " WHERE UPPER(COALESCE(status,'')) IN "
                      "('ACTIVE','PENDING','CONNECTING','OPEN')"
                )
                before = con.total_changes
                con.execute(sql)
                result["remote_sessions_closed"] += con.total_changes - before

        if reset_agent_state:
            # A new Master must never accept cloned agent bearer tokens,
            # enrollment grants, jobs or per-agent configuration.  Release
            # catalogs are intentionally retained so new installers can still
            # be generated immediately after first login.
            for table in (
                "agent_config_status",
                "agent_configurations",
                "jobs",
                "enrollment_grants",
                "agents",
            ):
                if table in names:
                    before = con.total_changes
                    con.execute(f'DELETE FROM "{table}"')
                    result["agent_rows_deleted"] += con.total_changes - before

            if "web_groups" in names and "agent_ids_json" in columns(con, "web_groups"):
                before = con.total_changes
                con.execute(
                    "UPDATE web_groups SET agent_ids_json='[]' "
                    "WHERE COALESCE(agent_ids_json,'[]')<>'[]'"
                )
                result["web_groups_cleared"] += con.total_changes - before

        con.commit()
    finally:
        con.close()

    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument(
        "--reset-agent-state",
        action="store_true",
        help="Remove cloned agent identities/grants/jobs on a new Master",
    )
    args = parser.parse_args()

    root = Path(args.data_root)
    report = {
        "data_root": str(root),
        "reset_agent_state": bool(args.reset_agent_state),
        "databases": [],
    }

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
            continue

        # Never create a persistent replacement for the intentionally excluded
        # 15-minute MFA step-up cache.
        if path.name.lower() == "security-step-up.sqlite3":
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            continue

        try:
            report["databases"].append(
                sanitize_database(path, reset_agent_state=args.reset_agent_state)
            )
        except sqlite3.DatabaseError as exc:
            report["databases"].append(
                {
                    "path": str(path),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    Path(args.report).write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
