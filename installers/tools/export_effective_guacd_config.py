from __future__ import annotations

import argparse
import ast
import importlib
import json
import sys
import traceback
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict:
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    return raw if isinstance(raw, dict) else {}


def literal_value(node: ast.AST | None) -> Any:
    if node is None:
        return None

    try:
        return ast.literal_eval(node)
    except Exception:
        pass

    # dataclasses.field(default=...)
    if isinstance(node, ast.Call):
        for keyword in node.keywords:
            if keyword.arg == "default":
                try:
                    return ast.literal_eval(keyword.value)
                except Exception:
                    return None

    return None


def ast_guacd_defaults(module_path: Path) -> tuple[dict, list[str]]:
    errors: list[str] = []
    defaults: dict[str, Any] = {}

    try:
        source = module_path.read_text(encoding="utf-8-sig")
        tree = ast.parse(source, filename=str(module_path))
    except Exception as exc:
        return {}, [f"AST_PARSE:{type(exc).__name__}:{exc}"]

    target: ast.ClassDef | None = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "GuacdConfig":
            target = node
            break

    if target is None:
        return {}, ["AST_GUACDCONFIG_NOT_FOUND"]

    for node in target.body:
        name = None
        value_node = None

        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            value_node = node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target_node = node.targets[0]
            if isinstance(target_node, ast.Name):
                name = target_node.id
                value_node = node.value

        if name in {"host", "port", "rdp_security", "rdp_ignore_cert"}:
            value = literal_value(value_node)
            if value is not None:
                defaults[name] = value

    required = {"host", "port"}
    missing = sorted(required - set(defaults))
    if missing:
        errors.append("AST_DEFAULTS_MISSING:" + ",".join(missing))

    return defaults, errors


def import_effective(app_root: Path, config: dict) -> tuple[dict | None, str | None]:
    # Use the installed package normally so relative imports work.
    # This runs in the GIDEON venv selected by the builder.
    sys.path.insert(0, str(app_root))

    try:
        module = importlib.import_module("gideon_web_admin.guacamole")
        cfg_type = getattr(module, "GuacdConfig", None)
        if cfg_type is None:
            return None, "IMPORT_GUACDCONFIG_NOT_FOUND"

        effective = cfg_type.from_config(config)
        return {
            "host": str(effective.host),
            "port": int(effective.port),
            "rdp_security": str(getattr(effective, "rdp_security", "nla")),
            "rdp_ignore_cert": bool(
                getattr(effective, "rdp_ignore_cert", False)
            ),
        }, None
    except Exception as exc:
        summary = (
            f"IMPORT:{type(exc).__name__}:{exc}"
        )
        return None, summary


def merge_explicit_with_defaults(
    explicit_raw: dict,
    defaults: dict,
) -> dict:
    host = explicit_raw.get("host")
    if host in (None, ""):
        host = defaults.get("host")

    port = explicit_raw.get("port")
    if port in (None, ""):
        port = defaults.get("port")

    rdp_security = explicit_raw.get("rdp_security")
    if rdp_security in (None, ""):
        rdp_security = defaults.get("rdp_security", "nla")

    rdp_ignore_cert = explicit_raw.get("rdp_ignore_cert")
    if rdp_ignore_cert is None:
        rdp_ignore_cert = defaults.get("rdp_ignore_cert", False)

    if not host or port in (None, ""):
        raise RuntimeError("EFFECTIVE_HOST_PORT_UNRESOLVED")

    return {
        "host": str(host),
        "port": int(port),
        "rdp_security": str(rdp_security or "nla"),
        "rdp_ignore_cert": bool(rdp_ignore_cert),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-root", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--diagnostics", required=False)
    args = ap.parse_args()

    app_root = Path(args.app_root).resolve()
    config_path = Path(args.config).resolve()
    output = Path(args.output).resolve()
    diagnostics_path = (
        Path(args.diagnostics).resolve()
        if args.diagnostics
        else output.with_name("webadmin-effective-guacd-diagnostics.json")
    )

    module_path = app_root / "gideon_web_admin" / "guacamole.py"
    config = load_json(config_path)

    raw_remote = config.get("remote_sessions") or {}
    raw_guacd = (
        raw_remote.get("guacd")
        if isinstance(raw_remote, dict)
        else None
    )
    explicit_raw = raw_guacd if isinstance(raw_guacd, dict) else {}
    explicit = bool(explicit_raw)

    diagnostics: dict[str, Any] = {
        "module_path": str(module_path),
        "config_path": str(config_path),
        "explicit_block_present": explicit,
        "attempts": [],
        "errors": [],
    }

    effective: dict | None = None
    source = ""

    # Stage 1/2: normal production import through the selected GIDEON venv.
    if module_path.is_file():
        imported, import_error = import_effective(app_root, config)
        diagnostics["attempts"].append("PRODUCTION_PACKAGE_IMPORT")

        if imported:
            effective = imported
            source = (
                "CONFIG_EXPLICIT"
                if explicit
                else "APPLICATION_EFFECTIVE_DEFAULT"
            )
        elif import_error:
            diagnostics["errors"].append(import_error)
    else:
        diagnostics["errors"].append(
            f"GUACAMOLE_PY_NOT_FOUND:{module_path}"
        )

    # Stage 3: AST/static fallback. This does not import the package and
    # therefore cannot be broken by unrelated WebAdmin imports/side effects.
    ast_defaults: dict[str, Any] = {}
    if effective is None and module_path.is_file():
        diagnostics["attempts"].append("AST_STATIC_DEFAULTS")
        ast_defaults, ast_errors = ast_guacd_defaults(module_path)
        diagnostics["ast_defaults"] = ast_defaults
        diagnostics["errors"].extend(ast_errors)

        try:
            effective = merge_explicit_with_defaults(
                explicit_raw,
                ast_defaults,
            )
            source = (
                "CONFIG_EXPLICIT_AST_DEFAULTS"
                if explicit
                else "APPLICATION_AST_DEFAULT"
            )
        except Exception as exc:
            diagnostics["errors"].append(
                f"AST_EFFECTIVE:{type(exc).__name__}:{exc}"
            )

    if effective is None:
        diagnostics["status"] = "FAIL"
        diagnostics_path.parent.mkdir(parents=True, exist_ok=True)
        diagnostics_path.write_text(
            json.dumps(diagnostics, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "ok": False,
                    "source": "UNRESOLVED",
                    "diagnostics": str(diagnostics_path),
                    "errors": diagnostics["errors"],
                },
                ensure_ascii=False,
            )
        )
        return 2

    payload = {
        **effective,
        "source": source,
        "explicit": explicit,
        "production_guacamole_py": str(module_path),
        "resolution_method": source,
    }

    diagnostics["status"] = "PASS"
    diagnostics["effective"] = payload

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    diagnostics_path.write_text(
        json.dumps(diagnostics, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(json.dumps({"ok": True, **payload}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
