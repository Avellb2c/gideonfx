from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

WIN_INSTALL = r"C:\Program Files\GIDEON Remote Control"
WIN_DATA = r"C:\ProgramData\GIDEON Remote Control"


def translate(value):
    if isinstance(value, str):
        return (
            value.replace(WIN_INSTALL, "/opt/gideon-remote-control/app")
            .replace(WIN_DATA, "/var/lib/gideon-remote-control")
        )
    if isinstance(value, list):
        return [translate(item) for item in value]
    if isinstance(value, dict):
        return {key: translate(item) for key, item in value.items()}
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--web-port", type=int, default=28443)
    parser.add_argument("--gateway-port", type=int, default=29443)
    parser.add_argument("--fqdn", default="")
    args = parser.parse_args()

    source = Path(args.source)
    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)

    if not source.exists():
        return 0

    for path in source.rglob("*"):
        if not path.is_file():
            continue

        relative = path.relative_to(source)
        output = dest / relative
        output.parent.mkdir(parents=True, exist_ok=True)

        if path.suffix.lower() == ".json":
            try:
                obj = translate(json.loads(path.read_text(encoding="utf-8-sig")))
                if path.name == "web_admin.json":
                    obj["listen_port"] = args.web_port
                    obj["gateway_base_url"] = f"https://127.0.0.1:{args.gateway_port}"
                    if args.fqdn:
                        obj["public_fqdn"] = args.fqdn

                if path.name == "gateway.json":
                    for key in ("listen_port", "port", "bind_port"):
                        if key in obj:
                            obj[key] = args.gateway_port
                            break
                    if args.fqdn and "public_url" in obj:
                        obj["public_url"] = f"https://{args.fqdn}:443"

                output.write_text(
                    json.dumps(obj, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                continue
            except Exception:
                # Non-JSON or malformed historical config is preserved verbatim.
                pass

        shutil.copy2(path, output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
