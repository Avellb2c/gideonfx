from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path


def windows_long(path: str) -> str:
    absolute = os.path.abspath(path)
    if os.name != "nt":
        return absolute
    if absolute.startswith("\\\\?\\"):
        return absolute
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def digest_file(path: str, attempts: int = 4) -> tuple[str, int]:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            h = hashlib.sha256()
            size = 0
            with open(windows_long(path), "rb", buffering=1024 * 1024) as handle:
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    h.update(block)
            return h.hexdigest(), size
        except (OSError, PermissionError) as exc:
            last_error = exc
            if attempt < attempts:
                time.sleep(0.25 * attempt)
    assert last_error is not None
    raise last_error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--sha-output", required=True)
    parser.add_argument("--json-report", required=True)
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    root_long = windows_long(root)
    sha_output = os.path.abspath(args.sha_output)
    report_output = os.path.abspath(args.json_report)

    skip_absolute = {
        os.path.normcase(os.path.abspath(sha_output)),
        os.path.normcase(os.path.abspath(report_output)),
    }

    rows: list[dict] = []
    errors: list[dict] = []
    started = time.time()
    processed = 0

    for current, dirs, files in os.walk(root_long):
        dirs[:] = [d for d in dirs if d not in {"__pycache__"}]

        for filename in files:
            full_long = os.path.join(current, filename)

            # Convert \\?\ path back to normal form for relative path/reporting.
            normal = full_long
            if os.name == "nt":
                if normal.startswith("\\\\?\\UNC\\"):
                    normal = "\\\\" + normal[8:]
                elif normal.startswith("\\\\?\\"):
                    normal = normal[4:]

            normal_abs = os.path.abspath(normal)
            processed += 1
            if processed == 1 or processed % 1000 == 0:
                elapsed = int(time.time() - started)
                print(
                    f"HASH_PROGRESS files={processed} elapsed_s={elapsed}",
                    flush=True,
                )
            if os.path.normcase(normal_abs) in skip_absolute:
                continue

            try:
                digest, size = digest_file(normal_abs)
                relative = os.path.relpath(normal_abs, root).replace("\\", "/")
                rows.append(
                    {
                        "path": relative,
                        "sha256": digest,
                        "size": size,
                    }
                )
            except Exception as exc:
                errors.append(
                    {
                        "path": normal_abs,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )

    rows.sort(key=lambda item: item["path"].casefold())

    Path(sha_output).parent.mkdir(parents=True, exist_ok=True)
    Path(sha_output).write_text(
        "".join(f"{row['sha256']}  {row['path']}\n" for row in rows),
        encoding="utf-8",
    )

    report = {
        "root": root,
        "files_hashed": len(rows),
        "errors": errors,
        "status": "PASS" if not errors else "FAIL",
    }
    Path(report_output).write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"FILES_HASHED={len(rows)}")
    print(f"HASH_ERRORS={len(errors)}")
    print(f"LONG_PATH_MANIFEST={'PASS' if not errors else 'FAIL'}")

    if errors:
        for item in errors[:20]:
            print(f"HASH_ERROR={item['path']} :: {item['error']}")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
