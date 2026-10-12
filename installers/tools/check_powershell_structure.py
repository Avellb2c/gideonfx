from __future__ import annotations

import argparse
import json
from pathlib import Path


PAIRS = {
    "{": "}",
    "(": ")",
    "[": "]",
}
CLOSING = {value: key for key, value in PAIRS.items()}


def scan_powershell(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8-sig")
    errors: list[dict] = []
    stack: list[tuple[str, int, int]] = []

    i = 0
    line = 1
    column = 1
    state = "code"
    here_end = None

    def advance(ch: str) -> None:
        nonlocal line, column
        if ch == "\n":
            line += 1
            column = 1
        else:
            column += 1

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "line_comment":
            advance(ch)
            i += 1
            if ch == "\n":
                state = "code"
            continue

        if state == "block_comment":
            if ch == "#" and nxt == ">":
                advance(ch)
                advance(nxt)
                i += 2
                state = "code"
                continue
            advance(ch)
            i += 1
            continue

        if state == "single":
            if ch == "'" and nxt == "'":
                advance(ch)
                advance(nxt)
                i += 2
                continue
            if ch == "'":
                advance(ch)
                i += 1
                state = "code"
                continue
            advance(ch)
            i += 1
            continue

        if state == "double":
            if ch == "`" and nxt:
                advance(ch)
                advance(nxt)
                i += 2
                continue
            if ch == '"':
                advance(ch)
                i += 1
                state = "code"
                continue
            advance(ch)
            i += 1
            continue

        if state == "here":
            # PowerShell here-string terminator must begin at column 1.
            if column == 1 and here_end and text.startswith(here_end, i):
                for part in here_end:
                    advance(part)
                i += len(here_end)
                state = "code"
                here_end = None
                continue
            advance(ch)
            i += 1
            continue

        # code state
        if ch == "#":
            state = "line_comment"
            advance(ch)
            i += 1
            continue

        if ch == "<" and nxt == "#":
            state = "block_comment"
            advance(ch)
            advance(nxt)
            i += 2
            continue

        if ch == "@" and nxt in {"'", '"'}:
            quote = nxt
            here_end = quote + "@"
            state = "here"
            advance(ch)
            advance(nxt)
            i += 2
            continue

        if ch == "'":
            state = "single"
            advance(ch)
            i += 1
            continue

        if ch == '"':
            state = "double"
            advance(ch)
            i += 1
            continue

        if ch in PAIRS:
            stack.append((ch, line, column))
        elif ch in CLOSING:
            expected_open = CLOSING[ch]
            if not stack:
                errors.append(
                    {
                        "type": "unexpected_closing",
                        "token": ch,
                        "line": line,
                        "column": column,
                    }
                )
            else:
                opening, open_line, open_column = stack[-1]
                if opening != expected_open:
                    errors.append(
                        {
                            "type": "mismatched_closing",
                            "token": ch,
                            "line": line,
                            "column": column,
                            "opening": opening,
                            "opening_line": open_line,
                            "opening_column": open_column,
                        }
                    )
                else:
                    stack.pop()

        advance(ch)
        i += 1

    for opening, open_line, open_column in stack:
        errors.append(
            {
                "type": "unclosed_opening",
                "token": opening,
                "line": open_line,
                "column": open_column,
            }
        )

    if state in {"single", "double", "block_comment", "here"}:
        errors.append(
            {
                "type": "unterminated_lexical_state",
                "state": state,
                "line": line,
                "column": column,
            }
        )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report", required=False)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    results = []
    total_errors = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".ps1", ".psm1"}:
            continue

        errors = scan_powershell(path)
        total_errors += len(errors)
        results.append(
            {
                "file": path.relative_to(root).as_posix(),
                "errors": errors,
            }
        )

    payload = {
        "files_scanned": len(results),
        "errors": total_errors,
        "status": "PASS" if total_errors == 0 else "FAIL",
        "files": results,
    }

    if args.report:
        Path(args.report).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    print(f"POWERSHELL_STRUCTURE_FILES={len(results)}")
    print(f"POWERSHELL_STRUCTURE_ERRORS={total_errors}")
    print(
        "POWERSHELL_STRUCTURE_CHECK="
        + ("PASS" if total_errors == 0 else "FAIL")
    )

    if total_errors:
        for row in results:
            for error in row["errors"][:20]:
                print(
                    f"STRUCTURE_ERROR={row['file']}:"
                    f"{error.get('line')}:{error.get('column')}:"
                    f"{error.get('type')}:{error.get('token','')}"
                )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
