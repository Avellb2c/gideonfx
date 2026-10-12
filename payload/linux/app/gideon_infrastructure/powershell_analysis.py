from __future__ import annotations

import re
from pathlib import Path
from typing import Pattern

from gideon_application.ports import ScriptInteractionFinding


class PowerShellInteractiveAnalyzer:
    """Detector estático conservador de interacción humana en PowerShell.

    Antes de buscar comandos, elimina comentarios, strings y here-strings.
    Así variables como ``$PauseEveryDirectories`` no se confunden con el
    comando interactivo real ``Pause``.
    """

    _PATTERNS: tuple[tuple[str, str, Pattern[str]], ...] = (
        (
            "READ_HOST",
            "Read-Host",
            re.compile(r"(?i)(?<![\w-])read-host(?![\w-])"),
        ),
        (
            "HOST_PROMPT_FOR_CHOICE",
            "$Host.UI.PromptForChoice",
            re.compile(
                r"(?i)\$host\s*\.\s*ui\s*\.\s*promptforchoice\s*\("
            ),
        ),
        (
            "HOST_PROMPT",
            "$Host.UI.Prompt",
            re.compile(
                r"(?i)\$host\s*\.\s*ui\s*\.\s*prompt\s*\("
            ),
        ),
        (
            "CONSOLE_READ",
            "Console.ReadLine/ReadKey",
            re.compile(
                r"(?i)\[\s*console\s*\]\s*::\s*(?:readline|readkey)\s*\("
            ),
        ),
        (
            "GET_CREDENTIAL",
            "Get-Credential",
            re.compile(r"(?i)(?<![\w-])get-credential(?![\w-])"),
        ),
        (
            "PAUSE_COMMAND",
            "Pause",
            re.compile(
                r"(?im)(?:^|[;|])\s*(?:&\s*)?pause(?=\s*(?:$|[;|]))"
            ),
        ),
        (
            "CMD_PAUSE",
            "cmd /c pause",
            re.compile(
                r"(?im)(?:^|[;|])\s*(?:&\s*)?cmd(?:\.exe)?\s+/(?:c|k)\s+pause(?=\s|$)"
            ),
        ),
    )

    def analyze(self, path: Path) -> tuple[ScriptInteractionFinding, ...]:
        script_path: Path = Path(path)
        try:
            text: str = script_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
        except OSError:
            return ()
        return self.analyze_text(text)

    def analyze_text(self, text: str) -> tuple[ScriptInteractionFinding, ...]:
        code: str = self._strip_non_code(text)
        findings: list[ScriptInteractionFinding] = []

        for finding_code, label, pattern in self._PATTERNS:
            for match in pattern.finditer(code):
                line: int = code.count("\n", 0, match.start()) + 1
                findings.append(
                    ScriptInteractionFinding(
                        code=finding_code,
                        label=label,
                        line=line,
                    )
                )

        unique: dict[tuple[str, int], ScriptInteractionFinding] = {}
        for finding in findings:
            unique.setdefault((finding.code, finding.line), finding)

        return tuple(
            sorted(
                unique.values(),
                key=lambda item: (item.line, item.code),
            )
        )

    @staticmethod
    def _strip_non_code(text: str) -> str:
        """Sustituye comentarios/strings por espacios conservando saltos de línea."""
        output: list[str] = []
        index: int = 0
        length: int = len(text)
        state: str = "NORMAL"

        def blank(character: str) -> str:
            return character if character in {"\r", "\n"} else " "

        while index < length:
            char: str = text[index]
            nxt: str = text[index + 1] if index + 1 < length else ""

            if state == "LINE_COMMENT":
                output.append(blank(char))
                index += 1
                if char == "\n":
                    state = "NORMAL"
                continue

            if state == "BLOCK_COMMENT":
                if char == "#" and nxt == ">":
                    output.extend((" ", " "))
                    index += 2
                    state = "NORMAL"
                else:
                    output.append(blank(char))
                    index += 1
                continue

            if state == "SINGLE_STRING":
                if char == "'" and nxt == "'":
                    output.extend((" ", " "))
                    index += 2
                elif char == "'":
                    output.append(" ")
                    index += 1
                    state = "NORMAL"
                else:
                    output.append(blank(char))
                    index += 1
                continue

            if state == "DOUBLE_STRING":
                if char == "`" and index + 1 < length:
                    output.append(" ")
                    output.append(blank(nxt))
                    index += 2
                elif char == '"':
                    output.append(" ")
                    index += 1
                    state = "NORMAL"
                else:
                    output.append(blank(char))
                    index += 1
                continue

            if state in {"HERE_SINGLE", "HERE_DOUBLE"}:
                terminator: str = "'@" if state == "HERE_SINGLE" else '"@'
                if text.startswith(terminator, index) and (
                    index == 0 or text[index - 1] in {"\r", "\n"}
                ):
                    output.extend((" ", " "))
                    index += 2
                    state = "NORMAL"
                else:
                    output.append(blank(char))
                    index += 1
                continue

            if char == "#":
                output.append(" ")
                index += 1
                state = "LINE_COMMENT"
                continue

            if char == "<" and nxt == "#":
                output.extend((" ", " "))
                index += 2
                state = "BLOCK_COMMENT"
                continue

            if char == "@" and nxt in {"'", '"'}:
                after: str = text[index + 2] if index + 2 < length else ""
                if after in {"\r", "\n"}:
                    output.extend((" ", " "))
                    index += 2
                    state = "HERE_SINGLE" if nxt == "'" else "HERE_DOUBLE"
                    continue

            if char == "'":
                output.append(" ")
                index += 1
                state = "SINGLE_STRING"
                continue

            if char == '"':
                output.append(" ")
                index += 1
                state = "DOUBLE_STRING"
                continue

            output.append(char)
            index += 1

        return "".join(output)
