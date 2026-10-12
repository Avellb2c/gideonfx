from __future__ import annotations

import base64


def ps_single_quote(value: str) -> str:
    return value.replace("'", "''")


def powershell_stdin_payload(code: str) -> str:
    return base64.b64encode(code.encode("utf-16le")).decode("ascii")


def utf8_bom_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8-sig")).decode("ascii")
