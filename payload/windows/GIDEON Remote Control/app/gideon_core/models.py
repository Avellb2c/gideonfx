from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class SiteIdentity:
    code: str
    name: str
    ip: str

    @property
    def label(self) -> str:
        return f"{self.code}_{self.name}"


@dataclass(frozen=True, slots=True)
class ScriptDefinition:
    index: int
    name: str
    remote_name: str
    result_name: str
    sha256: str
    size_bytes: int
    execution: dict[str, Any] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {"Ok": self.ok, "Errors": list(self.errors), "Warnings": list(self.warnings)}
