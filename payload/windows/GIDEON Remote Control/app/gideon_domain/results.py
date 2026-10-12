from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Outcome(Generic[T]):
    ok: bool
    value: T | None = None
    error_code: str | None = None
    error_message: str | None = None

    @classmethod
    def success(cls, value: T | None = None) -> "Outcome[T]":
        return cls(ok=True, value=value)

    @classmethod
    def failure(cls, code: str, message: str) -> "Outcome[T]":
        return cls(ok=False, error_code=code, error_message=message)
