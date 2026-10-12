"""GIDEON Web Admin package for headless Linux/AWS deployments.

Keep the FastAPI composition root lazy so installer-only helpers can import
``gideon_web_admin.auth`` without requiring the complete Web runtime first.
"""

from typing import Any

__all__ = ["create_app"]


def __getattr__(name: str) -> Any:
    if name == "create_app":
        from .app import create_app

        return create_app
    raise AttributeError(name)
