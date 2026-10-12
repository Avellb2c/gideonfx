from __future__ import annotations

"""White-label branding and code-signing configuration.

The module deliberately keeps secrets out of JSON.  PFX passwords are read only
from an environment variable at build time.  The same immutable BrandProfile is
consumed by all native packagers (EXE/DEB/RPM/PKG), keeping UI, packaging and
security policy separated according to SOLID.
"""

from dataclasses import dataclass, asdict
import json
import os
from pathlib import Path
import re
from typing import Any


DEFAULT_BRANDING: dict[str, Any] = {
    "schema_version": 1,
    "company_name": "Gideon Rx Project",
    "publisher_name": "Gideon Rx Contributors",
    "product_name": "Gideon Rx",
    "agent_product_name": "Gideon Rx Agent",
    "product_description": "Administración remota segura y multiplataforma de código abierto",
    "agent_description": "Agente administrado de Gideon Rx",
    "copyright": "Copyright 2026 Gideon Rx Contributors",
    "website_url": "",
    "support_url": "",
    "bundle_id": "org.gideonrx.agent",
    "agent_package_basename": "GideonRxAgent",
    "icon_path": "assets/gideon_agent_tray.ico",
    "signing": {
        "mode": "optional",
        "provider": "auto",
        "certificate_thumbprint": "",
        "pfx_path": "",
        "pfx_password_env": "GIDEON_SIGNING_PFX_PASSWORD",
        "timestamp_url": "http://timestamp.digicert.com",
        "digest_algorithm": "sha256",
        "verify_after_sign": True,
    "expected_publisher": "Gideon Rx Contributors",
    },
}


@dataclass(frozen=True)
class SigningProfile:
    mode: str = "optional"  # disabled | optional | required
    provider: str = "auto"  # auto | store | pfx
    certificate_thumbprint: str = ""
    pfx_path: str = ""
    pfx_password_env: str = "GIDEON_SIGNING_PFX_PASSWORD"
    timestamp_url: str = "http://timestamp.digicert.com"
    digest_algorithm: str = "sha256"
    verify_after_sign: bool = True
    expected_publisher: str = "Gideon Rx Contributors"

    @property
    def required(self) -> bool:
        return self.mode.casefold() == "required"

    @property
    def disabled(self) -> bool:
        return self.mode.casefold() == "disabled"


@dataclass(frozen=True)
class BrandProfile:
    company_name: str
    publisher_name: str
    product_name: str
    agent_product_name: str
    product_description: str
    agent_description: str
    copyright: str
    website_url: str
    support_url: str
    bundle_id: str
    agent_package_basename: str
    icon_path: str
    signing: SigningProfile

    def package_basename(self) -> str:
        value = re.sub(r"[^A-Za-z0-9._-]+", "-", self.agent_package_basename.strip()).strip("-._")
        return value or "GideonRxAgent"

    def metadata_text(self, value: str) -> str:
        """Return a single-line value safe for DEB/RPM/installer metadata."""
        return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split()).strip()

    def icon_file(self, app_root: Path) -> Path | None:
        raw = str(self.icon_path or "").strip()
        if not raw:
            return None
        path = Path(os.path.expandvars(raw)).expanduser()
        if not path.is_absolute():
            path = Path(app_root) / path
        return path.resolve() if path.is_file() else None


class BrandingRepository:
    ENV_MAP = {
        "company_name": "GIDEON_BRAND_COMPANY",
        "publisher_name": "GIDEON_BRAND_PUBLISHER",
        "product_name": "GIDEON_BRAND_PRODUCT",
        "agent_product_name": "GIDEON_BRAND_AGENT_PRODUCT",
        "product_description": "GIDEON_BRAND_DESCRIPTION",
        "agent_description": "GIDEON_BRAND_AGENT_DESCRIPTION",
        "copyright": "GIDEON_BRAND_COPYRIGHT",
        "website_url": "GIDEON_BRAND_WEBSITE",
        "support_url": "GIDEON_BRAND_SUPPORT_URL",
        "bundle_id": "GIDEON_BRAND_BUNDLE_ID",
        "agent_package_basename": "GIDEON_BRAND_AGENT_BASENAME",
        "icon_path": "GIDEON_BRAND_ICON",
    }
    SIGN_ENV_MAP = {
        "mode": "GIDEON_SIGNING_MODE",
        "provider": "GIDEON_SIGNING_PROVIDER",
        "certificate_thumbprint": "GIDEON_SIGNING_CERT_THUMBPRINT",
        "pfx_path": "GIDEON_SIGNING_PFX_PATH",
        "pfx_password_env": "GIDEON_SIGNING_PFX_PASSWORD_ENV",
        "timestamp_url": "GIDEON_SIGNING_TIMESTAMP_URL",
        "digest_algorithm": "GIDEON_SIGNING_DIGEST",
        "expected_publisher": "GIDEON_SIGNING_EXPECTED_PUBLISHER",
    }

    def __init__(self, app_root: Path) -> None:
        self.app_root = Path(app_root).resolve()
        self.path = self.app_root / "config" / "branding.json"

    @staticmethod
    def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        result = json.loads(json.dumps(base, ensure_ascii=False))
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = BrandingRepository._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def ensure(self) -> None:
        if self.path.is_file():
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write(DEFAULT_BRANDING)

    def _atomic_write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)

    def raw(self) -> dict[str, Any]:
        self.ensure()
        try:
            current = json.loads(self.path.read_text(encoding="utf-8-sig"))
            if not isinstance(current, dict):
                current = {}
        except Exception:
            current = {}
        return self._deep_merge(DEFAULT_BRANDING, current)

    def load(self) -> BrandProfile:
        data = self.raw()
        signing = dict(data.get("signing") or {})
        for key, env_name in self.ENV_MAP.items():
            value = os.environ.get(env_name)
            if value is not None and value != "":
                data[key] = value
        for key, env_name in self.SIGN_ENV_MAP.items():
            value = os.environ.get(env_name)
            if value is not None and value != "":
                signing[key] = value
        verify_env = os.environ.get("GIDEON_SIGNING_VERIFY")
        if verify_env is not None:
            signing["verify_after_sign"] = verify_env.strip().casefold() not in {"0", "false", "no", "off"}

        mode = str(signing.get("mode") or "optional").casefold()
        if mode not in {"disabled", "optional", "required"}:
            mode = "optional"
        provider = str(signing.get("provider") or "auto").casefold()
        if provider not in {"auto", "store", "pfx"}:
            provider = "auto"
        digest = str(signing.get("digest_algorithm") or "sha256").casefold()
        if digest not in {"sha256", "sha384", "sha512"}:
            digest = "sha256"

        sign_profile = SigningProfile(
            mode=mode,
            provider=provider,
            certificate_thumbprint=str(signing.get("certificate_thumbprint") or "").replace(" ", ""),
            pfx_path=str(signing.get("pfx_path") or ""),
            pfx_password_env=str(signing.get("pfx_password_env") or "GIDEON_SIGNING_PFX_PASSWORD"),
            timestamp_url=str(signing.get("timestamp_url") or ""),
            digest_algorithm=digest,
            verify_after_sign=bool(signing.get("verify_after_sign", True)),
            expected_publisher=str(signing.get("expected_publisher") or data.get("publisher_name") or ""),
        )
        return BrandProfile(
            company_name=str(data.get("company_name") or "Gideon Rx Project"),
            publisher_name=str(data.get("publisher_name") or data.get("company_name") or "Gideon Rx Contributors"),
            product_name=str(data.get("product_name") or "Gideon Rx"),
            agent_product_name=str(data.get("agent_product_name") or "Gideon Rx Agent"),
            product_description=str(data.get("product_description") or ""),
            agent_description=str(data.get("agent_description") or ""),
            copyright=str(data.get("copyright") or ""),
            website_url=str(data.get("website_url") or ""),
            support_url=str(data.get("support_url") or ""),
            bundle_id=str(data.get("bundle_id") or "org.gideonrx.agent"),
            agent_package_basename=str(data.get("agent_package_basename") or "GideonRxAgent"),
            icon_path=str(data.get("icon_path") or ""),
            signing=sign_profile,
        )

    def save(self, payload: dict[str, Any]) -> BrandProfile:
        current = self.raw()
        allowed = set(DEFAULT_BRANDING) - {"schema_version", "signing"}
        for key in allowed:
            if key in payload:
                current[key] = str(payload[key] or "")
        if isinstance(payload.get("signing"), dict):
            sign = dict(current.get("signing") or {})
            for key in DEFAULT_BRANDING["signing"]:
                if key in payload["signing"]:
                    value = payload["signing"][key]
                    sign[key] = bool(value) if key == "verify_after_sign" else str(value or "")
            current["signing"] = sign
        current["schema_version"] = 1
        self._atomic_write(current)
        return self.load()

    def as_dict(self, profile: BrandProfile | None = None) -> dict[str, Any]:
        p = profile or self.load()
        data = asdict(p)
        data["schema_version"] = 1
        return data
