from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import Response

from .auth import SecurityStore, SessionIdentity
from .step_up_cache import STEP_UP_CACHE, build_remote_scope_key, normalize_remote_client_id


@dataclass(slots=True)
class RequestSecurity:
    """HTTP/session authorization policy for WebAdmin requests.

    The class owns cookie/session, RBAC, CSRF and step-up behavior.  Route
    handlers no longer need to reimplement these rules or depend on how the
    session store authenticates them.
    """

    security: SecurityStore
    config: dict[str, Any]
    session_cookie: str
    default_session_ttl_seconds: int

    def remote_ip(self, request: Request) -> str:
        if bool(self.config.get("trust_proxy_headers", False)):
            forwarded = str(request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
            if forwarded:
                return forwarded
        return str(request.client.host if request.client else "")

    def set_session_cookie(self, response: Response, raw_token: str) -> None:
        response.set_cookie(
            self.session_cookie,
            raw_token,
            httponly=True,
            secure=bool(self.config.get("secure_cookies", True)),
            samesite="strict",
            max_age=int(self.config.get("session_ttl_seconds", self.default_session_ttl_seconds)),
            path="/",
        )

    def current_identity(self, request: Request, *, allow_incomplete: bool = False) -> SessionIdentity | None:
        marker = object()
        cached = getattr(request.state, "gideon_session_identity", marker)
        if cached is marker:
            identity = self.security.identity_for_session(request.cookies.get(self.session_cookie, ""))
            request.state.gideon_session_identity = identity
        else:
            identity = cached
        if identity is None:
            return None
        if allow_incomplete:
            return identity
        if identity.must_change_password and request.url.path not in {"/account/password", "/logout"}:
            return None
        return identity

    def require(self, request: Request, permission: str, *, mfa: bool = True) -> SessionIdentity:
        identity = self.current_identity(request, allow_incomplete=True)
        if identity is None:
            raise HTTPException(status_code=401, detail="LOGIN_REQUIRED")
        require_mfa = bool(self.config.get("require_mfa", True))
        if mfa and require_mfa and (not identity.mfa_enabled or not identity.mfa_complete):
            raise HTTPException(status_code=428, detail="MFA_REQUIRED")
        if identity.must_change_password:
            raise HTTPException(status_code=428, detail="PASSWORD_CHANGE_REQUIRED")
        if not identity.can(permission):
            raise HTTPException(status_code=403, detail="No autorizado")
        return identity

    async def validate_csrf(self, request: Request, identity: SessionIdentity) -> None:
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return
        token = str(request.headers.get("x-csrf-token") or "")
        if not token:
            form = await request.form()
            token = str(form.get("csrf") or "")
        if not token or not secrets.compare_digest(token, identity.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF inválido")

    def step_up_context(self, request: Request) -> dict[str, int | bool]:
        identity = self.current_identity(request, allow_incomplete=True)
        if identity is None:
            return {"active": False, "verified_unix": 0, "until_unix": 0, "remaining_seconds": 0, "ttl_seconds": 900}
        return STEP_UP_CACHE.status(session_id=identity.session_id, user_id=identity.user_id, ttl_seconds=900)

    def require_step_up(
        self,
        request: Request,
        identity: SessionIdentity,
        password: str,
        mfa_code: str,
        *,
        resource: str = "sensitive-operation",
        superadmin_only: bool = False,
    ) -> dict[str, int | bool]:
        if superadmin_only and identity.role != "SUPERADMIN":
            raise HTTPException(status_code=403, detail="Solo SuperAdmin puede realizar esta operación sensible.")
        cached = STEP_UP_CACHE.status(session_id=identity.session_id, user_id=identity.user_id, ttl_seconds=900)
        if bool(cached.get("active")):
            return cached
        if not str(password or "").strip() or not str(mfa_code or "").strip():
            raise HTTPException(status_code=428, detail="STEP_UP_REQUIRED: ingrese contraseña actual y MFA. La autorización se conservará 15 minutos en esta sesión.")
        try:
            effective_resource = request.url.path if resource == "sensitive-operation" else resource
            self.security.step_up_authenticate(
                identity.user_id,
                password,
                mfa_code,
                actor=identity.username,
                remote_ip=self.remote_ip(request),
                resource=effective_resource,
                role=identity.role,
            )
            return STEP_UP_CACHE.mark(session_id=identity.session_id, user_id=identity.user_id, ttl_seconds=900)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    def remote_step_up_scope_key(
        self,
        request: Request,
        identity: SessionIdentity,
        client_id: str,
    ) -> str:
        """Build the remote-control MFA grant scope for this browser context.

        The browser id is opaque metadata generated once and retained in
        localStorage.  It is combined with the authenticated user and
        user-agent before hashing server-side.  The resulting grant is
        independent from a remote target, WebAdmin session-row rotation and
        harmless IPv4/IPv6 egress changes, but cannot be reused by a browser
        context that lacks the same client id.
        """
        cid = normalize_remote_client_id(client_id)
        if not cid:
            # Compatibility/fail-closed fallback for a stale page that has not
            # loaded RC30.95.31.10 JavaScript yet.  This still scopes the grant to
            # the current authenticated WebAdmin session.
            cid = f"legacy-session:{int(identity.session_id)}"
        return build_remote_scope_key(
            user_id=identity.user_id,
            client_id=cid,
            remote_ip=self.remote_ip(request),
            user_agent=str(request.headers.get("user-agent") or ""),
        )

    def remote_step_up_context(
        self,
        request: Request,
        identity: SessionIdentity,
        client_id: str,
    ) -> dict[str, int | bool]:
        scope_key = self.remote_step_up_scope_key(request, identity, client_id)
        return STEP_UP_CACHE.remote_status(
            scope_key=scope_key,
            user_id=identity.user_id,
            ttl_seconds=900,
        )

    def require_mfa_step_up(
        self,
        request: Request,
        identity: SessionIdentity,
        mfa_code: str,
        *,
        resource: str = "interactive-session",
        client_id: str = "",
    ) -> dict[str, int | bool]:
        """Require remote-control MFA once, then reuse it for 15 minutes.

        This grant is deliberately separate from the password+MFA step-up used
        by sensitive WebAdmin operations.  A remote-session MFA can therefore
        never unlock PKI/security administration.
        """
        scope_key = self.remote_step_up_scope_key(request, identity, client_id)
        cached = STEP_UP_CACHE.remote_status(
            scope_key=scope_key, user_id=identity.user_id, ttl_seconds=900
        )
        if bool(cached.get("active")):
            return cached
        if not identity.mfa_enabled or not identity.mfa_complete:
            raise HTTPException(status_code=428, detail="MFA_REQUIRED: complete MFA for the current WebAdmin session.")
        code = "".join(ch for ch in str(mfa_code or "") if ch.isdigit())
        if not code:
            raise HTTPException(status_code=428, detail="REMOTE_MFA_REQUIRED: ingrese el código MFA. Se reutilizará durante 15 minutos para nuevas conexiones remotas en este navegador.")
        secret = self.security.get_mfa_secret(identity.user_id)
        if not secret or not self.security.verify_totp(secret, code):
            self.security.audit(
                identity.username, "auth.step_up.remote_mfa", "FAILED",
                f"Resource={resource}; Scope={scope_key[:12]}",
                self.remote_ip(request), resource=resource, role=identity.role,
            )
            raise HTTPException(status_code=403, detail="Código MFA inválido.")
        self.security.audit(
            identity.username, "auth.step_up.remote_mfa", "SUCCESS",
            f"Resource={resource}; Scope={scope_key[:12]}; TTL=900",
            self.remote_ip(request), resource=resource, role=identity.role,
        )
        return STEP_UP_CACHE.remote_mark(
            scope_key=scope_key,
            user_id=identity.user_id,
            issued_session_id=identity.session_id,
            ttl_seconds=900,
        )

    def require_superadmin_step_up(
        self,
        request: Request,
        identity: SessionIdentity,
        password: str,
        mfa_code: str,
        *,
        resource: str = "sensitive-operation",
    ) -> dict[str, int | bool]:
        return self.require_step_up(
            request, identity, password, mfa_code,
            resource=resource, superadmin_only=True,
        )
