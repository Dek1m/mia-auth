"""OidcIdentity — identity_kind='oidc': OpenID Connect / OAuth2.

Каркас Части 2. Контракт:
- authenticate({token}) → интроспекция/JWKS-валидация по auth_config
  (issuer, client_id, jwks_url); claims сопоставляются с auth.users
  по preferred_username/email; отсутствующий пользователь — JIT-provisioning
  в домен (если включён auth_config['jit']).
- client_secret хранит secrets-механизм, НЕ auth_config.
"""
from __future__ import annotations

from typing import Any

from ..identity_port import IdentityResult

__all__ = ["OidcIdentity"]


class OidcIdentity:
    """Скелет: OIDC-верификация токена."""

    def __init__(self, auth_config: dict[str, Any]) -> None:
        self._config = dict(auth_config)

    async def authenticate(self, credentials: dict[str, Any]) -> IdentityResult | None:
        raise NotImplementedError("oidc-identity: OIDC-флоу — волна после Части 2")

    async def discover(self, hint: str) -> str | None:
        # Email-домен подсказки сверяется с auth_config['email_domains'].
        raise NotImplementedError("oidc-identity: discover по email-домену")
