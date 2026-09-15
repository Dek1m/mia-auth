"""AdIdentity + AdDirectoryConnector — домен kind='ad' (Active Directory).

Каркасы Части 2. Контракты портов:
- AdIdentity.authenticate: Kerberos/NTLM через bind — волна интеграции LDAP.
- AdDirectoryConnector.sync_users/sync_groups: идемпотентный импорт
  (sAMAccountName → username, группы → scope='domain', domain_id домена).
- Bind-пароль — secrets-механизм по ключу домена, НЕ ad_config.
"""
from __future__ import annotations

from typing import Any

from ..directory_port import SyncReport
from ..identity_port import IdentityResult

__all__ = ["AdIdentity", "AdDirectoryConnector"]


class AdIdentity:
    """Скелет: идентичность через AD-контроллер домена."""

    def __init__(self, ad_config: dict[str, Any]) -> None:
        self._config = dict(ad_config)

    async def authenticate(self, credentials: dict[str, Any]) -> IdentityResult | None:
        raise NotImplementedError("ad-identity: LDAP bind — волна после Части 2")

    async def discover(self, hint: str) -> str | None:
        # UPN-суффикс (user@corp.local) сверяется с ad_config['upn_suffixes'].
        raise NotImplementedError("ad-identity: discover по UPN-суффиксу")


class AdDirectoryConnector:
    """Скелет коннектора каталога (DirectoryConnectorPort)."""

    def __init__(self, ad_config: dict[str, Any], repo: Any) -> None:
        """Args:
            ad_config: auth.domains.ad_config домена.
            repo: AuthRepository — запись синхронизируемых users/groups.
        """
        self._config = dict(ad_config)
        self._repo = repo

    async def test_connection(self, config: dict[str, Any]) -> bool:
        raise NotImplementedError("ad-connector: LDAP ping — волна после Части 2")

    async def sync_users(self, domain_id: str) -> SyncReport:
        raise NotImplementedError("ad-connector: sync_users — волна после Части 2")

    async def sync_groups(self, domain_id: str) -> SyncReport:
        raise NotImplementedError("ad-connector: sync_groups — волна после Части 2")
