"""Имплементации IdentityProviderPort по identity_kind домена.

local — рабочая обёртка над password.py; basic/oidc/ad — каркасы Части 2
(контракт зафиксирован портом, сетевые impl-ы — следующие волны).
"""
from __future__ import annotations

from .ad import AdIdentity, AdDirectoryConnector
from .basic import BasicIdentity
from .local import LocalIdentity
from .oidc import OidcIdentity

__all__ = [
    "LocalIdentity",
    "BasicIdentity",
    "OidcIdentity",
    "AdIdentity",
    "AdDirectoryConnector",
]
