"""Ошибки Domain. AdminProvider маппит code в AdminError."""
from __future__ import annotations

__all__ = ["DomainError", "DomainForbidden", "require_name", "is_duplicate"]


class DomainError(Exception):
    """Инвариант каталога. code: FORBIDDEN, DUPLICATE_NAME, OU_NOT_EMPTY, NOT_FOUND, VALIDATION."""

    def __init__(
        self,
        message: str,
        code: str = "DOMAIN_ERROR",
        *,
        human: str | None = None,
        entity: str | None = None,
    ) -> None:
        self.code = code
        self.human = human or message
        self.entity = entity
        super().__init__(message)


class DomainForbidden(DomainError):
    def __init__(self, message: str = "Forbidden", *, human: str | None = None) -> None:
        super().__init__(message, "FORBIDDEN", human=human)


def require_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        raise DomainError("Name is empty", "VALIDATION", human="Name is required")
    return cleaned


def is_duplicate(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "unique" in text or "duplicate" in text
