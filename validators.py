"""Auth Validators — Pydantic-схемы для модуля авторизации."""
from __future__ import annotations

from pydantic import BaseModel, field_validator

__all__ = [
    "CreateUserSchema",
    "LoginSchema",
    "UpdateUserSchema",
    "UserResponseSchema",
]


class CreateUserSchema(BaseModel):
    """Схема создания пользователя."""

    username: str
    password: str
    email: str | None = None
    roles: list[str] | None = None

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not v.isalnum():
            raise ValueError("Username must be alphanumeric")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginSchema(BaseModel):
    """Схема входа."""

    username: str
    password: str


class UpdateUserSchema(BaseModel):
    """Схема обновления пользователя."""

    email: str | None = None
    roles: list[str] | None = None
    permissions: list[str] | None = None
    is_active: bool | None = None


class UserResponseSchema(BaseModel):
    """Схема ответа пользователя."""

    id: str
    username: str
    email: str | None = None
    roles: list[str] = []
    permissions: list[str] = []
    is_active: bool = True
    created_at: float | None = None
    last_login: float | None = None
