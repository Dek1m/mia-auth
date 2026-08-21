"""Auth Validators — Pydantic-схемы и проверки профиля (ADR-001 §5.2)."""
from __future__ import annotations

import base64
import re

from pydantic import BaseModel, field_validator

__all__ = [
    "CreateUserSchema",
    "LoginSchema",
    "UpdateUserSchema",
    "UserResponseSchema",
    "CHIP_MODES",
    "AVATAR_MAX_BYTES",
    "AVATAR_MIME",
    "validate_chip_display_mode",
    "validate_profile_patch",
    "validate_email_simple",
    "decode_avatar",
    "ForbiddenAvatarError",
]


class ForbiddenAvatarError(ValueError):
    """Аватар отвергнут политикой (SVG / MIME), не ошибка формата."""

CHIP_MODES = frozenset({"nickname", "full_name"})
AVATAR_MAX_BYTES = 256 * 1024
AVATAR_MIME = frozenset({"image/jpeg", "image/png", "image/webp"})
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_NICK_MAX = 255
_PHONE_MAX = 32
_PROMPT_MAX = 32 * 1024


def validate_chip_display_mode(value: str) -> str:
    if value not in CHIP_MODES:
        raise ValueError("chip_display_mode must be 'nickname' or 'full_name'")
    return value


def validate_email_simple(value: str) -> str:
    if not _EMAIL_RE.match(value):
        raise ValueError(f"Invalid email: {value}")
    return value


def validate_profile_patch(data: dict[str, object]) -> dict[str, object]:
    """Длины и enum. Два режима chip — один enum, не два boolean."""
    cleaned: dict[str, object] = {}
    for key in ("nickname", "first_name", "last_name"):
        if key not in data:
            continue
        value = data[key]
        if value is None:
            cleaned[key] = None
            continue
        text = str(value).strip()
        if len(text) > _NICK_MAX:
            raise ValueError(f"{key} must be ≤ {_NICK_MAX} characters")
        cleaned[key] = text or None
    if "email" in data:
        email = data["email"]
        if email is None or str(email).strip() == "":
            cleaned["email"] = None
        else:
            cleaned["email"] = validate_email_simple(str(email).strip())
    if "phone" in data:
        phone = data["phone"]
        if phone is None or str(phone).strip() == "":
            cleaned["phone"] = None
        else:
            text = str(phone).strip()
            if len(text) > _PHONE_MAX:
                raise ValueError(f"phone must be ≤ {_PHONE_MAX} characters")
            cleaned["phone"] = text
    if "user_prompt" in data:
        prompt = data["user_prompt"]
        if prompt is None:
            cleaned["user_prompt"] = None
        else:
            text = str(prompt)
            if len(text.encode("utf-8")) > _PROMPT_MAX:
                raise ValueError("user_prompt must be ≤ 32 KiB")
            cleaned["user_prompt"] = text
    if "chip_display_mode" in data and data["chip_display_mode"] is not None:
        cleaned["chip_display_mode"] = validate_chip_display_mode(
            str(data["chip_display_mode"]),
        )
    return cleaned


def decode_avatar(image_b64: str, content_type: str) -> bytes:
    """MIME jpeg|png|webp, не SVG, ≤256 KiB raw. Forbidden через ValueError → 400;
    SVG/MIME — вызывающий мапит в ForbiddenError."""
    mime = (content_type or "").split(";")[0].strip().lower()
    if mime == "image/svg+xml" or mime.endswith("+xml") or mime == "image/svg":
        raise ForbiddenAvatarError("SVG is not allowed")
    if mime not in AVATAR_MIME:
        raise ForbiddenAvatarError("Unsupported image type")
    try:
        raw = base64.b64decode(image_b64.strip(), validate=False)
    except Exception as exc:
        raise ValueError("Invalid image encoding") from exc
    if len(raw) > AVATAR_MAX_BYTES:
        raise ValueError("Avatar must be ≤ 256 KiB")
    head = raw[:64].lstrip().lower()
    if head.startswith(b"<svg") or head.startswith(b"<?xml") or b"<svg" in head:
        raise ForbiddenAvatarError("SVG is not allowed")
    if mime == "image/jpeg" and not raw.startswith(b"\xff\xd8"):
        raise ForbiddenAvatarError("Image bytes do not match content_type")
    if mime == "image/png" and not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ForbiddenAvatarError("Image bytes do not match content_type")
    if mime == "image/webp" and not (raw.startswith(b"RIFF") and b"WEBP" in raw[:16]):
        raise ForbiddenAvatarError("Image bytes do not match content_type")
    return raw


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
