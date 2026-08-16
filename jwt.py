"""Auth JWT — создание и валидация JWT токенов.

Использует PyJWT с алгоритмом HS256.
- create_access_token() → подписанная JWT строка
- create_refresh_token() → opaque UUID4 строка
- validate_access_token() → payload dict
- hash_token() → SHA-256 hex для хранения в БД
- compare_tokens() → безопасное сравнение
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from typing import Any

import jwt

__all__ = [
    "create_access_token",
    "create_refresh_token",
    "validate_access_token",
    "hash_token",
    "compare_tokens",
    "TokenError",
    "TokenExpiredError",
    "TokenInvalidError",
]


class TokenError(Exception):
    """Базовая ошибка токена."""
    pass


class TokenExpiredError(TokenError):
    """Токен истёк."""
    pass


class TokenInvalidError(TokenError):
    """Токен невалиден (подпись, формат, отсутствует jti)."""
    pass


def create_access_token(
    user_id: str,
    username: str,
    perms_version: int,
    secret: str,
    algorithm: str = "HS256",
    expires_in_minutes: int = 15,
) -> str:
    """Создать access token (JWT HS256).

    Payload:
        sub: user_id
        username: username
        perms_version: версия прав (для инвалидации кеша)
        exp: время истечения
        iat: время создания
        jti: уникальный ID токена (обязателен для отзыва)

    Args:
        user_id: ID пользователя.
        username: Имя пользователя.
        perms_version: Версия прав (int, увеличивается при изменении).
        secret: Секрет для подписи.
        algorithm: Алгоритм (по умолчанию HS256).
        expires_in_minutes: Время жизни в минутах.

    Returns:
        JWT строка.
    """
    now = time.time()
    payload = {
        "sub": user_id,
        "username": username,
        "perms_version": perms_version,
        "iat": now,
        "exp": now + (expires_in_minutes * 60),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def create_refresh_token() -> str:
    """Создать refresh token — opaque UUID4 строка.

    Refresh token хранится как SHA-256 хеш в БД,
    поэтому сам токен — случайная строка.
    """
    return str(uuid.uuid4())


def validate_access_token(
    token: str,
    secret: str,
    algorithm: str = "HS256",
) -> dict[str, Any]:
    """Валидировать access token.

    Проверяет:
    - Подпись (secret)
    - Время жизни (exp)
    - Наличие jti в payload

    Args:
        token: JWT строка.
        secret: Секрет для проверки подписи.
        algorithm: Алгоритм.

    Returns:
        Payload dict.

    Raises:
        TokenExpiredError: Токен истёк.
        TokenInvalidError: Подпись невалидна, нет jti, формат ошибочен.
    """
    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError("Token has expired")
    except jwt.InvalidSignatureError:
        raise TokenInvalidError("Invalid token signature")
    except jwt.DecodeError:
        raise TokenInvalidError("Invalid token format")
    except jwt.InvalidTokenError as e:
        raise TokenInvalidError(f"Invalid token: {e}")

    # jti обязателен
    if "jti" not in payload:
        raise TokenInvalidError("Token missing 'jti' claim")

    return payload


def hash_token(token: str) -> str:
    """Хешировать токен через SHA-256 для безопасного хранения в БД.

    Args:
        token: Открытый токен (refresh или access).

    Returns:
        SHA-256 hex строка (64 символа).
    """
    return hashlib.sha256(token.encode()).hexdigest()


def compare_tokens(a: str, b: str) -> bool:
    """Безопасное сравнение двух токенов (хешей).

    Использует hmac.compare_digest для защиты от timing attacks.
    """
    return hmac.compare_digest(a, b)
