"""Auth Password — хеширование паролей через argon2id.

Поддерживает:
- hash_password() → argon2id hash
- verify_password() → bool + опциональный rehash
- needs_rehash() → True если параметры не совпадают

Формат хеша argon2id: $argon2id$v=19$m=19456,t=12,p=4$salt$hash
Формат старого PBKDF2: salt_hex:key_hex
"""
from __future__ import annotations

import hashlib
import hmac

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from argon2.low_level import Type

__all__ = ["hash_password", "verify_password", "needs_rehash"]

# OWASP-recommended argon2id parameters:
# m=19456 (19 MiB), t=12, p=4
_HASHER = PasswordHasher(
    memory_cost=19456,
    time_cost=12,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# PBKDF2 legacy params (used for detection)
_PBKDF2_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    """Хешировать пароль через argon2id.

    Args:
        password: Пароль в открытом виде.

    Returns:
        Argon2id hash строка.
    """
    return _HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> tuple[bool, str | None]:
    """Проверить пароль.

    Args:
        password: Пароль в открытом виде.
        password_hash: Хеш для проверки.

    Returns:
        Tuple[ok, new_hash]:
        - ok: True если пароль верный
        - new_hash: Если пароль верный, но хеш устарел (PBKDF2 или argon2id
          с другими параметрами) — возвращает новый argon2id хеш.
          Если хеш уже актуален — None.
    """
    # Определяем формат хеша
    if password_hash.startswith("$argon2"):
        return _verify_argon2id(password, password_hash)
    elif ":" in password_hash and len(password_hash.split(":")) == 2:
        return _verify_pbkdf2_legacy(password, password_hash)
    else:
        return False, None


def needs_rehash(password_hash: str) -> bool:
    """Проверить, нужно ли перехешировать пароль.

    Returns True если:
    - Хеш в формате PBKDF2 (legacy)
    - Хеш argon2id но с другими параметрами (memory/time/parallelism)
    """
    if not password_hash.startswith("$argon2"):
        return True  # PBKDF2 или другой legacy формат

    # Проверяем параметры argon2id хеша
    # Формат: $argon2id$v=19$m=19456,t=12,p=4$salt$hash
    try:
        parts = password_hash.split("$")
        # Ищем part содержащий m=,t=,p=
        for part in parts:
            if "m=" in part and "t=" in part and "p=" in part:
                params = {}
                for param in part.split(","):
                    key, val = param.split("=")
                    params[key.strip()] = int(val.strip())

                if params.get("m") != _HASHER.memory_cost:
                    return True
                if params.get("t") != _HASHER.time_cost:
                    return True
                if params.get("p") != _HASHER.parallelism:
                    return True
                return False
    except (ValueError, IndexError):
        return True  # Не можем распарсить — считаем устаревшим

    return False


def _verify_argon2id(password: str, password_hash: str) -> tuple[bool, str | None]:
    """Проверка через argon2id с поддержкой rehash."""
    try:
        _HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False, None
    except InvalidHashError:
        return False, None

    # Пароль верный — нужен ли rehash?
    rehash = needs_rehash(password_hash)
    new_hash = hash_password(password) if rehash else None
    return True, new_hash


def _verify_pbkdf2_legacy(password: str, password_hash: str) -> tuple[bool, str | None]:
    """Проверка legacy PBKDF2 хеша (salt:key_hex)."""
    try:
        salt_hex, key_hex = password_hash.split(":")
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt_hex.encode(),
            iterations=_PBKDF2_ITERATIONS,
        )
        ok = hmac.compare_digest(key.hex(), key_hex)
        if ok:
            # Пароль верный — возвращаем argon2id хеш для обновления
            return True, hash_password(password)
        return False, None
    except (ValueError, AttributeError):
        return False, None
