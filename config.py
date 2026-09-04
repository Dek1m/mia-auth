"""Auth Module Configuration — конфигурация модуля авторизации.

Читает конфигурацию из переменных окружения, файлов конфигурации
или прямых аргументов.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import ClassVar

from modules_system.pref_spec import PrefField

__all__ = ["AuthConfig"]


@dataclass
class AuthConfig:
    """Конфигурация авторизации.

    Приоритет конфигурации:
    1. Прямые аргументы (наивысший)
    2. Файл конфигурации
    3. Переменные окружения (наименьший)
    """

    # JWT
    jwt_secret: str = ""  # Обязательно: AUTH_JWT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_access_expiration_minutes: int = 15
    jwt_refresh_expiration_days: int = 30

    # Пароли
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_digit: bool = True
    password_history_size: int = 10

    # Сессии
    session_max_age_hours: int = 24 * 7  # 7 дней

    # Лимиты входа
    login_attempts_limit: int = 5
    login_block_minutes: int = 15

    # Кеш прав
    perms_cache_ttl: int = 300  # секунды

    # Повтор того же refresh-hash в окне → та же пара, не revoke family
    refresh_grace_seconds: int = 8

    SETTINGS: ClassVar[tuple[PrefField, ...]] = (
        PrefField(
            "jwt_access_expiration_minutes", "Access token TTL (min)",
            "Срок жизни access-токена. Короткий TTL снижает окно кражи cookie.",
            "int", 15, "Tokens", env="AUTH_JWT_ACCESS_EXPIRATION_MINUTES",
            minimum=1, maximum=1440,
        ),
        PrefField(
            "jwt_refresh_expiration_days", "Refresh token TTL (days)",
            "Срок жизни refresh-токена и cookie сессии.",
            "int", 30, "Tokens", env="AUTH_JWT_REFRESH_EXPIRATION_DAYS",
            minimum=1, maximum=365,
        ),
        PrefField(
            "password_min_length", "Min password length",
            "Минимальная длина пароля при создании и смене.",
            "int", 8, "Security", env="AUTH_PASSWORD_MIN_LENGTH",
            minimum=4, maximum=128,
        ),
        PrefField(
            "password_require_uppercase", "Require uppercase",
            "Пароль обязан содержать заглавную букву.",
            "bool", True, "Security", env="AUTH_PASSWORD_REQUIRE_UPPERCASE",
        ),
        PrefField(
            "password_require_digit", "Require digit",
            "Пароль обязан содержать цифру.",
            "bool", True, "Security", env="AUTH_PASSWORD_REQUIRE_DIGIT",
        ),
        PrefField(
            "password_history_size", "Password history",
            "Сколько предыдущих паролей нельзя повторять.",
            "int", 10, "Security", env="AUTH_PASSWORD_HISTORY_SIZE",
            minimum=0, maximum=50,
        ),
        PrefField(
            "session_max_age_hours", "Session max age (hours)",
            "Максимальный возраст сессии до принудительного logout.",
            "int", 24 * 7, "Tokens", env="AUTH_SESSION_MAX_AGE_HOURS",
            minimum=1, maximum=8760,
        ),
        PrefField(
            "login_attempts_limit", "Login attempts limit",
            "Неудачных попыток до временной блокировки.",
            "int", 5, "Security", env="AUTH_LOGIN_ATTEMPTS_LIMIT",
            minimum=1, maximum=50,
        ),
        PrefField(
            "login_block_minutes", "Login block (min)",
            "На сколько минут блокировать после лимита попыток.",
            "int", 15, "Security", env="AUTH_LOGIN_BLOCK_MINUTES",
            minimum=1, maximum=1440,
        ),
        PrefField(
            "perms_cache_ttl", "Permissions cache TTL (sec)",
            "TTL кеша прав. Меньше — свежее права, больше нагрузка.",
            "int", 300, "Limits", env="AUTH_PERMS_CACHE_TTL",
            minimum=0, maximum=86400,
        ),
        PrefField(
            "refresh_grace_seconds", "Refresh grace (sec)",
            "Окно повторного того же refresh-hash без revoke family.",
            "int", 8, "Tokens", env="AUTH_REFRESH_GRACE_SECONDS",
            minimum=0, maximum=60,
        ),
    )

    # БД (для прямого подключения, если пул не передан извне)
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "mia"
    db_user: str = "mia"
    db_password: str = ""
    db_ssl_mode: str = "prefer"  # disable, allow, prefer, require

    def __post_init__(self) -> None:
        if not self.jwt_secret:
            raise ValueError("jwt_secret is required — set AUTH_JWT_SECRET environment variable")

    @classmethod
    def from_env(cls) -> AuthConfig:
        """Создать конфигурацию из переменных окружения.

        Переменные окружения:
            AUTH_JWT_SECRET (обязательно), AUTH_JWT_ALGORITHM,
            AUTH_JWT_ACCESS_EXPIRATION_MINUTES, AUTH_JWT_REFRESH_EXPIRATION_DAYS
            AUTH_PASSWORD_MIN_LENGTH, AUTH_PASSWORD_REQUIRE_UPPERCASE,
            AUTH_PASSWORD_REQUIRE_DIGIT, AUTH_PASSWORD_HISTORY_SIZE
            AUTH_SESSION_MAX_AGE_HOURS
            AUTH_LOGIN_ATTEMPTS_LIMIT, AUTH_LOGIN_BLOCK_MINUTES
            AUTH_PERMS_CACHE_TTL
            AUTH_DB_HOST, AUTH_DB_PORT, AUTH_DB_NAME,
            AUTH_DB_USER, AUTH_DB_PASSWORD, AUTH_DB_SSL_MODE

        Raises:
            EnvironmentError: Если AUTH_JWT_SECRET не задан.

        Returns:
            Экземпляр AuthConfig.
        """
        return cls(
            jwt_secret=os.environ["AUTH_JWT_SECRET"],  # Обязательная переменная
            jwt_algorithm=os.getenv("AUTH_JWT_ALGORITHM", "HS256"),
            jwt_access_expiration_minutes=int(os.getenv("AUTH_JWT_ACCESS_EXPIRATION_MINUTES", "15")),
            jwt_refresh_expiration_days=int(os.getenv("AUTH_JWT_REFRESH_EXPIRATION_DAYS", "30")),
            password_min_length=int(os.getenv("AUTH_PASSWORD_MIN_LENGTH", "8")),
            password_require_uppercase=os.getenv(
                "AUTH_PASSWORD_REQUIRE_UPPERCASE", "true"
            ).lower()
            == "true",
            password_require_digit=os.getenv("AUTH_PASSWORD_REQUIRE_DIGIT", "true").lower()
            == "true",
            password_history_size=int(os.getenv("AUTH_PASSWORD_HISTORY_SIZE", "10")),
            session_max_age_hours=int(os.getenv("AUTH_SESSION_MAX_AGE_HOURS", str(24 * 7))),
            login_attempts_limit=int(os.getenv("AUTH_LOGIN_ATTEMPTS_LIMIT", "5")),
            login_block_minutes=int(os.getenv("AUTH_LOGIN_BLOCK_MINUTES", "15")),
            perms_cache_ttl=int(os.getenv("AUTH_PERMS_CACHE_TTL", "300")),
            refresh_grace_seconds=int(os.getenv("AUTH_REFRESH_GRACE_SECONDS", "8")),
            db_host=os.getenv("AUTH_DB_HOST", "localhost"),
            db_port=int(os.getenv("AUTH_DB_PORT", "5432")),
            db_name=os.getenv("AUTH_DB_NAME", "mia"),
            db_user=os.getenv("AUTH_DB_USER", "mia"),
            db_password=os.getenv("AUTH_DB_PASSWORD", ""),
            db_ssl_mode=os.getenv("AUTH_DB_SSL_MODE", "prefer"),
        )
