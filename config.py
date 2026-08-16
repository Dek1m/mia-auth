"""Auth Module Configuration — конфигурация модуля авторизации.

Читает конфигурацию из переменных окружения, файлов конфигурации
или прямых аргументов.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

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
            db_host=os.getenv("AUTH_DB_HOST", "localhost"),
            db_port=int(os.getenv("AUTH_DB_PORT", "5432")),
            db_name=os.getenv("AUTH_DB_NAME", "mia"),
            db_user=os.getenv("AUTH_DB_USER", "mia"),
            db_password=os.getenv("AUTH_DB_PASSWORD", ""),
            db_ssl_mode=os.getenv("AUTH_DB_SSL_MODE", "prefer"),
        )
