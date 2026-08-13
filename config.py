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
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24

    # Пароли
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_digit: bool = True

    # Сессии
    session_max_age_hours: int = 24 * 7  # 7 дней

    # Лимиты
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15

    @classmethod
    def from_env(cls) -> AuthConfig:
        """Создать конфигурацию из переменных окружения.

        Переменные окружения:
            AUTH_JWT_SECRET, AUTH_JWT_ALGORITHM, AUTH_JWT_EXPIRATION_HOURS
            AUTH_PASSWORD_MIN_LENGTH, AUTH_PASSWORD_REQUIRE_UPPERCASE, AUTH_PASSWORD_REQUIRE_DIGIT
            AUTH_SESSION_MAX_AGE_HOURS
            AUTH_MAX_LOGIN_ATTEMPTS, AUTH_LOCKOUT_DURATION_MINUTES

        Returns:
            Экземпляр AuthConfig.
        """
        return cls(
            jwt_secret=os.getenv("AUTH_JWT_SECRET", "change-me-in-production"),
            jwt_algorithm=os.getenv("AUTH_JWT_ALGORITHM", "HS256"),
            jwt_expiration_hours=int(os.getenv("AUTH_JWT_EXPIRATION_HOURS", "24")),
            password_min_length=int(os.getenv("AUTH_PASSWORD_MIN_LENGTH", "8")),
            password_require_uppercase=os.getenv(
                "AUTH_PASSWORD_REQUIRE_UPPERCASE", "true"
            ).lower()
            == "true",
            password_require_digit=os.getenv("AUTH_PASSWORD_REQUIRE_DIGIT", "true").lower()
            == "true",
            session_max_age_hours=int(os.getenv("AUTH_SESSION_MAX_AGE_HOURS", str(24 * 7))),
            max_login_attempts=int(os.getenv("AUTH_MAX_LOGIN_ATTEMPTS", "5")),
            lockout_duration_minutes=int(os.getenv("AUTH_LOCKOUT_DURATION_MINUTES", "15")),
        )
