"""Auth Provider — полная реализация авторизации для Mia Framework.

Phase 1: in-memory → PostgreSQL.
- Пользователи, группы, роли, связи хранятся в БД
- JWT access/refresh токены
- argon2id для паролей с lazy rehash
- Кеш permissions с TTL
- Bootstrap для первого администратора
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


from .config import AuthConfig
from .decorators import auth_method
from .password import hash_password, verify_password, needs_rehash
from .jwt import (
    create_access_token,
    create_refresh_token,
    validate_access_token,
    hash_token,
    compare_tokens,
    TokenExpiredError,
    TokenInvalidError,
)
from .repository import AuthRepository
from .permissions_cache import PermissionsCache
from .schema_registry import AuthSchemaRegistry
from .schema import AUTH_CORE_SCHEMA
from .bootstrap import AuthBootstrap


__all__ = ["AuthProvider", "UserContext"]


# ── Контекст пользователя ──────────────────────────────

@dataclass
class UserContext:
    """Контекст аутентифицированного пользователя."""
    user_id: str
    username: str
    perms_version: int


# ── Исключения ──────────────────────────────────────────

class AuthError(Exception):
    """Базовая ошибка auth-модуля."""

    def __init__(self, message: str, code: str = "AUTH_ERROR") -> None:
        self.code = code
        super().__init__(message)


class InvalidCredentialsError(AuthError):
    def __init__(self) -> None:
        super().__init__("Invalid username or password", "INVALID_CREDENTIALS")


class AccountLockedError(AuthError):
    def __init__(self, locked_until: datetime | None = None) -> None:
        msg = "Account is locked"
        if locked_until:
            msg += f" until {locked_until.isoformat()}"
        super().__init__(msg, "LOCKED")


class AccountDisabledError(AuthError):
    def __init__(self) -> None:
        super().__init__("Account is disabled", "DISABLED")


class ReuseDetectedError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            "Refresh token reuse detected — all sessions revoked", "REUSE_DETECTED"
        )


class NotFoundError(AuthError):
    def __init__(self, entity: str = "Resource") -> None:
        super().__init__(f"{entity} not found", "NOT_FOUND")


class PermissionDeniedError(AuthError):
    def __init__(self) -> None:
        super().__init__("Permission denied", "PERMISSION_DENIED")


class ForbiddenError(AuthError):
    def __init__(self, message: str = "Forbidden") -> None:
        super().__init__(message, "FORBIDDEN")


# ── Провайдер ───────────────────────────────────────────

class AuthProvider:
    """Провайдер авторизации.

    Предоставляет методы для:
    - Управления пользователями (CRUD)
    - Аутентификации (login/logout/refresh)
    - Авторизации (RBAC, permissions)
    - JWT токенов (access + refresh)
    - Шифрования паролей (argon2id)
    """

    def __init__(
        self,
        config: AuthConfig | None = None,
        database: Any | None = None,
        log: Any | None = None,
    ) -> None:
        """Args:
            config: Конфигурация auth-модуля.
            database: Database Provider (если None — не используется).
            log: Log facade (если None — используется get_logger).
        """
        self._config = config or AuthConfig()
        self._repo: AuthRepository | None = None
        self._registry: AuthSchemaRegistry | None = None
        self._cache: PermissionsCache | None = None
        self._bootstrap: AuthBootstrap | None = None
        self._log = log

        if database is not None:
            self._repo = AuthRepository(database, log=log)
            self._registry = AuthSchemaRegistry(database, log=log)
            self._cache = PermissionsCache(ttl=self._config.perms_cache_ttl)
            self._bootstrap = AuthBootstrap(self._repo, self._registry, log=log)

    @property
    def repository(self) -> AuthRepository | None:
        return self._repo

    @property
    def registry(self) -> AuthSchemaRegistry | None:
        return self._registry

    @property
    def cache(self) -> PermissionsCache | None:
        return self._cache

    # ─────────────────────────────────────────────
    # Инициализация (вызывается из on_load)
    # ─────────────────────────────────────────────

    async def initialize(self) -> None:
        """Зарегистрировать AUTH_CORE_SCHEMA в AuthSchemaRegistry."""
        if self._registry is None:
            return
        await self._registry.register("auth", AUTH_CORE_SCHEMA, is_builtin=True)
        self._log.info("Auth schema registered")

    def initialize_sync(self) -> None:
        """Синхронная версия initialize для on_load."""
        if self._registry is None:
            return
        self._registry.register_sync("auth", AUTH_CORE_SCHEMA, is_builtin=True)
        self._log.info("Auth schema registered")

    # ─────────────────────────────────────────────
    # Пользователи (CRUD)
    # ─────────────────────────────────────────────

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        """Получить пользователя по ID."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user(user_id)

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Получить пользователя по username."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_by_username(username)

    async def create_user(
        self,
        username: str,
        password: str,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> dict[str, Any]:
        """Создать пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")

        # Проверка уникальности username
        existing = await self._repo.get_user_by_username(username)
        if existing:
            raise ValueError(f"User '{username}' already exists")

        # Валидация пароля
        self._validate_password(password)

        # Хеширование
        password_hashed = hash_password(password)

        user = await self._repo.create_user(
            username=username,
            password_hash=password_hashed,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )

        self._log.info("User created", extra={"user_id": str(user["id"]), "username": username})
        return user

    async def update_user(self, user_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        result = await self._repo.update_user(user_id, data)
        if result and self._cache:
            self._cache.invalidate(user_id)
        return result


    async def delete_user(
        self, user_id: str, force: bool = False,
    ) -> bool:
        """Удалить пользователя.

        Без force: запрет удаления последнего system_admin.
        С force: каскадное удаление.
        """
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")

        # Проверка: последний system_admin
        user = await self._repo.get_user(user_id)
        if not user:
            raise NotFoundError("User")

        # Проверяем, является ли пользователь system_admin
        is_admin = await self._repo.is_user_admin(user_id)
        if is_admin:
            admin_count = await self._repo.get_active_admin_count()
            if admin_count <= 1 and not force:
                raise ForbiddenError("Cannot delete the last system_admin (use force=True)")

        # Проверка зависимостей (без force)
        if not force:
            groups = await self._repo.get_user_groups(user_id)
            sessions_count = await self._repo.count_user_sessions(user_id)
            if groups or sessions_count > 0:
                raise ForbiddenError(
                    "User has dependencies (groups, sessions). Use force=True to cascade."
                )

        # Каскадное удаление
        await self._repo.revoke_all_user_sessions(user_id)
        await self._repo.delete_user_roles(user_id)
        await self._repo.delete_user_group_memberships(user_id)
        await self._repo.delete_user_password_history(user_id)
        result = await self._repo.delete_user(user_id)

        if self._cache:
            self._cache.invalidate(user_id)

        self._log.info("User deleted", extra={"user_id": user_id, "force": force})
        return result


    async def list_users(
        self, offset: int = 0, limit: int = 100, search: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список пользователей с пагинацией."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.list_users(offset, limit, search)

    # ─────────────────────────────────────────────
    # Состояние пользователей
    # ─────────────────────────────────────────────


    async def block_user(self, user_id: str, minutes: int | None = None) -> None:
        """Заблокировать пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        mins = minutes or self._config.login_block_minutes
        until = datetime.now(timezone.utc) + timedelta(minutes=mins)
        await self._repo.block_user(user_id, until)
        await self._repo.revoke_all_user_sessions(user_id)
        if self._cache:
            self._cache.invalidate(user_id)
        self._log.info("User blocked", extra={"user_id": user_id, "until": until.isoformat()})


    async def unblock_user(self, user_id: str) -> None:
        """Разблокировать пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.unblock_user(user_id)
        if self._cache:
            self._cache.invalidate(user_id)
        self._log.info("User unblocked", extra={"user_id": user_id})


    async def disable_user(self, user_id: str) -> None:
        """Деактивировать пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.disable_user(user_id)
        await self._repo.revoke_all_user_sessions(user_id)
        if self._cache:
            self._cache.invalidate(user_id)
        self._log.info("User disabled", extra={"user_id": user_id})


    async def enable_user(self, user_id: str) -> None:
        """Активировать пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.enable_user(user_id)
        if self._cache:
            self._cache.invalidate(user_id)
        self._log.info("User enabled", extra={"user_id": user_id})

    # ─────────────────────────────────────────────
    # Пароли
    # ─────────────────────────────────────────────


    async def set_password(self, user_id: str, password: str) -> None:
        """Установить пароль пользователю.

        Сохраняет в историю паролей и проверяет на дубликат.
        """
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")

        self._validate_password(password)
        new_hash = hash_password(password)

        # Проверка истории
        is_reused = await self._repo.check_password_history(
            user_id, new_hash, self._config.password_history_size,
        )
        if is_reused:
            raise ForbiddenError("Password was recently used")

        await self._repo.set_password_hash(user_id, new_hash)
        await self._repo.save_password_history(user_id, new_hash)
        await self._repo.prune_password_history(user_id, self._config.password_history_size)

        self._log.info("Password changed", extra={"user_id": user_id})

    # ─────────────────────────────────────────────
    # Аутентификация
    # ─────────────────────────────────────────────


    async def login(
        self,
        username: str,
        password: str,
        user_agent: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Аутентификация пользователя.

        Returns:
            {"access_token": str, "refresh_token": str, "user_id": str, "username": str}

        Raises:
            InvalidCredentialsError: Неверный логин/пароль.
            AccountLockedError: Аккаунт заблокирован.
            AccountDisabledError: Аккаунт деактивирован.
        """
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")

        user = await self._repo.get_user_by_username(username)
        if not user:
            raise InvalidCredentialsError()

        # Проверка деактивации
        if user.get("is_disabled"):
            raise AccountDisabledError()

        # Проверка блокировки
        locked_until = user.get("locked_until")
        if locked_until:
            if isinstance(locked_until, str):
                locked_until = datetime.fromisoformat(locked_until)
            if locked_until > datetime.now(timezone.utc):
                raise AccountLockedError(locked_until)
            # Блокировка истекла — разблокируем
            await self._repo.unblock_user(user["id"])

        # Проверка пароля
        ok, new_hash = verify_password(password, user["password_hash"])
        if not ok:
            attempts = await self._repo.record_login_failure(user["id"])
            if attempts >= self._config.login_attempts_limit:
                until = datetime.now(timezone.utc) + timedelta(
                    minutes=self._config.login_block_minutes,
                )
                await self._repo.block_user(user["id"], until)
                self._log.warning(
                    "Account locked due to too many attempts",
                    extra={"username": username, "attempts": attempts},
                )
            raise InvalidCredentialsError()

        # Lazy rehash
        if new_hash:
            await self._repo.set_password_hash(user["id"], new_hash)
            await self._repo.save_password_history(user["id"], new_hash)
            await self._repo.prune_password_history(
                user["id"], self._config.password_history_size,
            )

        # Успешный вход — сброс счётчика
        await self._repo.reset_login_failures(user["id"])
        await self._repo.set_last_login(user["id"])

        # Версия прав
        perms_version = await self._repo.get_permissions_version(user["id"])

        # Создание токенов
        access_token = create_access_token(
            user_id=user["id"],
            username=user["username"],
            perms_version=perms_version,
            secret=self._config.jwt_secret,
            algorithm=self._config.jwt_algorithm,
            expires_in_minutes=self._config.jwt_access_expiration_minutes,
        )
        refresh_token = create_refresh_token()
        family_id = str(uuid.uuid4())

        # Сохранение сессии
        access_hash_val = hash_token(access_token)
        refresh_hash_val = hash_token(refresh_token)
        access_expires = datetime.now(timezone.utc) + timedelta(
            minutes=self._config.jwt_access_expiration_minutes,
        )
        refresh_expires = datetime.now(timezone.utc) + timedelta(
            days=self._config.jwt_refresh_expiration_days,
        )

        await self._repo.create_session(
            user_id=user["id"],
            access_hash=access_hash_val,
            access_expires_at=access_expires,
            refresh_hash=refresh_hash_val,
            refresh_expires_at=refresh_expires,
            user_agent=user_agent,
            ip_address=ip,
            family_id=family_id,
        )

        self._log.info(
            "User logged in",
            extra={"user_id": str(user["id"]), "username": username},
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user["id"],
            "username": user["username"],
        }


    async def refresh_token(
        self,
        refresh_token: str,
        user_agent: str | None = None,
        ip: str | None = None,
    ) -> dict[str, str]:
        """Обновить access token через refresh token.

        Обнаружение reuse: если last_used_at уже установлен —
        семья токенов скомпрометирована, все сессии отзываются.

        Returns:
            {"access_token": str, "refresh_token": str}

        Raises:
            ReuseDetectedError: Обнаружено повторное использование refresh token.
            AuthError: Сессия не найдена или истекла.
        """
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")

        refresh_hash_val = hash_token(refresh_token)
        session = await self._repo.get_session_by_refresh(refresh_hash_val)

        if not session:
            raise AuthError("Invalid or expired refresh token")

        # Reuse detection
        last_used = session.get("last_used_at")
        if last_used is not None:
            # Refresh token был использован повторно — компрометация
            family_id = session.get("family_id")
            if family_id:
                await self._repo.revoke_family(family_id)
            self._log.warning(
                "Refresh token reuse detected",
                extra={"session_id": str(session["id"]), "user_id": str(session["user_id"])},
            )
            raise ReuseDetectedError()

        # Проверка срока действия
        refresh_expires = session.get("refresh_expires_at")
        if isinstance(refresh_expires, str):
            refresh_expires = datetime.fromisoformat(refresh_expires)
        if refresh_expires and refresh_expires < datetime.now(timezone.utc):
            raise AuthError("Refresh token has expired")

        # Проверка пользователя
        user = await self._repo.get_user(session["user_id"])
        if not user or not user.get("is_active") or user.get("is_disabled"):
            raise AuthError("User account is not available")

        # Проверка блокировки
        locked_until = user.get("locked_until")
        if locked_until:
            if isinstance(locked_until, str):
                locked_until = datetime.fromisoformat(locked_until)
            if locked_until and locked_until > datetime.now(timezone.utc):
                raise AccountLockedError(locked_until)

        # Помечаем старую сессию как использованную (НЕ отзываем —
        # иначе reuse detection не сработает: get_session_by_refresh
        # фильтрует is_revoked=FALSE и не найдёт повторно использованный токен).
        # Если токен будет использован повторно — last_used_at != None → reuse detected.
        await self._repo.update_session_last_used(session["id"])

        # Создаём новую сессию с тем же family_id
        perms_version = await self._repo.get_permissions_version(user["id"])
        new_access_token = create_access_token(
            user_id=user["id"],
            username=user["username"],
            perms_version=perms_version,
            secret=self._config.jwt_secret,
            algorithm=self._config.jwt_algorithm,
            expires_in_minutes=self._config.jwt_access_expiration_minutes,
        )
        new_refresh_token = create_refresh_token()

        new_access_hash = hash_token(new_access_token)
        new_refresh_hash = hash_token(new_refresh_token)
        access_expires = datetime.now(timezone.utc) + timedelta(
            minutes=self._config.jwt_access_expiration_minutes,
        )
        refresh_expires_at = datetime.now(timezone.utc) + timedelta(
            days=self._config.jwt_refresh_expiration_days,
        )

        await self._repo.create_session(
            user_id=user["id"],
            access_hash=new_access_hash,
            access_expires_at=access_expires,
            refresh_hash=new_refresh_hash,
            refresh_expires_at=refresh_expires_at,
            user_agent=user_agent,
            ip_address=ip,
            family_id=session.get("family_id"),
        )

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
        }


    async def logout(self, refresh_token: str) -> bool:
        """Выход пользователя — отзыв сессии по refresh token."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")

        refresh_hash_val = hash_token(refresh_token)
        session = await self._repo.get_session_by_refresh(refresh_hash_val)
        if not session:
            return False

        await self._repo.revoke_session(session["id"])
        self._log.info("User logged out", extra={"user_id": str(session["user_id"])})
        return True

    # ─────────────────────────────────────────────
    # Авторизация
    # ─────────────────────────────────────────────


    async def validate_token(self, access_token: str) -> UserContext | None:
        """Валидировать access token и вернуть контекст пользователя.

        Returns:
            UserContext или None если невалиден.
        """
        if self._repo is None:
            return None

        try:
            payload = validate_access_token(
                access_token,
                self._config.jwt_secret,
                self._config.jwt_algorithm,
            )
        except (TokenExpiredError, TokenInvalidError):
            return None

        user_id = payload.get("sub")
        if not user_id:
            return None

        # Проверяем сессию в БД
        access_hash_val = hash_token(access_token)
        session = await self._repo.get_session_by_access(access_hash_val)
        if not session:
            return None

        # Проверяем пользователя
        user = await self._repo.get_user(user_id)
        if not user or not user.get("is_active") or user.get("is_disabled"):
            return None

        locked_until = user.get("locked_until")
        if locked_until:
            if isinstance(locked_until, str):
                locked_until = datetime.fromisoformat(locked_until)
            if locked_until and locked_until > datetime.now(timezone.utc):
                return None

        # Обновляем last_used_at
        await self._repo.update_session_last_used(session["id"])

        return UserContext(
            user_id=user_id,
            username=user["username"],
            perms_version=payload.get("perms_version", 0),
        )


    async def check_permission(self, user_id: str, permission: str) -> bool:
        """Проверить разрешение пользователя.

        Поддержка wildcard: *:* и resource:*
        """
        if self._repo is None or self._cache is None:
            return False

        # Проверяем пользователя
        user = await self._repo.get_user(user_id)
        if not user or not user.get("is_active") or user.get("is_disabled"):
            return False

        # Кеш
        current_version = await self._repo.get_permissions_version(user_id)
        cached = self._cache.get(user_id)
        if cached is not None:
            cached_version, cached_perms = cached
            if cached_version == current_version:
                return self._check_permission_set(cached_perms, permission)

        # Загружаем из БД
        perms = await self._repo.get_user_effective_permissions(user_id)
        self._cache.set(user_id, current_version, perms)

        return self._check_permission_set(perms, permission)

    def _check_permission_set(self, perms: frozenset[str], permission: str) -> bool:
        """Проверить permission в наборе с поддержкой wildcard."""
        # Точное совпадение
        if permission in perms:
            return True

        # Wildcard *:* — полный доступ
        if "*:*" in perms:
            return True

        # Wildcard resource:*
        if ":" in permission:
            resource, _ = permission.split(":", 1)
            wildcard = f"{resource}:*"
            if wildcard in perms:
                return True

        return False

    # ─────────────────────────────────────────────
    # Группы
    # ─────────────────────────────────────────────


    async def create_group(
        self, name: str, description: str | None = None,
    ) -> dict[str, Any]:
        """Создать группу."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.create_group(name, description)


    async def update_group(self, group_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить группу."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.update_group(group_id, data)


    async def delete_group(self, group_id: str, force: bool = False) -> bool:
        """Удалить группу.

        Без force: ошибка если есть зависимости.
        С force: каскадное удаление.
        """
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")

        if not force:
            deps = await self._repo.count_group_dependencies(group_id)
            total = sum(deps.values())
            if total > 0:
                raise ForbiddenError(
                    f"Group has dependencies: {deps}. Use force=True to cascade."
                )

        # Каскадное удаление
        await self._repo.delete_group_memberships(group_id)
        await self._repo.delete_group_hierarchy(group_id)
        await self._repo.delete_group_role_assignments(group_id)
        return await self._repo.delete_group(group_id)


    async def list_groups(
        self, offset: int = 0, limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список групп с пагинацией."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.list_groups(offset, limit)


    async def add_user_to_group(self, user_id: str, group_id: str, added_by: str | None = None) -> None:
        """Добавить пользователя в группу."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.add_user_to_group(user_id, group_id, added_by)


    async def remove_user_from_group(self, user_id: str, group_id: str) -> None:
        """Удалить пользователя из группы."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.remove_user_from_group(user_id, group_id)


    async def get_user_groups(self, user_id: str) -> list[dict[str, Any]]:
        """Получить группы пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_groups(user_id)


    async def add_group_to_group(self, parent_id: str, child_id: str) -> None:
        """Добавить дочернюю группу к родительской."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.add_group_to_group(parent_id, child_id)


    async def remove_group_from_group(self, parent_id: str, child_id: str) -> None:
        """Удалить дочернюю группу."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.remove_group_from_group(parent_id, child_id)

    # ─────────────────────────────────────────────
    # Роли
    # ─────────────────────────────────────────────


    async def create_role(
        self, name: str, description: str | None = None, is_builtin: bool = False,
    ) -> dict[str, Any]:
        """Создать роль."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.create_role(name, description, is_builtin)

    async def update_role(self, role_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить роль."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.update_role(role_id, data)

    async def delete_role(self, role_id: str, force: bool = False) -> bool:
        """Удалить роль.

        Без force: ошибка если есть назначения.
        С force: каскадное удаление.
        """
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")

        if not force:
            deps = await self._repo.count_role_assignments(role_id)
            total = sum(deps.values())
            if total > 0:
                raise ForbiddenError(
                    f"Role has assignments: {deps}. Use force=True to cascade."
                )

        # Каскадное удаление
        await self._repo.delete_role_user_assignments(role_id)
        await self._repo.delete_role_group_assignments(role_id)
        await self._repo.delete_role_permissions(role_id)
        result = await self._repo.delete_role(role_id)
        if self._cache:
            self._cache.invalidate_all()
        return result

    async def list_roles(
        self, offset: int = 0, limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список ролей с пагинацией."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.list_roles(offset, limit)

    async def assign_role_to_user(
        self, user_id: str, role_id: str, granted_by: str | None = None,
    ) -> None:
        """Назначить роль пользователю."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.assign_role_to_user(user_id, role_id, granted_by)
        if self._cache:
            self._cache.invalidate(user_id)

    async def remove_role_from_user(self, user_id: str, role_id: str) -> None:
        """Убрать роль у пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.remove_role_from_user(user_id, role_id)
        if self._cache:
            self._cache.invalidate(user_id)

    async def get_user_roles(self, user_id: str) -> list[dict[str, Any]]:
        """Получить прямые роли пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_roles(user_id)

    async def assign_role_to_group(self, group_id: str, role_id: str) -> None:
        """Назначить роль группе."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.assign_role_to_group(group_id, role_id)
        if self._cache:
            self._cache.invalidate_all()

    async def remove_role_from_group(self, group_id: str, role_id: str) -> None:
        """Убрать роль у группы."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.remove_role_from_group(group_id, role_id)
        if self._cache:
            self._cache.invalidate_all()

    async def get_group_roles(self, group_id: str) -> list[dict[str, Any]]:
        """Получить роли группы."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_group_roles(group_id)

    async def inspect_role(self, role_id: str) -> dict[str, Any] | None:
        """Получить роль с её permissions."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        role = await self._repo.get_role(role_id)
        if not role:
            return None
        role["permissions"] = await self._repo.get_role_permissions(role_id)
        return role

    # ─────────────────────────────────────────────
    # Эффективные права
    # ─────────────────────────────────────────────

    async def get_user_effective_roles(self, user_id: str) -> list[dict[str, Any]]:
        """Получить все эффективные роли (прямые + через группы)."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_effective_roles(user_id)

    async def get_user_effective_permissions(self, user_id: str) -> frozenset[str]:
        """Получить все эффективные permissions."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_effective_permissions(user_id)

    # ─────────────────────────────────────────────
    # Bootstrap
    # ─────────────────────────────────────────────

    @auth_method(
        name="needs_bootstrap",
        description="Проверить, нужен ли bootstrap (нет system_admin)",
        args={},
        return_type="bool",
        public=True,
    )
    async def needs_bootstrap(self) -> bool:
        """Проверить, нужен ли bootstrap."""
        if self._bootstrap is None:
            return False
        return await self._bootstrap.needs_bootstrap()

    @auth_method(
        name="bootstrap",
        description="Создать первого системного администратора",
        args={"username": "str", "password": "str", "email": "str"},
        return_type="dict",
        public=True,
    )
    async def bootstrap(
        self, username: str, password: str, email: str | None = None,
    ) -> dict[str, Any]:
        """Создать первого системного администратора."""
        if self._bootstrap is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._bootstrap.bootstrap(username, password, email)

    # ─────────────────────────────────────────────
    # Приватные методы
    # ─────────────────────────────────────────────

    def _validate_password(self, password: str) -> None:
        """Валидация пароля по политике."""
        if len(password) < self._config.password_min_length:
            raise ValueError(
                f"Password must be at least {self._config.password_min_length} characters"
            )
        if self._config.password_require_uppercase and not any(
            c.isupper() for c in password
        ):
            raise ValueError("Password must contain at least one uppercase letter")
        if self._config.password_require_digit and not any(
            c.isdigit() for c in password
        ):
            raise ValueError("Password must contain at least one digit")
