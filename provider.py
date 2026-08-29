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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


from .config import AuthConfig
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
from .validators import (
    ForbiddenAvatarError,
    decode_avatar,
    validate_profile_patch,
)
from core.task_decorator import task

AVATAR_URL = "/api/v1/auth/avatar"
_ADMINISTRATORS = "Administrators"


__all__ = ["AuthProvider", "UserContext"]


def _as_utc(value: Any) -> datetime | None:
    """Строка/naive datetime → aware UTC. Нужно для сравнения с now(timezone.utc)."""
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value if isinstance(value, datetime) else None


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


class BootstrapDoneError(AuthError):
    def __init__(self) -> None:
        super().__init__("Bootstrap already completed", "BOOTSTRAP_DONE")


@dataclass
class _RefreshGrace:
    access_token: str
    refresh_token: str
    user_id: str
    username: str
    expires_at: datetime


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
        self._refresh_grace: dict[str, _RefreshGrace] = {}
        self._refresh_lock = asyncio.Lock()

        if database is not None:
            self._repo = AuthRepository(database, log=log)
            self._registry = AuthSchemaRegistry(database, log=log)
            self._cache = PermissionsCache(ttl=self._config.perms_cache_ttl)
            self._bootstrap = AuthBootstrap(self._repo, self._registry, log=log)

    def _warn(self, message: str, **extra: Any) -> None:
        if self._log is None:
            return
        self._log.warning(message, extra=extra)

    def _info(self, message: str, extra: dict[str, Any] | None = None) -> None:
        if self._log is None:
            return
        if extra is None:
            self._log.info(message)
        else:
            self._log.info(message, extra=extra)

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

    @task(type="database")
    async def initialize(self) -> None:
        """Зарегистрировать AUTH_CORE_SCHEMA в AuthSchemaRegistry."""
        if self._registry is None:
            return
        await self._registry.register("auth", AUTH_CORE_SCHEMA, is_builtin=True)
        self._info("Auth schema registered")

    def initialize_sync(self) -> None:
        """Синхронная версия initialize для on_load."""
        if self._registry is None:
            return
        self._registry.register_sync("auth", AUTH_CORE_SCHEMA, is_builtin=True)
        if self._repo is not None:
            try:
                self._repo._database.execute(
                    "ALTER TABLE auth.users "
                    "ADD COLUMN IF NOT EXISTS ui_windows JSONB NOT NULL DEFAULT jsonb_build_object()",
                )
            except Exception as exc:
                self._warn("ui_windows_alter_failed", error=str(exc))
        self._info("Auth schema registered")

    # ─────────────────────────────────────────────
    # Пользователи (CRUD)
    # ─────────────────────────────────────────────

    @task(type="database")
    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        """Получить пользователя по ID."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user(user_id)

    @task(type="database")
    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Получить пользователя по username."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_by_username(username)

    @task(type="database")
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

        self._info("User created", extra={"user_id": str(user["id"]), "username": username})
        return user

    @task(type="database")
    async def update_user(self, user_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        result = await self._repo.update_user(user_id, data)
        if result and self._cache:
            self._cache.invalidate(user_id)
        return result


    @task(type="database")
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

        self._info("User deleted", extra={"user_id": user_id, "force": force})
        return result


    @task(type="database")
    async def list_users(
        self, offset: int = 0, limit: int = 100, search: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список пользователей с пагинацией."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.list_users(offset, limit, search)

    # ─────────────────────────────────────────────
    # Профиль (self) — ADR-001 §5.2–§5.5
    # ─────────────────────────────────────────────

    @task(
        type="database",
        api=True,
        name="get_me",
        description="Свой профиль. Любой валидный access, не users:read",
        args={},
        return_type="dict",
    )
    async def get_me(
        self,
        user_id: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        uid = self._self_id(_session_user_id, user_id, ignore_client=True)
        return await self._profile_dto(uid)

    @task(
        type="database",
        api=True,
        name="get_windows",
        description="Сохранённые размеры окон albedo",
        permission="profile:self",
        args={},
        return_type="dict",
    )
    async def get_windows(
        self,
        user_id: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        uid = self._self_id(_session_user_id, user_id, ignore_client=True)
        return {"items": await self._need_repo().get_ui_windows(uid)}

    @task(
        type="database",
        api=True,
        name="save_window",
        description="Записать геометрию окна при закрытии",
        permission="profile:self",
        args={"window_id": "str", "x": "float", "y": "float", "w": "float", "h": "float"},
        return_type="dict",
    )
    async def save_window(
        self,
        window_id: str,
        x: float,
        y: float,
        w: float,
        h: float,
        user_id: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        uid = self._self_id(_session_user_id, user_id, ignore_client=True)
        key = window_id.strip().lower()
        if not key or len(key) > 64 or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in key):
            raise ValueError("invalid window_id")
        geom = {
            "x": min(1.0, max(0.0, float(x))),
            "y": min(1.0, max(0.0, float(y))),
            "w": min(1.0, max(0.05, float(w))),
            "h": min(1.0, max(0.05, float(h))),
        }
        items = await self._need_repo().merge_ui_window(uid, key, geom)
        return {"items": items}

    @task(
        type="database",
        api=True,
        name="update_me",
        description="Обновить свой профиль",
        args={
            "nickname": "str",
            "first_name": "str",
            "last_name": "str",
            "date_of_birth": "str",
            "email": "str",
            "phone": "str",
            "user_prompt": "str",
            "chip_display_mode": "str",
        },
        return_type="dict",
    )
    async def update_me(
        self,
        nickname: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        date_of_birth: str | None = None,
        email: str | None = None,
        phone: str | None = None,
        user_prompt: str | None = None,
        chip_display_mode: str | None = None,
        user_id: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        uid = self._self_id(_session_user_id, user_id, ignore_client=True)
        raw: dict[str, Any] = {}
        for key, value in (
            ("nickname", nickname),
            ("first_name", first_name),
            ("last_name", last_name),
            ("date_of_birth", date_of_birth),
            ("email", email),
            ("phone", phone),
            ("user_prompt", user_prompt),
            ("chip_display_mode", chip_display_mode),
        ):
            if value is not None:
                raw[key] = value
        patch = validate_profile_patch(raw)
        if "email" in patch and patch["email"]:
            existing = await self._need_repo().get_user_by_email(str(patch["email"]))
            if existing and str(existing["id"]) != str(uid):
                raise ValueError("Email already in use")
        updated = await self._need_repo().update_profile(uid, patch)
        if updated is None:
            raise NotFoundError("User")
        return await self._profile_dto(uid)

    @task(
        type="database",
        api=True,
        name="change_username",
        description="Смена username с текущим паролем",
        args={"new_username": "str", "password": "str"},
        return_type="dict",
    )
    async def change_username(
        self,
        new_username: str,
        password: str,
        user_id: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        uid = self._self_id(_session_user_id, user_id, ignore_client=True)
        username = (new_username or "").strip()
        if not username or len(username) > 255:
            raise ValueError("Invalid username")
        user = await self._need_repo().get_user(uid)
        if not user:
            raise NotFoundError("User")
        ok, _ = verify_password(password, user["password_hash"])
        if not ok:
            raise InvalidCredentialsError()
        other = await self._need_repo().get_user_by_username(username)
        if other and str(other["id"]) != str(uid):
            raise ValueError(f"User '{username}' already exists")
        await self._need_repo().set_username(uid, username)
        return await self._profile_dto(uid)

    @task(
        type="cpu",
        api=True,
        name="set_avatar",
        description="Загрузить аватар (jpeg/png/webp, не SVG, ≤256 KiB)",
        args={"image_b64": "str", "content_type": "str"},
        return_type="dict",
    )
    async def set_avatar(
        self,
        image_b64: str,
        content_type: str,
        user_id: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, str]:
        uid = self._self_id(_session_user_id, user_id, ignore_client=True)
        try:
            raw = decode_avatar(image_b64, content_type)
        except ForbiddenAvatarError as exc:
            raise ForbiddenError(str(exc)) from exc
        mime = content_type.split(";")[0].strip().lower()
        await self._need_repo().upsert_avatar(uid, raw, mime)
        return {"avatar_url": AVATAR_URL}

    @task(
        type="database",
        api=True,
        name="clear_avatar",
        description="Удалить аватар",
        args={},
        return_type="dict",
    )
    async def clear_avatar(
        self,
        user_id: str | None = None,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        uid = self._self_id(_session_user_id, user_id, ignore_client=True)
        await self._need_repo().delete_avatar(uid)
        return await self._profile_dto(uid)

    @task(
        type="database",
        api=True,
        name="get_my_groups",
        description="Группы текущего пользователя",
        args={},
        return_type="list",
    )
    async def get_my_groups(
        self,
        user_id: str | None = None,
        _session_user_id: str | None = None,
    ) -> list[dict[str, Any]]:
        uid = self._self_id(_session_user_id, user_id, ignore_client=True)
        groups = await self._need_repo().get_user_groups(uid)
        return [self._group_dto(item, is_primary=bool(item.get("is_primary"))) for item in groups]

    @task(
        type="database",
        api=True,
        name="list_groups",
        description="Список групп для Add (без чужих membership)",
        args={"offset": "int", "limit": "int"},
        return_type="dict",
    )
    async def list_groups_rpc(
        self,
        offset: int = 0,
        limit: int = 100,
        _session_user_id: str | None = None,
    ) -> dict[str, Any]:
        # _session_user_id: метод не public — нужен валидный access
        items, total = await self.list_groups(offset, limit)
        return {
            "items": [self._group_dto(item, is_primary=False) for item in items],
            "total": total,
        }

    async def get_avatar_bytes(self, user_id: str) -> tuple[bytes, str] | None:
        """Для GET /api/v1/auth/avatar. Не RPC."""
        row = await self._need_repo().get_avatar(user_id)
        if not row or row.get("bytes") is None:
            return None
        return bytes(row["bytes"]), str(row.get("content_type") or "application/octet-stream")

    # ─────────────────────────────────────────────
    # Состояние пользователей
    # ─────────────────────────────────────────────


    @task(type="database")
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
        self._info("User blocked", extra={"user_id": user_id, "until": until.isoformat()})


    @task(type="database")
    async def unblock_user(self, user_id: str) -> None:
        """Разблокировать пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.unblock_user(user_id)
        if self._cache:
            self._cache.invalidate(user_id)
        self._info("User unblocked", extra={"user_id": user_id})


    @task(type="database")
    async def disable_user(self, user_id: str) -> None:
        """Деактивировать пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.disable_user(user_id)
        await self._repo.revoke_all_user_sessions(user_id)
        if self._cache:
            self._cache.invalidate(user_id)
        self._info("User disabled", extra={"user_id": user_id})


    @task(type="database")
    async def enable_user(self, user_id: str) -> None:
        """Активировать пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.enable_user(user_id)
        if self._cache:
            self._cache.invalidate(user_id)
        self._info("User enabled", extra={"user_id": user_id})

    # ─────────────────────────────────────────────
    # Пароли
    # ─────────────────────────────────────────────


    @task(type="database")
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

        self._info("Password changed", extra={"user_id": user_id})

    # ─────────────────────────────────────────────
    # Аутентификация
    # ─────────────────────────────────────────────


    @task(
        type="cpu",
        api=True,
        public=True,
        name="login",
        description="Аутентификация пользователя",
        args={"username": "str", "password": "str", "user_agent": "str", "ip": "str"},
        return_type="dict",
    )
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
            self._warn("login_failed", username=username, reason="unknown_user")
            raise InvalidCredentialsError()

        # Проверка деактивации
        if user.get("is_disabled"):
            self._warn("login_failed", username=username, reason="disabled")
            raise AccountDisabledError()

        # Проверка блокировки
        locked_until = _as_utc(user.get("locked_until"))
        if locked_until:
            if locked_until > datetime.now(timezone.utc):
                self._warn("login_failed", username=username, reason="locked")
                raise AccountLockedError(locked_until)
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
                self._warn(
                    "login_failed", username=username, reason="locked", attempts=attempts,
                )
            else:
                self._warn(
                    "login_failed", username=username, reason="bad_password", attempts=attempts,
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

        self._info(
            "User logged in",
            extra={"user_id": str(user["id"]), "username": username},
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user["id"],
            "username": user["username"],
        }


    @task(
        type="cpu",
        api=True,
        name="refresh_token",
        description="Обновить access token через refresh token",
        args={"refresh_token": "str", "user_agent": "str", "ip": "str"},
        return_type="dict",
    )
    async def refresh_token(
        self,
        refresh_token: str | None = None,
        user_agent: str | None = None,
        ip: str | None = None,
    ) -> dict[str, str]:
        """Обновить access token через refresh token.

        Пустой kwargs допустим: REST подставляет refresh из cookie.
        Grace 5–10 с: повтор того же hash → та же новая пара, не revoke.

        Returns:
            {"access_token", "refresh_token", "user_id", "username"}

        Raises:
            ReuseDetectedError: Повтор hash после grace-окна.
            AuthError: Сессия не найдена или истекла.
        """
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        if not refresh_token:
            raise AuthError("Invalid or expired refresh token")

        async with self._refresh_lock:
            return await self._rotate_refresh(refresh_token, user_agent, ip)


    @task(
        type="database",
        api=True,
        name="logout",
        description="Выход пользователя — отзыв сессии по refresh token",
        args={"refresh_token": "str"},
        return_type="bool",
    )
    async def logout(self, refresh_token: str | None = None) -> bool:
        """Выход пользователя — отзыв сессии по refresh token."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        if not refresh_token:
            return False

        refresh_hash_val = hash_token(refresh_token)
        session = await self._repo.get_session_by_refresh(refresh_hash_val)
        if not session:
            return False

        await self._repo.revoke_session(session["id"])
        self._info("User logged out", extra={"user_id": str(session["user_id"])})
        return True

    # ─────────────────────────────────────────────
    # Авторизация
    # ─────────────────────────────────────────────


    @task(type="cpu")
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

        locked_until = _as_utc(user.get("locked_until"))
        if locked_until and locked_until > datetime.now(timezone.utc):
            return None

        # last_used_at — маркер refresh-reuse, не activity access-токена
        return UserContext(
            user_id=user_id,
            username=user["username"],
            perms_version=payload.get("perms_version", 0),
        )


    @task(type="database")
    async def check_permission(self, user_id: str, permission: str) -> bool:
        """Проверить разрешение пользователя.

        Поддержка wildcard: *:* и resource:*
        """
        if self._repo is None:
            self._warn("permission_denied_no_repo", user_id=user_id, permission=permission)
            return False

        user = await self._repo.get_user(user_id)
        if not user or not user.get("is_active") or user.get("is_disabled"):
            self._warn(
                "permission_denied_user",
                user_id=user_id,
                permission=permission,
                found=bool(user),
            )
            return False
        if user.get("is_bootstrap_admin"):
            self._info(
                "permission_checked",
                extra={
                    "user_id": user_id,
                    "permission": permission,
                    "allowed": True,
                    "reason": "bootstrap_admin",
                },
            )
            return True

        current_version = await self._repo.get_permissions_version(user_id)
        cached = self._cache.get(user_id) if self._cache is not None else None
        if cached is not None:
            cached_version, cached_perms = cached
            if cached_version == current_version:
                allowed = self._check_permission_set(cached_perms, permission)
                self._info(
                    "permission_checked",
                    extra={
                        "user_id": user_id,
                        "permission": permission,
                        "allowed": allowed,
                        "cached": True,
                        "perm_count": len(cached_perms),
                    },
                )
                return allowed

        perms = await self._repo.get_user_effective_permissions(user_id)
        if self._cache is not None:
            self._cache.set(user_id, current_version, perms)
        allowed = self._check_permission_set(perms, permission)
        payload = {
            "user_id": user_id,
            "permission": permission,
            "allowed": allowed,
            "cached": False,
            "perm_count": len(perms),
            "has_wildcard": "*:*" in perms,
        }
        if allowed:
            self._info("permission_checked", extra=payload)
        else:
            self._warn("permission_checked", **payload)
        return allowed

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


    @task(type="database")
    async def create_group(
        self, name: str, description: str | None = None,
    ) -> dict[str, Any]:
        """Создать группу."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.create_group(name, description)


    @task(type="database")
    async def update_group(self, group_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить группу."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.update_group(group_id, data)


    @task(type="database")
    async def delete_group(self, group_id: str, force: bool = False) -> bool:
        """Удалить группу.

        Без force: ошибка если есть зависимости.
        С force: каскадное удаление.
        Builtin (Administrators) — всегда Forbidden.
        """
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")

        group = await self._repo.get_group(group_id)
        if group and group.get("is_builtin"):
            raise ForbiddenError("Cannot delete builtin group")

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


    @task(type="database")
    async def list_groups(
        self, offset: int = 0, limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список групп с пагинацией."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.list_groups(offset, limit)


    @task(
        type="database",
        api=True,
        name="add_user_to_group",
        description="Добавить в группу. Чужой user_id — только groups:manage_membership",
        args={"user_id": "str", "group_id": "str"},
        return_type="bool",
    )
    async def add_user_to_group(
        self,
        user_id: str | None = None,
        group_id: str | None = None,
        added_by: str | None = None,
        _session_user_id: str | None = None,
    ) -> bool:
        """Добавить пользователя в группу."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        if not group_id:
            raise ValueError("group_id is required")
        if _session_user_id:
            allowed = await self.check_permission(str(_session_user_id), "groups:manage_membership")
            if not allowed:
                raise ForbiddenError("Only an administrator can change group membership")
            group = await self._repo.get_group(group_id)
            if group and group.get("name") == "Everyone":
                raise ForbiddenError("Everyone already includes all users")
        target = await self._membership_target(user_id, _session_user_id)
        await self._repo.add_user_to_group(target, group_id, added_by or _session_user_id)
        return True

    @task(
        type="database",
        api=True,
        name="remove_user_from_group",
        description="Убрать из группы. Primary и bootstrap Administrators — Forbidden",
        args={"user_id": "str", "group_id": "str"},
        return_type="bool",
    )
    async def remove_user_from_group(
        self,
        user_id: str | None = None,
        group_id: str | None = None,
        _session_user_id: str | None = None,
    ) -> bool:
        """Удалить пользователя из группы. Сервер — истина AD-инвариантов."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        if not group_id:
            raise ValueError("group_id is required")
        if _session_user_id:
            allowed = await self.check_permission(str(_session_user_id), "groups:manage_membership")
            if not allowed:
                raise ForbiddenError("Only an administrator can change group membership")
            group = await self._repo.get_group(group_id)
            if group and group.get("name") == "Everyone":
                raise ForbiddenError("Everyone already includes all users")
        target = await self._membership_target(user_id, _session_user_id)
        membership = await self._repo.get_membership(target, group_id)
        if membership is None:
            raise NotFoundError("Membership")
        if membership.get("is_primary"):
            raise ForbiddenError("Cannot remove primary group")
        group = await self._repo.get_group(group_id)
        user = await self._repo.get_user(target)
        if (
            group
            and group.get("name") == _ADMINISTRATORS
            and user
            and user.get("is_bootstrap_admin")
        ):
            raise ForbiddenError("Cannot remove Administrators from bootstrap admin")
        await self._repo.remove_user_from_group(target, group_id)
        return True


    @task(type="database")
    async def get_user_groups(self, user_id: str) -> list[dict[str, Any]]:
        """Получить группы пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_groups(user_id)


    @task(type="database")
    async def add_group_to_group(self, parent_id: str, child_id: str) -> None:
        """Добавить дочернюю группу к родительской."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.add_group_to_group(parent_id, child_id)


    @task(type="database")
    async def remove_group_from_group(self, parent_id: str, child_id: str) -> None:
        """Удалить дочернюю группу."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.remove_group_from_group(parent_id, child_id)

    # ─────────────────────────────────────────────
    # Роли
    # ─────────────────────────────────────────────


    @task(type="database")
    async def create_role(
        self, name: str, description: str | None = None, is_builtin: bool = False,
    ) -> dict[str, Any]:
        """Создать роль."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.create_role(name, description, is_builtin)

    @task(type="database")
    async def update_role(self, role_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить роль."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.update_role(role_id, data)

    @task(type="database")
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

    @task(type="database")
    async def list_roles(
        self, offset: int = 0, limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список ролей с пагинацией."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.list_roles(offset, limit)

    @task(type="database")
    async def assign_role_to_user(
        self, user_id: str, role_id: str, granted_by: str | None = None,
    ) -> None:
        """Назначить роль пользователю."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.assign_role_to_user(user_id, role_id, granted_by)
        if self._cache:
            self._cache.invalidate(user_id)

    @task(type="database")
    async def remove_role_from_user(self, user_id: str, role_id: str) -> None:
        """Убрать роль у пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.remove_role_from_user(user_id, role_id)
        if self._cache:
            self._cache.invalidate(user_id)

    @task(type="database")
    async def get_user_roles(self, user_id: str) -> list[dict[str, Any]]:
        """Получить прямые роли пользователя."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_roles(user_id)

    @task(type="database")
    async def assign_role_to_group(self, group_id: str, role_id: str) -> None:
        """Назначить роль группе."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.assign_role_to_group(group_id, role_id)
        if self._cache:
            self._cache.invalidate_all()

    @task(type="database")
    async def remove_role_from_group(self, group_id: str, role_id: str) -> None:
        """Убрать роль у группы."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        await self._repo.remove_role_from_group(group_id, role_id)
        if self._cache:
            self._cache.invalidate_all()

    @task(type="database")
    async def get_group_roles(self, group_id: str) -> list[dict[str, Any]]:
        """Получить роли группы."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_group_roles(group_id)

    @task(type="database")
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

    @task(type="database")
    async def get_user_effective_roles(self, user_id: str) -> list[dict[str, Any]]:
        """Получить все эффективные роли (прямые + через группы)."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_effective_roles(user_id)

    @task(type="database")
    async def get_user_effective_permissions(self, user_id: str) -> frozenset[str]:
        """Получить все эффективные permissions."""
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return await self._repo.get_user_effective_permissions(user_id)

    # ─────────────────────────────────────────────
    # Bootstrap
    # ─────────────────────────────────────────────

    @task(
        type="database",
        api=True,
        public=True,
        name="needs_bootstrap",
        description="Проверить, нужен ли bootstrap (нет system_admin)",
        args={},
        return_type="bool",
    )
    async def needs_bootstrap(self) -> bool:
        """Проверить, нужен ли bootstrap."""
        if self._bootstrap is None:
            return False
        return await self._bootstrap.needs_bootstrap()

    @task(
        type="database",
        api=True,
        public=True,
        name="bootstrap",
        description="Создать первого системного администратора",
        args={"username": "str", "password": "str", "email": "str"},
        return_type="dict",
    )
    async def bootstrap(
        self, username: str, password: str, email: str | None = None,
    ) -> dict[str, Any]:
        """Создать первого системного администратора."""
        if self._bootstrap is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        try:
            return await self._bootstrap.bootstrap(username, password, email)
        except ValueError as exc:
            if "already completed" in str(exc).lower():
                raise BootstrapDoneError() from exc
            raise

    # ─────────────────────────────────────────────
    # Приватные методы
    # ─────────────────────────────────────────────

    async def _rotate_refresh(
        self,
        refresh_token: str,
        user_agent: str | None,
        ip: str | None,
    ) -> dict[str, str]:
        assert self._repo is not None
        now = datetime.now(timezone.utc)
        grace = max(0, int(self._config.refresh_grace_seconds))
        refresh_hash_val = hash_token(refresh_token)
        cached = self._refresh_grace.get(refresh_hash_val)
        if cached is not None and cached.expires_at >= now:
            return {
                "access_token": cached.access_token,
                "refresh_token": cached.refresh_token,
                "user_id": cached.user_id,
                "username": cached.username,
            }

        session = await self._repo.get_session_by_refresh(refresh_hash_val)
        if not session:
            raise AuthError("Invalid or expired refresh token")

        last_used = _as_utc(session.get("last_used_at"))
        if last_used is not None:
            elapsed = (now - last_used).total_seconds()
            if grace > 0 and elapsed < grace:
                # Окно есть, пары в кеше нет — не режем family
                raise AuthError("Invalid or expired refresh token")
            family_id = session.get("family_id")
            if family_id:
                await self._repo.revoke_family(family_id)
            self._warn(
                "Refresh token reuse detected",
                session_id=str(session["id"]),
                user_id=str(session["user_id"]),
            )
            raise ReuseDetectedError()

        refresh_expires = _as_utc(session.get("refresh_expires_at"))
        if refresh_expires and refresh_expires < now:
            raise AuthError("Refresh token has expired")

        user = await self._repo.get_user(session["user_id"])
        if not user or not user.get("is_active") or user.get("is_disabled"):
            raise AuthError("User account is not available")

        locked_until = _as_utc(user.get("locked_until"))
        if locked_until and locked_until > now:
            raise AccountLockedError(locked_until)

        # last_used, не revoke: иначе повторный hash не найдёт сессию
        await self._repo.update_session_last_used(session["id"])

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
        access_expires = now + timedelta(minutes=self._config.jwt_access_expiration_minutes)
        refresh_expires_at = now + timedelta(days=self._config.jwt_refresh_expiration_days)
        await self._repo.create_session(
            user_id=user["id"],
            access_hash=hash_token(new_access_token),
            access_expires_at=access_expires,
            refresh_hash=hash_token(new_refresh_token),
            refresh_expires_at=refresh_expires_at,
            user_agent=user_agent,
            ip_address=ip,
            family_id=session.get("family_id"),
        )
        if grace > 0:
            self._refresh_grace[refresh_hash_val] = _RefreshGrace(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                user_id=str(user["id"]),
                username=str(user["username"]),
                expires_at=now + timedelta(seconds=grace),
            )
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "user_id": str(user["id"]),
            "username": str(user["username"]),
        }

    def _need_repo(self) -> AuthRepository:
        if self._repo is None:
            raise AuthError("Auth not initialized (no Database Provider)")
        return self._repo

    def _self_id(
        self,
        session_user_id: str | None,
        client_user_id: str | None,
        *,
        ignore_client: bool,
    ) -> str:
        if ignore_client:
            uid = session_user_id or client_user_id
        else:
            uid = client_user_id or session_user_id
        if not uid:
            raise AuthError("Authentication required")
        return str(uid)

    async def _membership_target(
        self, client_user_id: str | None, session_user_id: str | None,
    ) -> str:
        actor = session_user_id
        if not actor:
            if not client_user_id:
                raise AuthError("Authentication required")
            return str(client_user_id)
        if client_user_id and str(client_user_id) != str(actor):
            allowed = await self.check_permission(actor, "groups:manage_membership")
            if not allowed:
                raise ForbiddenError("Cannot manage another user's membership")
            return str(client_user_id)
        return str(actor)

    async def _profile_dto(self, user_id: str) -> dict[str, Any]:
        repo = self._need_repo()
        row = await repo.get_profile(user_id)
        if row is None:
            raise NotFoundError("User")
        bootstrap = bool(row.get("is_bootstrap_admin"))
        mode = row.get("chip_display_mode") or "nickname"
        if mode not in {"nickname", "full_name"}:
            mode = "nickname"
        has_file = await repo.has_avatar(user_id)
        primary = await repo.get_primary_group_id(user_id)
        return {
            "user_id": str(row["id"]),
            "username": row["username"],
            "nickname": row.get("nickname"),
            "first_name": row.get("first_name"),
            "last_name": row.get("last_name"),
            "date_of_birth": row.get("date_of_birth").isoformat() if row.get("date_of_birth") else None,
            "email": row.get("email"),
            "phone": row.get("phone"),
            "avatar_url": AVATAR_URL if has_file else None,
            "user_prompt": row.get("user_prompt"),
            "chip_display_mode": mode,
            "is_superadmin": bootstrap,
            "is_bootstrap_admin": bootstrap,
            "primary_group_id": primary,
        }

    def _group_dto(self, row: dict[str, Any], *, is_primary: bool) -> dict[str, Any]:
        return {
            "id": str(row.get("id") or row.get("group_id")),
            "name": row.get("name"),
            "description": row.get("description"),
            "is_builtin": bool(row.get("is_builtin")),
            "is_primary": is_primary,
        }

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
