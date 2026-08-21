"""Auth DB Schema — 12 таблиц модуля авторизации.

Формат Schema-first: dict с ключом "columns".
Колонки описаны строками SQL-типов и ограничений.
Ключ "schema" указывает PostgreSQL-схему для всех таблиц.
Ключ "auto_id": False отключает автодобавление id UUID PK.
Ключ "primary_key": [...] задаёт составной PK.
Профиль albedo (ADR-001): отдельные колонки, не custom_fields JSONB.
"""
from __future__ import annotations

from typing import Any

__all__ = ["DB_SCHEMA"]

DB_SCHEMA: dict[str, dict[str, Any]] = {
    "schema": "auth",

    # ── Пользователи ──────────────────────────────────────────
    "users": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "username": "VARCHAR(255) UNIQUE NOT NULL",
            "password_hash": "TEXT NOT NULL",
            "first_name": "VARCHAR(255)",
            "last_name": "VARCHAR(255)",
            "email": "VARCHAR(255) UNIQUE",
            "description": "TEXT",
            "is_active": "BOOLEAN DEFAULT TRUE",
            "locked_until": "TIMESTAMPTZ",
            "is_disabled": "BOOLEAN DEFAULT FALSE",
            "disabled_at": "TIMESTAMPTZ",
            "enabled_at": "TIMESTAMPTZ",
            "last_login": "TIMESTAMPTZ",
            "login_attempts": "INT DEFAULT 0",
            "custom_fields": "JSONB DEFAULT '{}'",
            "nickname": "VARCHAR(255)",
            "phone": "VARCHAR(32)",
            "user_prompt": "TEXT",
            "chip_display_mode": "VARCHAR(16) NOT NULL DEFAULT 'nickname'",
            "is_bootstrap_admin": "BOOLEAN NOT NULL DEFAULT FALSE",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Аватар (байты, не JSONB; MIME — в приложении, SVG запрещён) ─
    "user_avatars": {
        "auto_id": False,
        "columns": {
            "user_id": "UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE",
            "bytes": "BYTEA NOT NULL",
            "content_type": "VARCHAR(64) NOT NULL",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Группы ────────────────────────────────────────────────
    "groups": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "name": "VARCHAR(255) UNIQUE NOT NULL",
            "description": "TEXT",
            "is_builtin": "BOOLEAN DEFAULT FALSE",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Роли ──────────────────────────────────────────────────
    "roles": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "name": "VARCHAR(255) UNIQUE NOT NULL",
            "description": "TEXT",
            "is_builtin": "BOOLEAN DEFAULT FALSE",
            "source_module": "VARCHAR(100)",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Разрешения ────────────────────────────────────────────
    "permissions": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "name": "VARCHAR(255) UNIQUE NOT NULL",
            "description": "TEXT",
            "is_builtin": "BOOLEAN DEFAULT FALSE",
            "source_module": "VARCHAR(100)",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Связь пользователи ↔ группы ───────────────────────────
    "user_group_membership": {
        "auto_id": False,
        "primary_key": ["user_id", "group_id"],
        "columns": {
            "user_id": "UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE",
            "group_id": "UUID NOT NULL REFERENCES auth.groups(id) ON DELETE CASCADE",
            "is_primary": "BOOLEAN NOT NULL DEFAULT FALSE",
            "added_at": "TIMESTAMPTZ DEFAULT NOW()",
            "added_by": "UUID REFERENCES auth.users(id)",
        },
    },
    # ── Связь группы ↔ группы (иерархия) ──────────────────────
    "group_group_membership": {
        "auto_id": False,
        "primary_key": ["parent_group_id", "child_group_id"],
        "columns": {
            "parent_group_id": "UUID NOT NULL REFERENCES auth.groups(id) ON DELETE CASCADE",
            "child_group_id": "UUID NOT NULL REFERENCES auth.groups(id) ON DELETE CASCADE",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Связь группы ↔ роли ───────────────────────────────────
    "group_roles": {
        "auto_id": False,
        "primary_key": ["group_id", "role_id"],
        "columns": {
            "group_id": "UUID NOT NULL REFERENCES auth.groups(id) ON DELETE CASCADE",
            "role_id": "UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Связь пользователи ↔ роли (прямые) ────────────────────
    "user_roles": {
        "auto_id": False,
        "primary_key": ["user_id", "role_id"],
        "columns": {
            "user_id": "UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE",
            "role_id": "UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE",
            "granted_at": "TIMESTAMPTZ DEFAULT NOW()",
            "granted_by": "UUID REFERENCES auth.users(id)",
        },
    },
    # ── Связь роли ↔ разрешения ───────────────────────────────
    "role_permissions": {
        "auto_id": False,
        "primary_key": ["role_id", "permission_id"],
        "columns": {
            "role_id": "UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE",
            "permission_id": "UUID NOT NULL REFERENCES auth.permissions(id) ON DELETE CASCADE",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Сессии ────────────────────────────────────────────────
    "auth_sessions": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "user_id": "UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE",
            "access_token_hash": "VARCHAR(64)",
            "access_expires_at": "TIMESTAMPTZ",
            "refresh_token_hash": "VARCHAR(64)",
            "refresh_expires_at": "TIMESTAMPTZ",
            "user_agent": "TEXT",
            "ip_address": "INET",
            "is_revoked": "BOOLEAN DEFAULT FALSE",
            "revoked_at": "TIMESTAMPTZ",
            "family_id": "UUID",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "last_used_at": "TIMESTAMPTZ",
        },
    },
    # ── История паролей ───────────────────────────────────────
    "password_history": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "user_id": "UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE",
            "password_hash": "TEXT NOT NULL",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
}
