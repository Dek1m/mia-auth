"""Auth Core Schema — базовые permissions и роли модуля auth.

Описания на русском. Каждая permission и роль имеет description.
"""
from __future__ import annotations

from typing import Any

__all__ = ["AUTH_CORE_SCHEMA"]

AUTH_CORE_SCHEMA: dict[str, list[dict[str, Any]]] = {
    "permissions": [
        # === users ===
        {"name": "users:create", "description": "Создание пользователей"},
        {"name": "users:update", "description": "Обновление данных пользователей"},
        {"name": "users:delete", "description": "Удаление пользователей"},
        {"name": "users:list", "description": "Получение списка пользователей"},
        {"name": "users:read", "description": "Просмотр данных пользователя"},
        # === user_state ===
        {"name": "user_state:block", "description": "Блокировка пользователей"},
        {"name": "user_state:toggle", "description": "Переключение состояния активности пользователя"},
        # === passwords ===
        {"name": "passwords:manage", "description": "Управление паролями (сброс, принудительное изменение)"},
        # === groups ===
        {"name": "groups:create", "description": "Создание групп пользователей"},
        {"name": "groups:update", "description": "Обновление данных групп"},
        {"name": "groups:delete", "description": "Удаление групп"},
        {"name": "groups:list", "description": "Получение списка групп"},
        {"name": "groups:read", "description": "Просмотр данных группы"},
        {"name": "groups:manage_membership", "description": "Управление составом групп (добавление/удаление участников)"},
        # === roles ===
        {"name": "roles:create", "description": "Создание ролей"},
        {"name": "roles:update", "description": "Обновление данных ролей"},
        {"name": "roles:delete", "description": "Удаление ролей"},
        {"name": "roles:list", "description": "Получение списка ролей"},
        {"name": "roles:manage", "description": "Назначение ролей пользователям и группам"},
        {"name": "roles:inspect", "description": "Просмотр разрешений роли"},
        # === profile (свой профиль; не users:read — иначе дыра на чужие записи) ===
        {"name": "profile:self", "description": "Чтение и изменение собственного профиля"},
        # === system ===
        {"name": "system:force_delete", "description": "Принудительное удаление любых данных (только для system_admin)"},
    ],
    "roles": [
        {
            "name": "system_admin",
            "description": "Системный администратор — полный доступ ко всем ресурсам",
            "permissions": ["*:*"],
        },
        {
            "name": "user_manager",
            "description": "Менеджер пользователей — управление пользователями и их состоянием",
            "permissions": ["users:*", "user_state:*", "passwords:manage", "profile:self"],
        },
        {
            "name": "group_manager",
            "description": "Менеджер групп — управление группами и их составом",
            "permissions": ["groups:*", "groups:manage_membership", "profile:self"],
        },
        {
            "name": "role_manager",
            "description": "Менеджер ролей — управление ролями и назначение разрешений",
            "permissions": ["roles:*", "profile:self"],
        },
    ],
}
