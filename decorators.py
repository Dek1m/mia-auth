"""Auth Decorators — @auth_method для метаданных API методов.

@auth_method сохраняет метаданные на функции (_auth_method_meta dict).
Реестр API Proxy заберёт их на Фазе 2.
НЕ реализует проверку прав — только метаданные.
"""
from __future__ import annotations

import functools
from typing import Any, Callable

__all__ = ["auth_method"]


def auth_method(
    fn: Callable | None = None,
    *,
    name: str | None = None,
    description: str = "",
    args: dict[str, str] | None = None,
    return_type: str | None = None,
    public: bool = False,
    required_permission: str | None = None,
) -> Callable:
    """Декоратор для регистрации API метода с метаданными.

    Args:
        name: Имя метода в API (по умолчанию имя функции).
        description: Описание метода.
        args: Словарь {имя_аргумента: "тип"} для документации.
        return_type: Тип возврата (строка).
        public: True если метод доступен без авторизации.
        required_permission: Минимальное разрешение для доступа.

    Returns:
        Декорированная функция с атрибутом _auth_method_meta.
    """

    def decorator(func: Callable) -> Callable:
        meta = {
            "name": name or func.__name__,
            "description": description,
            "args": args or {},
            "return_type": return_type,
            "public": public,
            "required_permission": required_permission,
        }
        func._auth_method_meta = meta  # type: ignore[attr-defined]

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        wrapper._auth_method_meta = meta  # type: ignore[attr-defined]
        return wrapper

    if fn is not None:
        return decorator(fn)
    return decorator
