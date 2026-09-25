#!/usr/bin/env python3
"""Interactively create the main admin password hash and Flask session key.

Usage (from quick_access_center/): python access_control/setup_access.py
The real access.env is deliberately excluded from Git.
"""

from __future__ import annotations

import getpass
import os
import secrets
import tempfile
from pathlib import Path

from werkzeug.security import generate_password_hash

ENV_PATH = Path(__file__).resolve().parent / "access.env"
EXAMPLE_PATH = ENV_PATH.with_suffix(".env.example")


def update_value(lines: list[str], key: str, value: str) -> list[str]:
    prefix = key + "="
    result = [prefix + value if line.startswith(prefix) else line for line in lines]
    if not any(line.startswith(prefix) for line in lines):
        result.append(prefix + value)
    return result


def main() -> None:
    if ENV_PATH.exists():
        reply = input("access.env уже существует. Обновить логин/пароль? [y/N]: ").strip().lower()
        if reply not in {"y", "yes", "д", "да"}:
            print("Без изменений.")
            return
        lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    else:
        lines = EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()

    username = input("Логин основного администратора [admin]: ").strip() or "admin"
    while True:
        password = getpass.getpass("Новый пароль (не менее 12 символов): ")
        repeated = getpass.getpass("Повторите пароль: ")
        if len(password) < 12:
            print("Пароль слишком короткий.")
        elif password != repeated:
            print("Пароли не совпадают.")
        else:
            break

    lines = [line for line in lines if not line.startswith("MAIN_ACCESS_PASSWORD=")]
    values = dict(line.split("=", 1) for line in lines if "=" in line and not line.lstrip().startswith("#"))
    lines = update_value(lines, "MAIN_ACCESS_ENABLED", "1")
    lines = update_value(lines, "MAIN_ACCESS_USERNAME", username)
    lines = update_value(lines, "MAIN_ACCESS_PASSWORD_HASH", generate_password_hash(password))
    if not values.get("MAIN_ACCESS_SECRET_KEY", "").strip():
        lines = update_value(lines, "MAIN_ACCESS_SECRET_KEY", secrets.token_urlsafe(48))

    # An atomic replace keeps the previous configuration if writing fails.
    ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=ENV_PATH.parent,
            prefix=".access.", delete=False,
        ) as temp_file:
            temp_name = temp_file.name
            temp_file.write("\n".join(lines).rstrip() + "\n")
        os.replace(temp_name, ENV_PATH)
        try:
            ENV_PATH.chmod(0o600)
        except OSError:
            print("Не удалось установить права 0600; проверьте права доступа к access.env вручную.")
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)

    print("Готово: access_control/access.env. Значения секретов не показаны.")
    print("Разрешённые IP задаются в MAIN_ACCESS_ALLOWED_IPS; по умолчанию только localhost.")


if __name__ == "__main__":
    main()
