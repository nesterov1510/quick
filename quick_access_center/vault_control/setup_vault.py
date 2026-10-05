#!/usr/bin/env python3
"""Interactively create the separate Vault login and Fernet encryption key."""

from __future__ import annotations

import getpass
import os
import sqlite3
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

ENV_PATH = Path(__file__).resolve().parent / "vault.env"
EXAMPLE_PATH = ENV_PATH.with_suffix(".env.example")


def update_value(lines: list[str], key: str, value: str) -> list[str]:
    prefix = key + "="
    result = [prefix + value if line.startswith(prefix) else line for line in lines]
    if not any(line.startswith(prefix) for line in lines):
        result.append(prefix + value)
    return result


def existing_credential_count() -> int:
    """Prevent accidental creation of a new key for an existing database."""
    root = Path(os.environ.get("MSB_QUICK_ACCESS_DATA_DIR") or
                ENV_PATH.parent.parent / "save_blocks" / "save_base").expanduser().resolve()
    db_file = root / "base" / "quick_access.db"
    if not db_file.exists():
        return 0
    try:
        with sqlite3.connect(db_file.as_uri() + "?mode=ro", uri=True) as conn:
            return conn.execute("SELECT COUNT(*) FROM app_credentials").fetchone()[0]
    except sqlite3.OperationalError as error:
        if "no such table" in str(error):
            return 0
        raise RuntimeError("Не удалось проверить базу данных Vault") from error
    except sqlite3.DatabaseError as error:
        raise RuntimeError("Не удалось проверить базу данных Vault") from error


def main() -> None:
    print("MSB Vault — настройка отдельного администратора")
    if ENV_PATH.exists():
        reply = input("vault.env уже существует. Обновить логин/пароль? [y/N]: ").strip().lower()
        if reply not in {"y", "yes", "д", "да"}:
            print("Без изменений.")
            return
        lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    else:
        lines = EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()

    values = dict(line.split("=", 1) for line in lines if "=" in line and not line.lstrip().startswith("#"))
    encryption_key = values.get("VAULT_ENCRYPTION_KEY", "").strip()
    if encryption_key:
        try:
            Fernet(encryption_key.encode("utf-8"))
        except (ValueError, TypeError) as error:
            raise RuntimeError("VAULT_ENCRYPTION_KEY имеет неверный формат; восстановите его из бэкапа") from error
    elif existing_credential_count():
        raise RuntimeError("В БД есть пароли, но VAULT_ENCRYPTION_KEY отсутствует. "
                           "Восстановите vault.env из бэкапа, не создавайте новый ключ.")
    else:
        encryption_key = Fernet.generate_key().decode("utf-8")

    username = input("Отдельный логин [vault-admin]: ").strip() or "vault-admin"
    while True:
        password = getpass.getpass("Новый отдельный пароль (не менее 12 символов): ")
        repeated = getpass.getpass("Повторите пароль: ")
        if len(password) < 12:
            print("Пароль слишком короткий.")
        elif password != repeated:
            print("Пароли не совпадают.")
        else:
            break

    # Add new ticket-login defaults to older vault.env files without changing
    # any administrator-supplied allowlist or HTTP opt-in.
    if "VAULT_QUICK_ACCESS_SITES" not in values:
        lines = update_value(lines, "VAULT_QUICK_ACCESS_SITES", "")
    if "VAULT_QUICK_ACCESS_ALLOW_PRIVATE_HTTP" not in values:
        lines = update_value(lines, "VAULT_QUICK_ACCESS_ALLOW_PRIVATE_HTTP", "0")

    lines = update_value(lines, "VAULT_ACCESS_ENABLED", "1")
    lines = update_value(lines, "VAULT_ACCESS_USERNAME", username)
    lines = update_value(lines, "VAULT_ACCESS_PASSWORD_HASH", generate_password_hash(password))
    lines = update_value(lines, "VAULT_ENCRYPTION_KEY", encryption_key)

    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=ENV_PATH.parent,
            prefix=".vault.", delete=False,
        ) as temp_file:
            temp_name = temp_file.name
            temp_file.write("\n".join(lines).rstrip() + "\n")
        os.replace(temp_name, ENV_PATH)
        try:
            ENV_PATH.chmod(0o600)
        except OSError:
            print("Не удалось установить права 0600; проверьте права доступа к vault.env вручную.")
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)

    print("Готово: vault_control/vault.env.")
    print("Сохраните файл vault.env в защищённом бэкапе. Без ключа пароли не расшифруются.")


if __name__ == "__main__":
    main()
