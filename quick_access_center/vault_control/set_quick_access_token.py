#!/usr/bin/env python3
"""Provision/rotate a target-service PAT without ever sending it to a browser."""
from __future__ import annotations

import getpass
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _valid_token(value: str) -> bool:
    return bool(value) and len(value) <= 8192 and all(33 <= ord(char) <= 126 for char in value)


def provision_token(db_factory, app_id: int, credential_id: int, app_url: str, token: str) -> str:
    """Encrypt and bind a PAT to one allowlisted card/record, leaving it disabled."""
    from vault_control.autologin import (
        is_quick_access_supported_url,
        normalize_login_url,
        quick_access_private_http_allowed,
    )
    from vault_control.vault_settings import encrypt_secret

    if not _valid_token(token):
        raise ValueError("Некорректный формат сервисного токена")
    canonical_target = normalize_login_url(
        app_url,
        allow_private_http=quick_access_private_http_allowed(),
    )
    if not canonical_target or not is_quick_access_supported_url(app_url):
        raise ValueError("URL карточки не разрешён конфигурацией Quick Access")

    conn = db_factory()
    try:
        conn.execute("BEGIN IMMEDIATE")
        selected = conn.execute(
            """SELECT a.url FROM app_credentials AS c
               JOIN apps AS a ON a.id = c.app_id
               WHERE c.id = ? AND c.app_id = ?""",
            (int(credential_id), int(app_id)),
        ).fetchone()
        actual_target = normalize_login_url(
            selected["url"] if selected else "",
            allow_private_http=quick_access_private_http_allowed(),
        )
        if (
            not selected
            or actual_target != canonical_target
            or not is_quick_access_supported_url(selected["url"])
        ):
            raise ValueError("URL записи изменился или не разрешён")
        token_enc = encrypt_secret(token)
        conn.execute(
            "UPDATE app_credentials SET quick_access_enabled = 0 WHERE app_id = ?",
            (int(app_id),),
        )
        cursor = conn.execute(
            """UPDATE app_credentials
               SET quick_access_token_enc = ?, quick_access_target = ?,
                   quick_access_enabled = 0, updated_at = ?
               WHERE id = ? AND app_id = ?""",
            (
                token_enc,
                canonical_target,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                int(credential_id),
                int(app_id),
            ),
        )
        if cursor.rowcount != 1:
            raise ValueError("Запись Vault не найдена для указанной карточки")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return canonical_target


def main() -> int:
    if len(sys.argv) != 1:
        print("Команда не принимает аргументы; секрет вводится только скрытым prompt.", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print(
            "Запускайте команду из интерактивного терминала; токен не передаётся "
            "через аргументы или stdin.",
            file=sys.stderr,
        )
        return 2

    try:
        # Importing the existing app uses its configured data directory, Vault
        # Fernet key and automatic DB migrations; it does not start the server.
        import app
        from vault_control.autologin import (
            is_quick_access_supported_url,
            normalize_login_url,
            quick_access_private_http_allowed,
        )
        from vault_control.vault_settings import (
            decrypt_secret,
            get_vault_config,
            is_vault_configured,
        )
    except Exception:
        print("Не удалось загрузить Quick Access/Vault. Проверьте окружение и vault.env.", file=sys.stderr)
        return 2

    vault_config = get_vault_config()
    if not vault_config.get("enabled") or not is_vault_configured(vault_config):
        print("Vault не настроен или отключён.", file=sys.stderr)
        return 2
    conn = app.get_db()
    try:
        rows = conn.execute(
            """SELECT c.id AS credential_id, c.app_id, c.title_enc,
                      a.name AS app_name, a.url AS app_url
               FROM app_credentials AS c JOIN apps AS a ON a.id = c.app_id
               ORDER BY a.name COLLATE NOCASE, c.id"""
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        print("В Vault пока нет записей. Создайте запись в разделе Vault и повторите.", file=sys.stderr)
        return 2

    print("Выберите запись Vault. Сервисные токены не выводятся и не принимаются как аргументы.")
    for row in rows:
        # repr() escapes terminal control characters from legacy card metadata.
        title = decrypt_secret(row["title_enc"])
        print(
            f"  ID {row['credential_id']} · {str(row['app_name'])!r} · "
            f"{title!r} · {str(row['app_url'])!r}"
        )
    try:
        credential_id = int(input("ID записи Vault: ").strip())
    except (ValueError, EOFError):
        print("Некорректный ID записи.", file=sys.stderr)
        return 2

    selected = next((row for row in rows if int(row["credential_id"]) == credential_id), None)
    if selected is None:
        print("Запись не найдена.", file=sys.stderr)
        return 2

    app_url = str(selected["app_url"])
    canonical_target = normalize_login_url(
        app_url,
        allow_private_http=quick_access_private_http_allowed(),
    )
    if not canonical_target or not is_quick_access_supported_url(app_url):
        print("Точный URL карточки отсутствует в VAULT_QUICK_ACCESS_SITES или не разрешён.", file=sys.stderr)
        return 2

    token = getpass.getpass("Сервисный токен (ввод скрыт): ")
    confirmation = getpass.getpass("Повторите токен: ")
    if token != confirmation:
        print("Значения не совпадают.", file=sys.stderr)
        return 2
    if not _valid_token(token):
        print("Токен должен быть ASCII без пробелов/управляющих символов и не длиннее 8192 символов.", file=sys.stderr)
        return 2

    try:
        provision_token(
            app.get_db,
            int(selected["app_id"]),
            credential_id,
            app_url,
            token,
        )
    except Exception:
        print("Не удалось сохранить токен. Проверьте ключ Vault и состояние БД.", file=sys.stderr)
        return 1
    finally:
        token = ""
        confirmation = ""

    print("Токен сохранён зашифрованным в существующем Vault и оставлен отключённым.")
    print("Откройте запись Vault и включите «Вход через Quick Access» явным действием.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
