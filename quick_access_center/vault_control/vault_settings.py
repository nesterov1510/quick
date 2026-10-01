# vault_control/vault_settings.py
"""Настройки, отдельная авторизация и шифрование хранилища паролей."""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
import threading
import time
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from flask import abort, redirect, request, session, url_for
from werkzeug.security import check_password_hash

from client_address import resolve_client_ip

try:
    from on_off_debug.debug_mode import (
        debug_success_print as _debug_success_print,
        debug_success1_print as _debug_success1_print,
        debug_error_print as _debug_error_print,
        debug_error1_print as _debug_error1_print,
    )
except Exception:  # pragma: no cover
    def _debug_success_print(message) -> None:
        return None

    def _debug_success1_print(message) -> None:
        return None

    def _debug_error_print(message) -> None:
        return None

    def _debug_error1_print(message) -> None:
        return None


BASE_DIR = Path(__file__).resolve().parent
VAULT_ENV_PATH = BASE_DIR / "vault.env"
_data_dir = os.environ.get("MSB_QUICK_ACCESS_DATA_DIR", "").strip()
ATTEMPTS_DIR = Path(_data_dir).expanduser().resolve() / "attempts" if _data_dir else BASE_DIR
VAULT_ATTEMPTS_FILE = ATTEMPTS_DIR / "vault_attempts.json"
VAULT_ATTEMPTS_LOCK_FILE = ATTEMPTS_DIR / "vault_attempts.lock"
_ATTEMPTS_THREAD_LOCK = threading.RLock()

LOG_SOURCE = "vault_control.vault_settings"
VAULT_CONFIG: Dict[str, Any] = {}
VAULT_CONFIG_LOADED = False


def _log_success(message: str) -> None:
    _debug_success_print(f"[{LOG_SOURCE}] {message}")


def _log_detail(message: str) -> None:
    _debug_success1_print(f"[{LOG_SOURCE}] {message}")


def _log_warning(message: str) -> None:
    _debug_error1_print(f"[{LOG_SOURCE}] {message}")


def _log_error(message: str) -> None:
    _debug_error_print(f"[{LOG_SOURCE}] {message}")


def read_vault_env_file() -> Dict[str, str]:
    data: Dict[str, str] = {}

    if not VAULT_ENV_PATH.exists():
        return data

    try:
        with VAULT_ENV_PATH.open("r", encoding="utf-8", errors="ignore") as file:
            for line_number, line in enumerate(file, start=1):
                clean = line.strip()
                if not clean or clean.startswith("#") or "=" not in clean:
                    continue

                key, value = clean.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if not key:
                    _log_warning(f"Пропущена строка vault.env без ключа. line={line_number}")
                    continue

                data[key] = value
    except Exception as error:
        _log_error(f"Ошибка чтения vault.env: {error}")
        return {}

    return data


def _env_value(data: Dict[str, str], name: str, default: str = "") -> str:
    return str(os.environ.get(name, data.get(name, default)) or "").strip()


def _env_bool(data: Dict[str, str], name: str, default: str = "1") -> bool:
    return _env_value(data, name, default).lower() not in {
        "0", "false", "no", "off", "disabled", "disable", "нет", "ложь"
    }


def _env_int(data: Dict[str, str], name: str, default: str) -> int:
    try:
        return int(_env_value(data, name, default))
    except Exception:
        _log_warning(f"Некорректное значение {name}; используется {default}")
        return int(default)


def _parse_list(value: str) -> list[str]:
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]


def build_vault_config(data: Dict[str, str]) -> Dict[str, Any]:
    allowed_raw = _env_value(
        data,
        "VAULT_ACCESS_ALLOWED_IPS",
        _env_value(data, "MAIN_ACCESS_ALLOWED_IPS", "127.0.0.1,::1"),
    )

    return {
        "enabled": _env_bool(data, "VAULT_ACCESS_ENABLED", "1"),
        "username": _env_value(data, "VAULT_ACCESS_USERNAME", "vault-admin"),
        "password_hash": _env_value(data, "VAULT_ACCESS_PASSWORD_HASH", ""),
        "encryption_key": _env_value(data, "VAULT_ENCRYPTION_KEY", ""),
        "allowed_ips_raw": allowed_raw,
        "allowed_ips": _parse_list(allowed_raw),
        "trust_proxy": _env_bool(data, "VAULT_ACCESS_TRUST_PROXY", "0"),
        "trusted_proxies": _parse_list(
            _env_value(data, "VAULT_ACCESS_TRUSTED_PROXIES", "127.0.0.1,::1")
        ),
        "session_minutes": max(5, _env_int(data, "VAULT_ACCESS_SESSION_MINUTES", "30")),
        # 1 = срок Vault продлевается, пока администратор активно работает.
        # Сессия закрывается только после указанного времени бездействия.
        "sliding_session": _env_bool(data, "VAULT_ACCESS_SLIDING_SESSION", "1"),
        "session_refresh_seconds": max(
            10,
            _env_int(data, "VAULT_ACCESS_SESSION_REFRESH_SECONDS", "30"),
        ),
        "max_failed_attempts": max(1, _env_int(data, "VAULT_ACCESS_MAX_FAILED_ATTEMPTS", "5")),
        "failed_window_minutes": max(1, _env_int(data, "VAULT_ACCESS_FAILED_WINDOW_MINUTES", "10")),
        "lock_minutes": max(1, _env_int(data, "VAULT_ACCESS_LOCK_MINUTES", "15")),
        "failed_delay_seconds": max(0, _env_int(data, "VAULT_ACCESS_FAILED_DELAY_SECONDS", "1")),
    }


def reload_vault_config(log: bool = False) -> Dict[str, Any]:
    global VAULT_CONFIG, VAULT_CONFIG_LOADED

    data = read_vault_env_file()
    VAULT_CONFIG = build_vault_config(data)
    VAULT_CONFIG_LOADED = True

    if log:
        _log_success(
            "Vault config загружен: "
            f"enabled={VAULT_CONFIG['enabled']}, "
            f"configured={is_vault_configured(VAULT_CONFIG)}, "
            f"session_minutes={VAULT_CONFIG['session_minutes']}, "
            f"allowed_ips_count={len(VAULT_CONFIG['allowed_ips'])}"
        )

    return VAULT_CONFIG


def get_vault_config() -> Dict[str, Any]:
    if not VAULT_CONFIG_LOADED:
        return reload_vault_config(log=False)
    return VAULT_CONFIG


def is_vault_configured(config: Optional[Dict[str, Any]] = None) -> bool:
    cfg = config or get_vault_config()
    return bool(cfg.get("username") and cfg.get("password_hash") and cfg.get("encryption_key"))


def get_client_ip() -> str:
    config = get_vault_config()
    return resolve_client_ip(
        request.remote_addr,
        request.headers.get("X-Forwarded-For", ""),
        request.headers.get("X-Real-IP", ""),
        trust_proxy=config["trust_proxy"],
        trusted_proxies=config["trusted_proxies"],
    )


def is_ip_allowed(ip_text: str) -> bool:
    allowed_items = get_vault_config().get("allowed_ips", [])

    if not allowed_items:
        return False
    if "*" in allowed_items:
        return True

    try:
        client_ip = ipaddress.ip_address(ip_text)
    except Exception:
        return False

    for item in allowed_items:
        try:
            if "/" in item:
                if client_ip in ipaddress.ip_network(item, strict=False):
                    return True
            elif client_ip == ipaddress.ip_address(item):
                return True
        except Exception:
            _log_warning(f"Некорректное правило VAULT_ACCESS_ALLOWED_IPS пропущено: {item}")

    return False


def is_safe_next_url(next_url: str) -> bool:
    if not next_url or not next_url.startswith("/"):
        return False
    if next_url.startswith("//") or "\\" in next_url:
        return False
    return not any(ord(char) < 32 for char in next_url)


def clear_vault_session() -> None:
    keys = [key for key in session.keys() if key.startswith("vault_")]
    for key in keys:
        session.pop(key, None)


def is_vault_logged_in() -> bool:
    """Проверяет отдельную Vault-сессию.

    По умолчанию используется sliding session: пока администратор работает
    внутри Vault, срок доступа продлевается. Закрытие происходит после
    VAULT_ACCESS_SESSION_MINUTES минут бездействия, а не через несколько
    минут после самого входа независимо от активности.
    """
    config = get_vault_config()

    if not config["enabled"]:
        return True
    if not session.get("vault_logged_in"):
        return False

    current_ip = get_client_ip()
    session_ip = str(session.get("vault_ip", "")).strip()

    if not session_ip or not hmac.compare_digest(session_ip, current_ip):
        clear_vault_session()
        _log_warning(f"Vault session IP изменился: old={session_ip or 'unknown'}, new={current_ip}")
        return False

    try:
        now = time.time()
        login_at = float(session.get("vault_login_at", 0))
        last_activity = float(session.get("vault_last_activity", login_at or 0))
        max_age = int(config["session_minutes"]) * 60
        sliding_session = bool(config.get("sliding_session", True))
        reference_time = last_activity if sliding_session else login_at

        if not reference_time or now - reference_time > max_age:
            clear_vault_session()
            _log_warning(f"Vault session истекла для IP={current_ip}")
            return False

        # Не переписываем cookie на каждом запросе: обновляем отметку активности
        # с небольшим интервалом. Это сохраняет сессию стабильной и не создаёт шум.
        refresh_seconds = int(config.get("session_refresh_seconds", 30))
        if sliding_session and now - last_activity >= refresh_seconds:
            session["vault_last_activity"] = str(now)
            session.modified = True

    except Exception as error:
        clear_vault_session()
        _log_warning(f"Ошибка проверки Vault session: {error}")
        return False

    return True


def vault_login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        config = get_vault_config()
        current_ip = get_client_ip()

        if not config["enabled"]:
            abort(404)

        if not is_ip_allowed(current_ip):
            return redirect(
                url_for(
                    "vault_control.vault_login",
                    error=f"Доступ к хранилищу запрещён для IP: {current_ip}",
                    next=request.full_path if request.query_string else request.path,
                )
            )

        if not is_vault_logged_in():
            return redirect(
                url_for(
                    "vault_control.vault_login",
                    next=request.full_path if request.query_string else request.path,
                )
            )

        return view_func(*args, **kwargs)

    return wrapped


def get_fernet() -> Fernet:
    config = get_vault_config()
    key = str(config.get("encryption_key", "")).encode("utf-8")

    if not key:
        raise RuntimeError("VAULT_ENCRYPTION_KEY не настроен")

    try:
        return Fernet(key)
    except Exception as error:
        raise RuntimeError("VAULT_ENCRYPTION_KEY имеет неверный формат") from error


def encrypt_secret(value: str) -> str:
    clean_value = str(value or "")
    if not clean_value:
        return ""
    return get_fernet().encrypt(clean_value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    clean_value = str(value or "")
    if not clean_value:
        return ""

    try:
        return get_fernet().decrypt(clean_value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        _log_error("Не удалось расшифровать запись: неверный ключ или повреждённые данные")
        return "[ОШИБКА РАСШИФРОВКИ]"
    except Exception as error:
        _log_error(f"Ошибка расшифровки записи: {error}")
        return "[ОШИБКА РАСШИФРОВКИ]"


def get_csrf_token() -> str:
    token = str(session.get("vault_csrf_token", ""))
    if not token:
        token = secrets.token_urlsafe(32)
        session["vault_csrf_token"] = token
        session.modified = True
    return token


def reset_csrf_token() -> str:
    """Создаёт новый CSRF-токен без очистки основной и Vault-сессий."""
    token = secrets.token_urlsafe(32)
    session["vault_csrf_token"] = token
    session.modified = True
    return token


def validate_csrf_token() -> bool:
    expected = str(session.get("vault_csrf_token", ""))
    provided = str(request.form.get("csrf_token", ""))
    return bool(expected and provided and hmac.compare_digest(expected, provided))


@contextmanager
def _attempts_storage_lock():
    with _ATTEMPTS_THREAD_LOCK:
        VAULT_ATTEMPTS_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        lock_handle = VAULT_ATTEMPTS_LOCK_FILE.open("a+", encoding="utf-8")
        try:
            try:
                import fcntl
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            except Exception:
                fcntl = None
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_handle.close()


def _load_attempts() -> dict:
    if not VAULT_ATTEMPTS_FILE.exists():
        return {"records": {}}
    try:
        data = json.loads(VAULT_ATTEMPTS_FILE.read_text(encoding="utf-8", errors="ignore"))
        if not isinstance(data, dict) or not isinstance(data.get("records"), dict):
            return {"records": {}}
        return data
    except Exception:
        return {"records": {}}


def _save_attempts(data: dict) -> bool:
    """Атомарно сохраняет anti-brute-force данные.

    Ошибка файловой системы не должна ломать страницу входа. Она фиксируется
    в серверном логе, а пользователь всё равно получает обычную форму входа.
    """
    try:
        VAULT_ATTEMPTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        temp_path = VAULT_ATTEMPTS_FILE.with_suffix(".tmp")
        temp_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temp_path.replace(VAULT_ATTEMPTS_FILE)
        return True
    except Exception as error:
        _log_error(f"Не удалось сохранить Vault anti-brute-force state: {error}")
        return False


def _attempt_key(ip_text: str, username: str) -> str:
    return f"{ip_text}::{(username or '').strip().lower()}"


def get_login_lock_status(username: str, ip_text: str) -> dict:
    config = get_vault_config()
    now = time.time()
    key = _attempt_key(ip_text, username)

    try:
        with _attempts_storage_lock():
            data = _load_attempts()
            record = data.get("records", {}).get(key, {})
            locked_until = float(record.get("locked_until") or 0)

            if locked_until > now:
                return {
                    "locked": True,
                    "remaining_seconds": max(1, int(locked_until - now)),
                }

            window_seconds = int(config["failed_window_minutes"]) * 60
            last_failed_at = float(record.get("last_failed_at") or 0)
            if last_failed_at and now - last_failed_at > window_seconds:
                data.get("records", {}).pop(key, None)
                _save_attempts(data)
    except Exception as error:
        _log_error(f"Ошибка чтения Vault anti-brute-force state: {error}")

    return {"locked": False, "remaining_seconds": 0}


def register_failed_login(username: str, ip_text: str) -> dict:
    config = get_vault_config()
    now = time.time()
    key = _attempt_key(ip_text, username)
    max_failed = int(config["max_failed_attempts"])
    window_seconds = int(config["failed_window_minutes"]) * 60
    lock_seconds = int(config["lock_minutes"]) * 60
    failed_count = 1
    locked_until = 0

    try:
        with _attempts_storage_lock():
            data = _load_attempts()
            records = data.setdefault("records", {})
            record = records.get(key, {})
            first_failed_at = float(record.get("first_failed_at") or 0)
            failed_count = int(record.get("failed_count") or 0)

            if not first_failed_at or now - first_failed_at > window_seconds:
                first_failed_at = now
                failed_count = 0

            failed_count += 1
            locked_until = now + lock_seconds if failed_count >= max_failed else 0

            records[key] = {
                "failed_count": failed_count,
                "first_failed_at": first_failed_at,
                "last_failed_at": now,
                "locked_until": locked_until,
            }
            _save_attempts(data)
    except Exception as error:
        # Не выдаём пользователю 500 при неверном пароле, даже если файл
        # попыток временно недоступен. Ошибка остаётся в серверном логе.
        _log_error(f"Ошибка записи Vault anti-brute-force state: {error}")

    return {
        "locked": bool(locked_until),
        "remaining_attempts": max(0, max_failed - failed_count),
        "remaining_seconds": lock_seconds if locked_until else 0,
    }


def clear_failed_logins(username: str, ip_text: str) -> None:
    key = _attempt_key(ip_text, username)
    try:
        with _attempts_storage_lock():
            data = _load_attempts()
            data.setdefault("records", {}).pop(key, None)
            _save_attempts(data)
    except Exception as error:
        _log_error(f"Ошибка очистки Vault anti-brute-force state: {error}")


def verify_vault_login(username: str, password: str) -> bool:
    config = get_vault_config()
    username_ok = hmac.compare_digest(str(username or ""), str(config.get("username", "")))

    try:
        password_ok = check_password_hash(str(config.get("password_hash", "")), str(password or ""))
    except Exception:
        password_ok = False

    return bool(username_ok and password_ok)


def format_seconds(seconds: int) -> str:
    seconds = max(0, int(seconds))
    minutes, rest = divmod(seconds, 60)
    if minutes:
        return f"{minutes} мин. {rest} сек."
    return f"{rest} сек."
