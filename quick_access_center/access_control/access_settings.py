# access_control/access_settings.py
"""
Access Control core для универсального Flask-шаблона.

Этот файл НЕ регистрирует routes напрямую.
Routes и static подключаются через Blueprint в access_control/blueprint.py.

Имена настроек только MAIN_ACCESS_*.
Логи только через on_off_debug.
MAIN_ACCESS_SECRET_KEY используется приложением как секрет подписи Flask-сессии.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Optional

from flask import abort, jsonify, request, render_template, redirect, url_for, session
from werkzeug.security import check_password_hash

from client_address import resolve_client_ip


# ==========================================================
# Совместимое подключение on_off_debug текущего проекта
# ==========================================================
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


def _with_source(message: str, source: Optional[str] = None) -> str:
    return f"[{source}] {message}" if source else str(message)


def debug_info_print(message, source: Optional[str] = None) -> None:
    _debug_success1_print(_with_source(message, source))


def debug_success_print(message, source: Optional[str] = None) -> None:
    _debug_success_print(_with_source(message, source))


def debug_warning_print(message, source: Optional[str] = None) -> None:
    _debug_error1_print(_with_source(message, source))


def debug_error_print(message, source: Optional[str] = None) -> None:
    _debug_error_print(_with_source(message, source))


def debug_error1_print(message, source: Optional[str] = None) -> None:
    _debug_error1_print(_with_source(message, source))


def critical_error_print(message, source: Optional[str] = None) -> None:
    _debug_error_print(_with_source(f"CRITICAL | {message}", source))


BASE_DIR = Path(__file__).resolve().parent
ACCESS_ENV_PATH = BASE_DIR / "access.env"
_data_dir = os.environ.get("MSB_QUICK_ACCESS_DATA_DIR", "").strip()
ATTEMPTS_DIR = Path(_data_dir).expanduser().resolve() / "attempts" if _data_dir else BASE_DIR
ACCESS_ATTEMPTS_FILE = ATTEMPTS_DIR / "access_attempts.json"
ACCESS_ATTEMPTS_LOCK_FILE = ATTEMPTS_DIR / "access_attempts.lock"
_ATTEMPTS_THREAD_LOCK = threading.RLock()

LOG_SOURCE = "access_control.access_settings"

ACCESS_CONFIG: Dict = {}
ACCESS_CONFIG_LOADED = False


ACCESS_EXEMPT_ENDPOINTS = {
    # main app static
    "static",

    # access_control blueprint
    "access_control.static",
    "access_control.access_control_page",
    "access_control.access_login_route",
    "access_control.access_logout_route",
}


# ==========================================================
# ENV reader
# ==========================================================

def read_access_env_file() -> Dict[str, str]:
    """
    Читает access_control/access.env без сторонних библиотек.

    Здесь НЕ пишем success-лог, потому что эта функция может быть вызвана
    внутри запроса. Успешную загрузку логирует только reload_access_config(log=True).
    """
    data: Dict[str, str] = {}

    if not ACCESS_ENV_PATH.exists():
        return data

    try:
        with ACCESS_ENV_PATH.open("r", encoding="utf-8", errors="ignore") as file:
            for line_number, line in enumerate(file, start=1):
                clean = line.strip()

                if not clean or clean.startswith("#") or "=" not in clean:
                    continue

                key, value = clean.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if not key:
                    debug_warning_print(
                        f"Пропущена строка access.env без ключа. line={line_number}",
                        source=LOG_SOURCE,
                    )
                    continue

                data[key] = value

    except Exception as e:
        debug_error_print(
            f"Ошибка чтения access.env: {e}",
            source=LOG_SOURCE,
        )
        return {}

    return data


def _raw_env_value(data: Dict[str, str], name: str, default: str = "") -> str:
    """
    Возвращает значение только по новому имени MAIN_ACCESS_*.
    Старые ACCESS_* намеренно не используются, чтобы в шаблоне не было каши.
    """
    value = os.environ.get(name, data.get(name, default))
    return str(value or "").strip()


def access_env_bool(data: Dict[str, str], name: str, default: str = "1") -> bool:
    value = _raw_env_value(data, name, default).lower()
    return value not in {"0", "false", "no", "off", "disable", "disabled", "нет", "ложь"}


def access_env_int(data: Dict[str, str], name: str, default: str = "12") -> int:
    value = _raw_env_value(data, name, default)

    try:
        return int(str(value).strip())
    except Exception:
        debug_warning_print(
            f"Некорректное int-значение {name}. Используется default={default}.",
            source=LOG_SOURCE,
        )
        return int(default)


def access_env_str(data: Dict[str, str], name: str, default: str = "") -> str:
    return _raw_env_value(data, name, default)


def parse_access_list(value: str) -> list[str]:
    if not value:
        return []

    return [
        item.strip()
        for item in value.replace("\n", ",").split(",")
        if item.strip()
    ]


def build_access_config(data: Dict[str, str]) -> Dict:
    """
    Собирает конфиг только из MAIN_ACCESS_*.
    """
    return {
        "enabled": access_env_bool(data, "MAIN_ACCESS_ENABLED", "1"),
        "username": access_env_str(data, "MAIN_ACCESS_USERNAME", "admin"),

        "password_hash": access_env_str(data, "MAIN_ACCESS_PASSWORD_HASH", ""),

        "allowed_ips_raw": access_env_str(data, "MAIN_ACCESS_ALLOWED_IPS", "127.0.0.1,::1"),
        "allowed_ips": parse_access_list(
            access_env_str(data, "MAIN_ACCESS_ALLOWED_IPS", "127.0.0.1,::1")
        ),
        "trust_proxy": access_env_bool(data, "MAIN_ACCESS_TRUST_PROXY", "0"),
        "trusted_proxies": parse_access_list(
            access_env_str(data, "MAIN_ACCESS_TRUSTED_PROXIES", "127.0.0.1,::1")
        ),
        "session_hours": access_env_int(data, "MAIN_ACCESS_SESSION_HOURS", "12"),

        # Секрет подписи access-сессии. Значение никогда не логируется.
        "access_secret_key": access_env_str(data, "MAIN_ACCESS_SECRET_KEY", ""),

        "log_failed": access_env_bool(data, "MAIN_ACCESS_LOG_FAILED", "1"),

        "max_failed_attempts": access_env_int(data, "MAIN_ACCESS_MAX_FAILED_ATTEMPTS", "5"),
        "failed_window_minutes": access_env_int(data, "MAIN_ACCESS_FAILED_WINDOW_MINUTES", "10"),
        "lock_minutes": access_env_int(data, "MAIN_ACCESS_LOCK_MINUTES", "15"),
        "failed_delay_seconds": access_env_int(data, "MAIN_ACCESS_FAILED_DELAY_SECONDS", "1"),
    }


def reload_access_config(log: bool = False) -> Dict:
    """
    Перезагружает конфиг доступа.

    log=True использовать только при старте или ручной перезагрузке.
    Не использовать log=True внутри каждого request.
    """
    global ACCESS_CONFIG, ACCESS_CONFIG_LOADED

    data = read_access_env_file()
    config = build_access_config(data)

    ACCESS_CONFIG = config
    ACCESS_CONFIG_LOADED = True

    if log:
        if ACCESS_ENV_PATH.exists():
            debug_success_print(
                "access.env успешно прочитан. Секретные значения не выводятся.",
                source=LOG_SOURCE,
            )
        else:
            debug_warning_print(
                f"access.env не найден: {ACCESS_ENV_PATH}. Используются default-настройки.",
                source=LOG_SOURCE,
            )

        if config.get("password_hash"):
            debug_success_print(
                "MAIN_ACCESS_PASSWORD_HASH загружен. Hash не выводится.",
                source=LOG_SOURCE,
            )
        else:
            debug_warning_print(
                "MAIN_ACCESS_PASSWORD_HASH пустой. Вход заблокирован до выполнения setup_access.py.",
                source=LOG_SOURCE,
            )

        if config.get("access_secret_key"):
            debug_success_print(
                "MAIN_ACCESS_SECRET_KEY загружен. Значение скрыто.",
                source=LOG_SOURCE,
            )
        else:
            debug_warning_print(
                "MAIN_ACCESS_SECRET_KEY пустой. Требуется MSB_QUICK_ACCESS_SECRET_KEY в окружении.",
                source=LOG_SOURCE,
            )

        debug_success_print(
            (
                "Access Control config готов: "
                f"enabled={config['enabled']}, "
                f"trust_proxy={config['trust_proxy']}, "
                f"session_hours={config['session_hours']}, "
                f"allowed_ips_count={len(config['allowed_ips'])}"
            ),
            source=LOG_SOURCE,
        )

    return config


def get_access_config() -> Dict:
    """
    Возвращает кешированный access config.

    Здесь нет success-логов, потому что функция вызывается на каждый request.
    """
    if not ACCESS_CONFIG_LOADED:
        return reload_access_config(log=False)

    return ACCESS_CONFIG


# ==========================================================
# Request helpers
# ==========================================================

def get_client_ip() -> str:
    config = get_access_config()
    return resolve_client_ip(
        request.remote_addr,
        request.headers.get("X-Forwarded-For", ""),
        request.headers.get("X-Real-IP", ""),
        trust_proxy=config["trust_proxy"],
        trusted_proxies=config["trusted_proxies"],
    )


def is_ip_allowed(ip_text: str) -> bool:
    config = get_access_config()
    allowed_items = config["allowed_ips"]

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
            else:
                if client_ip == ipaddress.ip_address(item):
                    return True
        except Exception:
            debug_warning_print(
                f"Некорректное правило MAIN_ACCESS_ALLOWED_IPS пропущено: {item}",
                source=LOG_SOURCE,
            )
            continue

    return False


def is_safe_next_url(next_url: str) -> bool:
    if not next_url or not next_url.startswith("/"):
        return False

    if next_url.startswith("//") or "\\" in next_url:
        return False

    return not any(ord(char) < 32 for char in next_url)


def is_access_logged_in() -> bool:
    config = get_access_config()

    if not config["enabled"]:
        return True

    if not session.get("access_logged_in"):
        return False

    login_at = session.get("access_login_at")

    if not login_at:
        session.clear()
        return False

    current_ip = get_client_ip()
    session_ip = str(session.get("access_ip", "")).strip()

    if not session_ip or not hmac.compare_digest(session_ip, current_ip):
        username = session.get("access_user", "unknown")
        session.clear()
        debug_warning_print(
            f"SESSION IP CHANGED | username={username} | old_ip={session_ip or 'unknown'} | new_ip={current_ip}",
            source=LOG_SOURCE,
        )
        return False

    try:
        max_age = max(1, int(config["session_hours"])) * 3600

        if time.time() - float(login_at) > max_age:
            username = session.get("access_user", "unknown")
            ip_text = session.get("access_ip", "unknown")
            session.clear()

            debug_warning_print(
                f"SESSION EXPIRED | ip={ip_text} | username={username}",
                source=LOG_SOURCE,
            )
            return False

    except Exception as e:
        session.clear()
        debug_error1_print(
            f"Ошибка проверки срока session: {e}",
            source=LOG_SOURCE,
        )
        return False

    return True


# ==========================================================
# CSRF for the main admin area (Vault has its own separate CSRF token)
# ==========================================================

def get_main_csrf_token() -> str:
    token = session.get("main_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["main_csrf_token"] = token
    return token


def require_main_csrf_token():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    if (request.endpoint or "").startswith("vault_control."):
        return None

    expected = str(session.get("main_csrf_token", ""))
    provided = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
    if expected and provided and hmac.compare_digest(expected, provided):
        return None

    if _request_expects_json():
        return jsonify({"ok": False, "error": "invalid_csrf_token"}), 400
    abort(400, description="Неверный CSRF-токен. Обновите страницу и повторите действие.")


# ==========================================================
# Protect hook
# ==========================================================

def _request_expects_json() -> bool:
    return bool(
        request.is_json
        or request.path.startswith("/api/")
        or request.accept_mimetypes.best == "application/json"
    )


def _access_error_response(message: str, status_code: int):
    next_url = request.full_path if request.query_string else request.path
    login_url = url_for(
        "access_control.access_control_page",
        error=message if status_code == 403 else None,
        msg=message if status_code == 401 else None,
        next=next_url,
    )

    if _request_expects_json():
        return jsonify({
            "ok": False,
            "error": "access_denied" if status_code == 403 else "authentication_required",
            "message": message,
            "login_url": login_url,
        }), status_code

    return redirect(login_url)


def protect_admin_routes():
    config = get_access_config()

    if not config["enabled"]:
        return None

    endpoint = request.endpoint or ""

    if endpoint in ACCESS_EXEMPT_ENDPOINTS:
        return None

    current_ip = get_client_ip()

    if not is_ip_allowed(current_ip):
        critical_error_print(
            f"BLOCKED IP | ip={current_ip} | path={request.path} | endpoint={endpoint}",
            source=LOG_SOURCE,
        )
        return _access_error_response(
            f"Доступ запрещён для IP: {current_ip}",
            403,
        )

    if not is_access_logged_in():
        return _access_error_response("Сначала войдите в систему.", 401)

    return None


# ==========================================================
# Pages
# ==========================================================

def render_access_page(
    error_message: str = "",
    system_message: str = "",
    login_value: str = "",
    next_url: str = "/",
):
    current_ip = get_client_ip()
    config = get_access_config()

    return render_template(
        "access_control/access-control.html",
        session_user=session.get("access_user"),
        is_logged_in=is_access_logged_in(),
        system_message=system_message,
        error_message=error_message,
        login_value=login_value,
        next_url=next_url if is_safe_next_url(next_url) else "/",
        access_enabled=config["enabled"],
        access_current_ip=current_ip,
        access_ip_allowed=is_ip_allowed(current_ip),
        access_allowed_ips=config["allowed_ips_raw"],
        access_trust_proxy=config["trust_proxy"],
        access_session_hours=config["session_hours"],
    )


def access_control_page():
    error_message = request.args.get("error", "").strip()
    system_message = request.args.get("msg", "").strip()
    next_url = request.args.get("next", "/").strip() or "/"

    current_ip = get_client_ip()

    if not is_ip_allowed(current_ip):
        error_message = error_message or f"Доступ запрещён для IP: {current_ip}"

    return render_access_page(
        error_message=error_message,
        system_message=system_message,
        next_url=next_url,
    )


# ==========================================================
# Anti brute-force
# ==========================================================

@contextmanager
def _attempts_storage_lock():
    """Сериализует чтение/запись попыток между потоками и Gunicorn workers."""
    with _ATTEMPTS_THREAD_LOCK:
        ACCESS_ATTEMPTS_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        lock_handle = ACCESS_ATTEMPTS_LOCK_FILE.open("a+", encoding="utf-8")

        try:
            try:
                import fcntl  # Linux/systemd/Gunicorn
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


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _attempt_key_ip(ip_text: str) -> str:
    return f"ip::{ip_text}"


def _attempt_key_user(ip_text: str, username: str) -> str:
    normalized_username = (username or "").strip().lower()
    return f"user::{ip_text}::{normalized_username}"


def _load_attempts_data() -> dict:
    if not ACCESS_ATTEMPTS_FILE.exists():
        return {"records": {}}

    try:
        data = json.loads(
            ACCESS_ATTEMPTS_FILE.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        )

        if not isinstance(data, dict):
            return {"records": {}}

        if not isinstance(data.get("records"), dict):
            data["records"] = {}

        return data

    except Exception as e:
        debug_error1_print(
            f"ATTEMPTS JSON READ ERROR | error={e}",
            source=LOG_SOURCE,
        )
        return {"records": {}}


def _save_attempts_data(data: dict) -> None:
    try:
        ACCESS_ATTEMPTS_FILE.parent.mkdir(parents=True, exist_ok=True)

        temp_file = ACCESS_ATTEMPTS_FILE.with_suffix(".tmp")
        temp_file.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temp_file.replace(ACCESS_ATTEMPTS_FILE)

    except Exception as e:
        debug_error1_print(
            f"ATTEMPTS JSON SAVE ERROR | error={e}",
            source=LOG_SOURCE,
        )


def _cleanup_attempts_data(data: dict) -> dict:
    config = get_access_config()
    now = time.time()

    max_keep_seconds = max(
        3600,
        int(config["failed_window_minutes"]) * 60 * 3,
        int(config["lock_minutes"]) * 60 * 3,
    )

    records = data.get("records", {})
    cleaned = {}

    for key, record in records.items():
        last_failed_at = _safe_float(record.get("last_failed_at"))
        locked_until = _safe_float(record.get("locked_until"))

        if locked_until > now:
            cleaned[key] = record
            continue

        if last_failed_at and now - last_failed_at <= max_keep_seconds:
            cleaned[key] = record

    data["records"] = cleaned
    return data


def get_login_lock_status(username: str, ip_text: str) -> dict:
    with _attempts_storage_lock():
        data = _cleanup_attempts_data(_load_attempts_data())
        now = time.time()

        keys = [
            _attempt_key_ip(ip_text),
            _attempt_key_user(ip_text, username),
        ]

        locked_until_max = 0.0
        locked_key = ""

        for key in keys:
            record = data.get("records", {}).get(key, {})
            locked_until = _safe_float(record.get("locked_until"))

            if locked_until > now and locked_until > locked_until_max:
                locked_until_max = locked_until
                locked_key = key

        _save_attempts_data(data)

        if locked_until_max > now:
            return {
                "locked": True,
                "locked_until": locked_until_max,
                "remaining_seconds": int(locked_until_max - now),
                "key": locked_key,
            }

        return {
            "locked": False,
            "locked_until": 0,
            "remaining_seconds": 0,
            "key": "",
        }


def register_failed_login(username: str, ip_text: str) -> dict:
    config = get_access_config()
    now = time.time()

    max_failed = max(1, int(config["max_failed_attempts"]))
    window_seconds = max(60, int(config["failed_window_minutes"]) * 60)
    lock_seconds = max(60, int(config["lock_minutes"]) * 60)

    with _attempts_storage_lock():
        data = _cleanup_attempts_data(_load_attempts_data())
        records = data.setdefault("records", {})

        result = {
            "locked": False,
            "remaining_attempts": max_failed,
            "locked_until": 0,
            "remaining_seconds": 0,
        }

        keys = [
            _attempt_key_ip(ip_text),
            _attempt_key_user(ip_text, username),
        ]

        for key in keys:
            record = records.get(key, {})

            first_failed_at = _safe_float(record.get("first_failed_at"))
            failed_count = int(record.get("failed_count") or 0)

            if not first_failed_at or now - first_failed_at > window_seconds:
                first_failed_at = now
                failed_count = 0

            failed_count += 1
            locked_until = 0.0

            if failed_count >= max_failed:
                locked_until = now + lock_seconds

            records[key] = {
                "failed_count": failed_count,
                "first_failed_at": first_failed_at,
                "last_failed_at": now,
                "locked_until": locked_until,
            }

            remaining_attempts = max(0, max_failed - failed_count)

            if remaining_attempts < result["remaining_attempts"]:
                result["remaining_attempts"] = remaining_attempts

            if locked_until > now:
                result["locked"] = True
                result["locked_until"] = max(result["locked_until"], locked_until)
                result["remaining_seconds"] = int(result["locked_until"] - now)

        _save_attempts_data(data)

    if result["locked"]:
        critical_error_print(
            f"BRUTE-FORCE LOCK | ip={ip_text} | username={username} | locked_seconds={result['remaining_seconds']}",
            source=LOG_SOURCE,
        )

    return result


def clear_failed_logins(username: str, ip_text: str) -> None:
    with _attempts_storage_lock():
        data = _load_attempts_data()
        records = data.setdefault("records", {})

        for key in [
            _attempt_key_ip(ip_text),
            _attempt_key_user(ip_text, username),
        ]:
            records.pop(key, None)

        _save_attempts_data(_cleanup_attempts_data(data))


def format_lock_time(seconds: int) -> str:
    seconds = max(0, int(seconds))

    minutes = seconds // 60
    rest_seconds = seconds % 60

    if minutes <= 0:
        return f"{rest_seconds} сек."

    return f"{minutes} мин. {rest_seconds} сек."


# ==========================================================
# Login / logout
# ==========================================================

def access_login_route():
    config = get_access_config()
    current_ip = get_client_ip()

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    remember = request.form.get("remember", "").strip() == "1"
    next_url = request.form.get("next", "/").strip() or "/"

    if not config["enabled"]:
        return redirect(next_url if is_safe_next_url(next_url) else "/")

    if not is_ip_allowed(current_ip):
        critical_error_print(
            f"LOGIN BLOCKED BY IP | ip={current_ip} | username={username}",
            source=LOG_SOURCE,
        )

        return render_access_page(
            error_message=f"Ваш IP не разрешён: {current_ip}",
            login_value=username,
            next_url=next_url,
        )

    lock_status = get_login_lock_status(username=username, ip_text=current_ip)

    if lock_status["locked"]:
        critical_error_print(
            (
                "LOGIN LOCKED | "
                f"ip={current_ip} | username={username} | "
                f"remaining={lock_status['remaining_seconds']}s | key={lock_status['key']}"
            ),
            source=LOG_SOURCE,
        )

        return render_access_page(
            error_message=(
                "Слишком много неправильных попыток входа. "
                f"Повторите через {format_lock_time(lock_status['remaining_seconds'])}"
            ),
            login_value=username,
            next_url=next_url,
        )

    username_ok = hmac.compare_digest(username, config["username"])

    password_ok = False
    if config.get("password_hash"):
        try:
            password_ok = check_password_hash(config["password_hash"], password)
        except Exception as e:
            debug_error_print(
                f"HASH CHECK ERROR | ip={current_ip} | username={username} | error={e}",
                source=LOG_SOURCE,
            )

    if username_ok and password_ok:
        clear_failed_logins(username=username, ip_text=current_ip)

        session.clear()
        session["access_logged_in"] = True
        session["access_user"] = username
        session["access_login_at"] = str(time.time())
        session["access_ip"] = current_ip
        session.permanent = remember

        debug_success_print(
            f"LOGIN OK | ip={current_ip} | username={username} | remember={remember}",
            source=LOG_SOURCE,
        )

        return redirect(next_url if is_safe_next_url(next_url) else "/")

    failed_info = register_failed_login(username=username, ip_text=current_ip)

    delay_seconds = max(0, int(config.get("failed_delay_seconds", 1)))
    if delay_seconds:
        time.sleep(delay_seconds)

    if config["log_failed"]:
        debug_warning_print(
            (
                "LOGIN FAILED | "
                f"ip={current_ip} | username={username} | "
                f"remaining_attempts={failed_info['remaining_attempts']} | "
                f"locked={failed_info['locked']}"
            ),
            source=LOG_SOURCE,
        )

    if failed_info["locked"]:
        error_message = (
            "Слишком много неправильных попыток входа. "
            f"Доступ временно заблокирован на {format_lock_time(failed_info['remaining_seconds'])}"
        )
    else:
        error_message = (
            "Неверный логин или пароль. "
            f"Осталось попыток: {failed_info['remaining_attempts']}"
        )

    return render_access_page(
        error_message=error_message,
        login_value=username,
        next_url=next_url,
    )


def access_logout_route():
    current_ip = get_client_ip()
    username = session.get("access_user", "unknown")

    session.clear()

    debug_info_print(
        f"LOGOUT | ip={current_ip} | username={username}",
        source=LOG_SOURCE,
    )

    return redirect(
        url_for("access_control.access_control_page", msg="Вы вышли из системы.")
    )
