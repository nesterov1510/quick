from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse

from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

app = Flask(__name__)

#################_управление_логированием_и_debug_####################################################################_такие_комментый_нужный для разделение кода не пропусти их_#
try:
    import on_off_debug.debug_mode as debug_mode  # type: ignore
    from on_off_debug.debug_mode import set_debug_mode, debug_success_print, debug_error_print, debug_success1_print, debug_error1_print  # type: ignore

    set_debug_mode(success=True, error=True, success1=True, error1=True, unicode_log=False)
except Exception:
    class _DebugModeFallback:
        DEBUG_SUCCESS_MODE = True

    debug_mode = _DebugModeFallback()

    def debug_success_print(message):
        pass

    def debug_error_print(message):
        pass

    def debug_success1_print(message):
        pass

    def debug_error1_print(message):
        pass
#################_управление_логированием_и_debug_####################################################################_такие_комментый_нужный для разделение кода не пропусти их_#

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Keep generated data separate from code when MSB_QUICK_ACCESS_DATA_DIR is set.
SAVE_ROOT_DIR = os.path.abspath(os.path.expanduser(
    os.environ.get("MSB_QUICK_ACCESS_DATA_DIR")
    or os.path.join(BASE_DIR, "save_blocks", "save_base")
))
SAVE_DB_DIR = os.path.join(SAVE_ROOT_DIR, "base")
SAVE_IMAGES_DIR = os.path.join(SAVE_ROOT_DIR, "images")
SAVE_OTMETKI_DIR = os.path.join(SAVE_ROOT_DIR, "otmetki")

OLD_DB_NAME = os.path.join(BASE_DIR, "quick_access.db")
DB_NAME = os.path.join(SAVE_DB_DIR, "quick_access.db")

PING_COUNT = max(1, int(os.environ.get("MSB_QUICK_ACCESS_PING_COUNT", "3")))
PING_WORKERS = max(1, int(os.environ.get("MSB_QUICK_ACCESS_PING_WORKERS", "8")))
NETWORK_CHECK_TIMEOUT_SECONDS = max(
    0.2,
    float(os.environ.get("MSB_QUICK_ACCESS_CHECK_TIMEOUT", "1.5")),
)
STATUS_REFRESH_INTERVAL_SECONDS = max(
    5,
    int(os.environ.get("MSB_QUICK_ACCESS_REFRESH_INTERVAL", "30")),
)
ALLOWED_IMAGE_FORMATS = {
    "png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "webp": "WEBP", "gif": "GIF",
}
ALLOWED_IMAGE_EXTENSIONS = set(ALLOWED_IMAGE_FORMATS)
MAX_IMAGE_BYTES = max(1024, int(os.environ.get("MSB_QUICK_ACCESS_MAX_IMAGE_BYTES", str(5 * 1024 * 1024))))
app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_BYTES + 1024 * 1024  # multipart overhead / form fields
Image.MAX_IMAGE_PIXELS = 20_000_000

# Проверка статусов выполняется отдельно от HTTP-запроса главной страницы.
# Благодаря этому dashboard открывается сразу, даже если часть сервисов недоступна.
_status_refresh_lock = threading.Lock()
_status_refresh_executor = ThreadPoolExecutor(
    max_workers=1,
    thread_name_prefix="msb-status-refresh",
)
_status_refresh_future = None
_status_refresh_last_started = 0.0


# --------------------------------------------------------------------------------------
# MSB LOGGING HELPERS — все сообщения только через твой debug-модуль, без print()
# --------------------------------------------------------------------------------------
def log_success(message: str):
    debug_success_print(f"[MSB QUICK ACCESS] {message}")


def log_error(message: str):
    debug_error_print(f"[MSB QUICK ACCESS ERROR] {message}")


def log_success1(message: str):
    debug_success1_print(f"[MSB QUICK ACCESS DETAIL] {message}")


def log_error1(message: str):
    debug_error1_print(f"[MSB QUICK ACCESS DETAIL ERROR] {message}")


# --------------------------------------------------------------------------------------
# ACCESS CONTROL
# --------------------------------------------------------------------------------------
try:
    from access_control import get_access_config, init_access_control

    _access_config = get_access_config()
    _flask_secret_key = (
        os.environ.get("MSB_QUICK_ACCESS_SECRET_KEY", "").strip()
        or str(_access_config.get("access_secret_key", "")).strip()
    )

    if not _flask_secret_key:
        raise RuntimeError(
            "Не задан MSB_QUICK_ACCESS_SECRET_KEY или MAIN_ACCESS_SECRET_KEY"
        )

    app.secret_key = _flask_secret_key
    init_access_control(app)
    log_success("Access Control включён")
except Exception as e:
    log_error(f"Access Control не запущен: {e}")
    raise


# --------------------------------------------------------------------------------------
# STORAGE
# --------------------------------------------------------------------------------------
def prepare_storage_dirs():
    """
    Готовит постоянное хранилище проекта:
    - save_blocks/save_base/base/quick_access.db
    - save_blocks/save_base/images/
    - save_blocks/save_base/otmetki/

    Если старая база есть рядом с app.py, а новой ещё нет — копируем старую в новое место.
    Старую базу не удаляем, чтобы не потерять данные.
    """
    try:
        os.makedirs(SAVE_DB_DIR, mode=0o700, exist_ok=True)
        os.makedirs(SAVE_IMAGES_DIR, mode=0o700, exist_ok=True)
        os.makedirs(SAVE_OTMETKI_DIR, mode=0o700, exist_ok=True)

        if (not os.environ.get("MSB_QUICK_ACCESS_DATA_DIR")
                and not os.path.exists(DB_NAME) and os.path.exists(OLD_DB_NAME)):
            shutil.copy2(OLD_DB_NAME, DB_NAME)
            log_success(f"База скопирована в новое место: {DB_NAME}")
    except Exception as e:
        log_error(f"Ошибка подготовки папок хранения: {e}")
        raise


prepare_storage_dirs()


# --------------------------------------------------------------------------------------
# DATABASE
# --------------------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_column(cur, table_name: str, column_name: str, column_sql: str):
    cur.execute(f"PRAGMA table_info({table_name})")
    existing_columns = [row[1] for row in cur.fetchall()]

    if column_name not in existing_columns:
        cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")
        log_success1(f"Добавлена колонка {column_name} в таблицу {table_name}")


def init_db():
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                address TEXT,
                app_type TEXT,
                description TEXT,
                launch_info TEXT,
                image_filename TEXT,
                status TEXT DEFAULT 'inactive',
                open_count INTEGER DEFAULT 0,
                created_at TEXT,
                last_opened TEXT,
                last_checked TEXT,
                ping_host TEXT,
                ping_result TEXT,
                ping_success_count INTEGER DEFAULT 0,
                ping_total_count INTEGER DEFAULT 3,
                order_index INTEGER DEFAULT 0
            )
        """)

        # Оставляем старые колонки для совместимости со старой базой,
        # но в интерфейсе показываем только нужное: название + IP/порт или ссылка + картинка.
        ensure_column(cur, "apps", "code", "code TEXT")
        ensure_column(cur, "apps", "name", "name TEXT NOT NULL DEFAULT ''")
        ensure_column(cur, "apps", "url", "url TEXT NOT NULL DEFAULT ''")
        ensure_column(cur, "apps", "address", "address TEXT")
        ensure_column(cur, "apps", "app_type", "app_type TEXT")
        ensure_column(cur, "apps", "description", "description TEXT")
        ensure_column(cur, "apps", "launch_info", "launch_info TEXT")
        ensure_column(cur, "apps", "image_filename", "image_filename TEXT")
        ensure_column(cur, "apps", "status", "status TEXT DEFAULT 'inactive'")
        ensure_column(cur, "apps", "open_count", "open_count INTEGER DEFAULT 0")
        ensure_column(cur, "apps", "created_at", "created_at TEXT")
        ensure_column(cur, "apps", "last_opened", "last_opened TEXT")
        ensure_column(cur, "apps", "last_checked", "last_checked TEXT")
        ensure_column(cur, "apps", "ping_host", "ping_host TEXT")
        ensure_column(cur, "apps", "ping_result", "ping_result TEXT")
        ensure_column(cur, "apps", "ping_success_count", "ping_success_count INTEGER DEFAULT 0")
        ensure_column(cur, "apps", "ping_total_count", "ping_total_count INTEGER DEFAULT 3")
        ensure_column(cur, "apps", "order_index", "order_index INTEGER DEFAULT 0")

        # Для старой базы: если порядок пустой, расставляем карточки по ID.
        cur.execute("SELECT id FROM apps WHERE order_index IS NULL OR order_index = 0 ORDER BY id ASC")
        rows_for_order = cur.fetchall()
        if rows_for_order:
            cur.execute("SELECT COALESCE(MAX(order_index), 0) AS max_order FROM apps")
            max_order = int(cur.fetchone()["max_order"] or 0)
            for offset, row in enumerate(rows_for_order, start=1):
                cur.execute(
                    "UPDATE apps SET order_index = ? WHERE id = ?",
                    (max_order + offset, row["id"])
                )

        conn.commit()
        conn.close()
        try:
            os.chmod(DB_NAME, 0o600)
        except OSError:
            pass  # Windows ACLs are configured separately.
        log_success(f"База данных готова: {DB_NAME}")
    except Exception as e:
        log_error(f"Ошибка инициализации базы: {e}")
        raise


init_db()


# --------------------------------------------------------------------------------------
# SEPARATE PASSWORD VAULT
# --------------------------------------------------------------------------------------
try:
    from vault_control import init_vault_control
    from vault_control.autologin import is_supported_login_url
    from vault_control.vault_settings import (
        get_csrf_token as get_vault_csrf_token,
        get_vault_config,
        is_vault_logged_in,
    )

    init_vault_control(app, get_db)

    # Не разрешаем приложению запуститься в частично обновлённом состоянии:
    # шаблон уже содержит ссылки Vault, поэтому все endpoints обязаны быть
    # зарегистрированы до обработки первого HTTP-запроса.
    required_vault_endpoints = {
        "vault_control.vault_index",
        "vault_control.vault_login",
        "vault_control.vault_logout",
        "vault_control.app_vault",
        "vault_control.autologin_credential",
        "vault_control.create_credential",
        "vault_control.update_credential",
        "vault_control.delete_credential",
    }
    missing_vault_endpoints = sorted(
        required_vault_endpoints.difference(app.view_functions.keys())
    )
    if missing_vault_endpoints:
        raise RuntimeError(
            "Vault Blueprint зарегистрирован не полностью. "
            f"Отсутствуют endpoints: {missing_vault_endpoints}"
        )

    log_success(
        "Отдельное админ-хранилище паролей подключено; "
        f"маршрутов проверено: {len(required_vault_endpoints)}"
    )
except Exception as e:
    log_error(f"Хранилище паролей не запущено: {e}")
    raise


# --------------------------------------------------------------------------------------
# HELPERS
# --------------------------------------------------------------------------------------
def normalize_target_to_url(target: str) -> str:
    """Accept only HTTP(S) links or a bare host[:port], never executable URLs."""
    target = (target or "").strip()
    if not target:
        return ""
    if any(char.isspace() or ord(char) < 32 for char in target) or "\\" in target:
        raise ValueError("Адрес не должен содержать пробелы или обратную косую черту")
    if "://" not in target:
        if target.startswith("/"):
            raise ValueError("Укажите адрес сервиса или ссылку HTTP(S)")
        target = "http://" + target

    try:
        parsed = urlparse(target)
        host = parsed.hostname
    except ValueError as error:
        raise ValueError("Некорректный адрес сервиса") from error
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        raise ValueError("Разрешены только адреса HTTP и HTTPS с корректным хостом")
    if parsed.username or parsed.password:
        raise ValueError("Не указывайте логин и пароль в адресе; используйте Vault")
    try:
        port = parsed.port  # Reject invalid port numbers before saving the link.
        if port == 0:
            raise ValueError("invalid port")
    except ValueError as error:
        raise ValueError("Порт должен быть числом от 1 до 65535") from error
    return parsed.scheme.lower() + "://" + target.split("://", 1)[1]


def get_address_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc or url.replace("http://", "").replace("https://", "")
    except Exception:
        return url


def is_allowed_image(filename: str) -> bool:
    if not filename or "." not in filename:
        return False

    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_IMAGE_EXTENSIONS


def save_block_image(file_obj, old_filename: str = "") -> str:
    """Validate an image's size and actual format before storing it."""
    if not file_obj or not file_obj.filename:
        return old_filename or ""

    original_name = secure_filename(file_obj.filename)
    if not is_allowed_image(original_name):
        raise ValueError("Разрешены только изображения: png, jpg, jpeg, webp, gif")

    ext = original_name.rsplit(".", 1)[1].lower()
    file_obj.stream.seek(0, os.SEEK_END)
    image_size = file_obj.stream.tell()
    file_obj.stream.seek(0)
    if not image_size or image_size > MAX_IMAGE_BYTES:
        raise ValueError(f"Изображение должно быть меньше {MAX_IMAGE_BYTES // (1024 * 1024)} МиБ")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(file_obj.stream) as image:
                if image.format != ALLOWED_IMAGE_FORMATS[ext]:
                    raise ValueError("Расширение файла не совпадает с форматом изображения")
                image.verify()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ValueError("Файл не является корректным изображением") from None
    finally:
        file_obj.stream.seek(0)

    new_filename = f"block_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:10]}.{ext}"
    save_path = os.path.join(SAVE_IMAGES_DIR, new_filename)
    try:
        file_obj.save(save_path)
        try:
            os.chmod(save_path, 0o600)
        except OSError:
            pass
    except Exception:
        delete_block_image(new_filename)
        raise
    return new_filename


def delete_block_image(filename: str):
    """
    Удаляет картинку блока, если она есть.
    """
    filename = secure_filename(filename or "")

    if not filename:
        return

    image_path = os.path.join(SAVE_IMAGES_DIR, filename)

    try:
        if os.path.exists(image_path):
            os.remove(image_path)
    except Exception as e:
        log_error1(f"Не удалось удалить изображение {filename}: {e}")


def extract_ping_host(url: str, address: str = "") -> str:
    candidates = [url or "", address or ""]

    for value in candidates:
        value = (value or "").strip()
        if not value:
            continue

        value_for_parse = value
        if not value_for_parse.startswith("http://") and not value_for_parse.startswith("https://"):
            value_for_parse = "http://" + value_for_parse

        try:
            parsed = urlparse(value_for_parse)
            host = parsed.hostname
            if host:
                return host.strip("[]")
        except Exception:
            pass

        cleaned = value.replace("http://", "").replace("https://", "")
        cleaned = cleaned.split("/")[0].split("?")[0].strip()

        if cleaned.startswith("[") and "]" in cleaned:
            return cleaned.split("]")[0].strip("[]")

        if ":" in cleaned:
            return cleaned.split(":")[0]

        if cleaned:
            return cleaned

    return ""


def parse_received_count(output: str, default_count: int, returncode: int) -> int:
    text = output or ""

    patterns = [
        r"Received\s*=\s*(\d+)",
        r"получено\s*=\s*(\d+)",
        r"Получено\s*=\s*(\d+)",
        r"(\d+)\s+received",
        r"(\d+)\s+packets\s+received",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            try:
                return int(match.group(1))
            except Exception:
                return 0

    if returncode == 0:
        return default_count

    return 0


def run_ping(host: str, count: int = PING_COUNT) -> dict:
    """
    ICMP ping оставляем как запасной вариант.
    Для веб-панелей и сервисов с портом основной тест ниже: HTTP/TCP.
    """
    host = (host or "").strip()

    if not host:
        return {
            "status": "inactive",
            "received": 0,
            "total": count,
            "result": f"OFFLINE 0/{count}",
        }

    system_name = platform.system().lower()

    if "windows" in system_name:
        cmd = ["ping", "-n", str(count), "-w", "1000", host]
        timeout_seconds = count + 4
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", host]
        timeout_seconds = count + 4

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout_seconds,
        )

        output = f"{completed.stdout}\n{completed.stderr}"
        received = parse_received_count(output, count, completed.returncode)
        is_active = received > 0
        status = "active" if is_active else "inactive"
        label = "PING OK" if is_active else "OFFLINE"

        return {
            "status": status,
            "received": received,
            "total": count,
            "result": f"{label} {received}/{count}",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "inactive",
            "received": 0,
            "total": count,
            "result": f"OFFLINE 0/{count}",
        }
    except Exception as e:
        log_error1(f"Ping error для host={host}: {e}")
        return {
            "status": "inactive",
            "received": 0,
            "total": count,
            "result": f"OFFLINE 0/{count}",
        }


def get_target_parts(url: str, address: str = "") -> dict:
    """
    Возвращает host/port/scheme для проверки.
    Пример: http://192.168.8.9:8080 -> host=192.168.8.9, port=8080, scheme=http
    """
    raw_value = (url or address or "").strip()
    normalized = normalize_target_to_url(raw_value)

    try:
        parsed = urlparse(normalized)
        host = parsed.hostname or extract_ping_host(normalized, address)
        port = parsed.port
        scheme = parsed.scheme or "http"

        if port is None:
            if scheme == "https":
                port = 443
            elif scheme == "http":
                port = 80

        return {
            "url": normalized,
            "host": (host or "").strip("[]"),
            "port": port,
            "scheme": scheme,
        }
    except Exception as e:
        log_error1(f"Ошибка разбора адреса {raw_value}: {e}")
        return {
            "url": normalized,
            "host": extract_ping_host(normalized, address),
            "port": None,
            "scheme": "http",
        }


def run_http_check(url: str, count: int = PING_COUNT) -> int:
    """
    HTTP/curl-подобная проверка без внешней библиотеки requests.
    401/403/404 тоже считаем живым ответом: сервер ответил, значит сервис есть.
    """
    success_count = 0

    for _ in range(count):
        try:
            request_obj = urllib.request.Request(
                url,
                method="HEAD",
                headers={"User-Agent": "MSB-Quick-Access-HealthCheck/1.0"},
            )

            with urllib.request.urlopen(request_obj, timeout=NETWORK_CHECK_TIMEOUT_SECONDS) as response:
                if 100 <= int(response.status) < 600:
                    success_count += 1
        except urllib.error.HTTPError:
            # Сервер ответил кодом ошибки — это всё равно значит, что HTTP-сервис живой.
            success_count += 1
        except Exception:
            # Некоторые панели не любят HEAD, пробуем GET.
            try:
                request_obj = urllib.request.Request(
                    url,
                    method="GET",
                    headers={"User-Agent": "MSB-Quick-Access-HealthCheck/1.0"},
                )
                with urllib.request.urlopen(request_obj, timeout=NETWORK_CHECK_TIMEOUT_SECONDS) as response:
                    if 100 <= int(response.status) < 600:
                        success_count += 1
            except urllib.error.HTTPError:
                success_count += 1
            except Exception:
                pass

    return success_count


def run_tcp_check(host: str, port: int, count: int = PING_COUNT) -> int:
    """
    TCP-проверка порта. Это лучше ping для сервисов типа Adminer, Pritunl, PostgreSQL UI.
    Если порт открыт — блок ONLINE, даже если ICMP ping запрещён firewall'ом.
    """
    success_count = 0

    for _ in range(count):
        try:
            with socket.create_connection((host, int(port)), timeout=NETWORK_CHECK_TIMEOUT_SECONDS):
                success_count += 1
        except Exception:
            pass

    return success_count


def run_service_check(url: str, address: str = "", count: int = PING_COUNT) -> dict:
    """
    Главная проверка блока:
    1) HTTP/HTTPS как curl-тест.
    2) Если HTTP не прошёл — TCP connect на порт.
    3) Если порта нет — обычный ping.
    """
    parts = get_target_parts(url, address)
    host = parts["host"]
    port = parts["port"]
    normalized_url = parts["url"]

    if not host:
        return {
            "status": "inactive",
            "host": "",
            "received": 0,
            "total": count,
            "result": f"OFFLINE 0/{count}",
        }

    # Если есть порт, сначала проверяем как веб-сервис.
    if port:
        http_success = run_http_check(normalized_url, count)
        if http_success > 0:
            return {
                "status": "active",
                "host": host,
                "received": http_success,
                "total": count,
                "result": f"HTTP OK {http_success}/{count}",
            }

        tcp_success = run_tcp_check(host, int(port), count)
        if tcp_success > 0:
            return {
                "status": "active",
                "host": host,
                "received": tcp_success,
                "total": count,
                "result": f"TCP OPEN {tcp_success}/{count}",
            }

        return {
            "status": "inactive",
            "host": host,
            "received": 0,
            "total": count,
            "result": f"PORT CLOSED 0/{count}",
        }

    # Если порта нет — только тогда ping.
    ping_data = run_ping(host, count)
    ping_data["host"] = host
    return ping_data


def auto_ping_all_apps():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, name, url, address FROM apps ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()

        if not rows:
            return

        max_workers = min(PING_WORKERS, max(1, len(rows)))
        tasks = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for row in rows:
                tasks.append((row, executor.submit(run_service_check, row["url"], row["address"], PING_COUNT)))

            results = []
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            for row, future in tasks:
                try:
                    check_data = future.result()
                except Exception as e:
                    log_error1(f"Future check error для ID={row['id']}: {e}")
                    check_data = {
                        "status": "inactive",
                        "host": extract_ping_host(row["url"], row["address"]),
                        "received": 0,
                        "total": PING_COUNT,
                        "result": f"OFFLINE 0/{PING_COUNT}",
                    }

                results.append((
                    check_data["status"],
                    now,
                    check_data.get("host") or extract_ping_host(row["url"], row["address"]),
                    check_data["result"],
                    check_data["received"],
                    check_data["total"],
                    row["id"],
                    row["name"],
                ))

        conn = get_db()
        cur = conn.cursor()

        for status, now, host, result_text, received, total, app_id, name in results:
            cur.execute("""
                UPDATE apps
                SET status = ?,
                    last_checked = ?,
                    ping_host = ?,
                    ping_result = ?,
                    ping_success_count = ?,
                    ping_total_count = ?
                WHERE id = ?
            """, (status, now, host, result_text, received, total, app_id))
            log_success1(f"CHECK {name} [{host}] -> {result_text}")

        conn.commit()
        conn.close()
    except Exception as e:
        log_error(f"Ошибка auto_ping_all_apps: {e}")


def _run_background_status_refresh():
    """Выполняет полную проверку сервисов вне HTTP-запроса пользователя."""
    auto_ping_all_apps()


def _finish_background_status_refresh(future):
    """Освобождает состояние фоновой задачи после её завершения."""
    global _status_refresh_future

    try:
        future.result()
    except Exception as e:
        log_error(f"Ошибка фонового обновления статусов: {e}")
    finally:
        with _status_refresh_lock:
            if _status_refresh_future is future:
                _status_refresh_future = None


def schedule_auto_ping_all_apps(force: bool = False) -> bool:
    """
    Запускает проверку всех сервисов в фоне и сразу возвращает управление.

    Защита:
    - одновременно работает только одна полная проверка;
    - обычный запуск выполняется не чаще заданного интервала;
    - force=True игнорирует интервал, но не запускает дубликат текущей задачи.
    """
    global _status_refresh_future
    global _status_refresh_last_started

    now = time.monotonic()

    with _status_refresh_lock:
        if (
            _status_refresh_future is not None
            and not _status_refresh_future.done()
        ):
            return False

        if (
            not force
            and now - _status_refresh_last_started
            < STATUS_REFRESH_INTERVAL_SECONDS
        ):
            return False

        _status_refresh_last_started = now
        future = _status_refresh_executor.submit(
            _run_background_status_refresh
        )
        _status_refresh_future = future

    # add_done_callback invokes the callback immediately if the future is already
    # finished. Registering it under _status_refresh_lock would deadlock here.
    future.add_done_callback(_finish_background_status_refresh)
    log_success1("Фоновое обновление статусов запущено")
    return True


# --------------------------------------------------------------------------------------
# ROUTES
# --------------------------------------------------------------------------------------
@app.route("/")
def dashboard():
    search = request.args.get("search", "").strip()
    requested_category = request.args.get("category")
    category_all = "__all__"
    category_uncategorized = "__uncategorized__"
    session_key = "msb_quick_access_selected_category"
    session.permanent = True

    if requested_category is not None:
        selected_category = requested_category.strip() or category_all
        session[session_key] = selected_category
    else:
        selected_category = str(session.get(session_key, category_all)).strip() or category_all

    # Не ждём HTTP/TCP/ping-проверки: страница отдаётся сразу,
    # а статусы обновляются в отдельном фоновом потоке.
    schedule_auto_ping_all_apps()

    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT
                TRIM(COALESCE(app_type, '')) AS category_name,
                COUNT(*) AS category_count
            FROM apps
            GROUP BY TRIM(COALESCE(app_type, ''))
            ORDER BY
                CASE WHEN TRIM(COALESCE(app_type, '')) = '' THEN 1 ELSE 0 END,
                LOWER(TRIM(COALESCE(app_type, ''))) ASC
        """)
        category_rows = cur.fetchall()

        categories = [{
            "value": category_all,
            "label": "Все категории",
            "count": sum(int(row["category_count"] or 0) for row in category_rows),
        }]
        available_category_values = {category_all}

        for row in category_rows:
            category_name = (row["category_name"] or "").strip()
            category_count = int(row["category_count"] or 0)

            if category_name:
                categories.append({
                    "value": category_name,
                    "label": category_name,
                    "count": category_count,
                })
                available_category_values.add(category_name)
            else:
                categories.append({
                    "value": category_uncategorized,
                    "label": "Без категории",
                    "count": category_count,
                })
                available_category_values.add(category_uncategorized)

        if selected_category not in available_category_values:
            selected_category = category_all
            session[session_key] = category_all

        where_parts = []
        query_params = []

        if search:
            search_pattern = f"%{search}%"
            where_parts.append("""
                (
                    name LIKE ?
                    OR url LIKE ?
                    OR address LIKE ?
                    OR ping_host LIKE ?
                    OR app_type LIKE ?
                    OR description LIKE ?
                    OR launch_info LIKE ?
                )
            """)
            query_params.extend([search_pattern] * 7)

        if selected_category == category_uncategorized:
            where_parts.append("TRIM(COALESCE(app_type, '')) = ''")
        elif selected_category != category_all:
            where_parts.append("TRIM(COALESCE(app_type, '')) = ?")
            query_params.append(selected_category)

        apps_sql = "SELECT * FROM apps"
        if where_parts:
            apps_sql += " WHERE " + " AND ".join(where_parts)
        apps_sql += " ORDER BY order_index ASC, id ASC"

        cur.execute(apps_sql, tuple(query_params))
        apps = cur.fetchall()

        # Only deliberately selected credentials for the pinned HTTPS login
        # page become auto-login cards. Passwords are never fetched here.
        cur.execute("SELECT app_id FROM app_credentials WHERE auto_login = 1")
        marked_ids = {int(row["app_id"]) for row in cur.fetchall()}
        vault_enabled = get_vault_config()["enabled"]
        auto_login_ids = {
            int(item["id"]) for item in apps
            if vault_enabled and int(item["id"]) in marked_ids
            and is_supported_login_url(item["url"])
        }

        cur.execute("SELECT COUNT(*) AS total FROM apps")
        total_apps = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) AS active FROM apps WHERE status = 'active'")
        active_apps = cur.fetchone()["active"]

        cur.execute("SELECT COUNT(*) AS inactive FROM apps WHERE status = 'inactive'")
        inactive_apps = cur.fetchone()["inactive"]

        conn.close()

        vault_unlocked = vault_enabled and is_vault_logged_in()
        return render_template(
            "dashboard.html",
            apps=apps,
            auto_login_ids=auto_login_ids,
            vault_autologin_csrf=get_vault_csrf_token() if vault_unlocked else "",
            search=search,
            categories=categories,
            selected_category=selected_category,
            total_apps=total_apps,
            active_apps=active_apps,
            inactive_apps=inactive_apps,
            ping_count=PING_COUNT,
        )
    except Exception as e:
        log_error(f"Ошибка dashboard: {e}")
        flash("Ошибка панели", "error")
        return render_template(
            "dashboard.html",
            apps=[],
            auto_login_ids=set(),
            vault_autologin_csrf="",
            search=search,
            categories=[{"value": category_all, "label": "Все категории", "count": 0}],
            selected_category=category_all,
            total_apps=0,
            active_apps=0,
            inactive_apps=0,
            ping_count=PING_COUNT,
        )


@app.route("/add", methods=["GET", "POST"])
def add_app():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        target = request.form.get("target", "").strip()
        app_type = request.form.get("app_type", "").strip()
        description = request.form.get("description", "").strip()
        launch_info = request.form.get("launch_info", "").strip()
        image_file = request.files.get("image")

        if not name or not target:
            log_error1("Попытка добавить приложение без name или target")
            flash("Заполни название и IP/порт", "error")
            return redirect(url_for("dashboard"))

        try:
            url = normalize_target_to_url(target)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("dashboard"))
        address = get_address_from_url(url)
        ping_host = extract_ping_host(url, address)

        try:
            image_filename = save_block_image(image_file)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("dashboard"))

        conn = None
        try:
            conn = get_db()
            cur = conn.cursor()

            cur.execute("SELECT COALESCE(MAX(order_index), 0) AS max_order FROM apps")
            next_order = int(cur.fetchone()["max_order"] or 0) + 1

            cur.execute("""
                INSERT INTO apps (
                    code, name, url, address, app_type, description, launch_info, image_filename,
                    status, created_at, open_count,
                    ping_host, ping_result, ping_success_count, ping_total_count, order_index
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "",
                name,
                url,
                address,
                app_type,
                description,
                launch_info,
                image_filename,
                "inactive",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                0,
                ping_host,
                f"WAIT 0/{PING_COUNT}",
                0,
                PING_COUNT,
                next_order,
            ))

            conn.commit()
            conn.close()
            conn = None

            log_success(f"Добавлено приложение: {name} -> {url}")
            if is_supported_login_url(url):
                flash("Добавлено. Для автовхода сохраните логин/пароль через 🔐 на карточке и подключите расширение.", "success")
            else:
                flash("Добавлено", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            if conn is not None:
                conn.rollback()
                conn.close()
            delete_block_image(image_filename)
            log_error(f"Ошибка добавления приложения: {e}")
            flash("Не добавилось", "error")
            return redirect(url_for("dashboard"))

    return render_template("app_form.html", mode="add", app_item=None)

@app.route("/edit/<int:app_id>", methods=["GET", "POST"])
def edit_app(app_id):
    conn = None
    new_image_filename = ""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app_item = cur.fetchone()

        if not app_item:
            conn.close()
            flash("Не найдено", "error")
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            target = request.form.get("target", "").strip()
            app_type = request.form.get("app_type", "").strip()
            description = request.form.get("description", "").strip()
            launch_info = request.form.get("launch_info", "").strip()
            image_file = request.files.get("image")
            remove_image = request.form.get("remove_image") == "1"

            if not name or not target:
                conn.close()
                flash("Заполни название и IP/порт", "error")
                return redirect(url_for("edit_app", app_id=app_id))

            try:
                url = normalize_target_to_url(target)
            except ValueError as e:
                conn.close()
                flash(str(e), "error")
                return redirect(url_for("edit_app", app_id=app_id))
            address = get_address_from_url(url)
            ping_host = extract_ping_host(url, address)

            old_image_filename = app_item["image_filename"] if "image_filename" in app_item.keys() else ""
            image_filename = old_image_filename

            try:
                if remove_image:
                    image_filename = ""
                elif image_file and image_file.filename:
                    new_image_filename = save_block_image(image_file)
                    image_filename = new_image_filename
            except ValueError as e:
                conn.close()
                flash(str(e), "error")
                return redirect(url_for("edit_app", app_id=app_id))

            cur.execute("""
                UPDATE apps
                SET name = ?,
                    url = ?,
                    address = ?,
                    app_type = ?,
                    description = ?,
                    launch_info = ?,
                    image_filename = ?,
                    status = 'inactive',
                    ping_host = ?,
                    ping_result = ?,
                    ping_success_count = 0,
                    ping_total_count = ?
                WHERE id = ?
            """, (
                name,
                url,
                address,
                app_type,
                description,
                launch_info,
                image_filename,
                ping_host,
                f"WAIT 0/{PING_COUNT}",
                PING_COUNT,
                app_id,
            ))

            conn.commit()
            conn.close()
            conn = None
            # Never delete the old image before the database transaction succeeds.
            if old_image_filename and image_filename != old_image_filename:
                delete_block_image(old_image_filename)

            log_success(f"Обновлено приложение ID {app_id}: {name} -> {url}")
            flash("Сохранено", "success")
            return redirect(url_for("dashboard"))

        conn.close()
        return render_template("app_form.html", mode="edit", app_item=app_item)

    except Exception as e:
        if conn is not None:
            conn.rollback()
            conn.close()
        if new_image_filename:
            delete_block_image(new_image_filename)
        log_error(f"Ошибка edit_app ID={app_id}: {e}")
        flash("Ошибка", "error")
        return redirect(url_for("dashboard"))


@app.route("/open/<int:app_id>")
def open_app(app_id):
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        app_item = cur.fetchone()

        if not app_item:
            conn.close()
            flash("Не найдено", "error")
            return redirect(url_for("dashboard"))

        destination = normalize_target_to_url(app_item["url"])
        if not destination:
            raise ValueError("Пустой адрес сервиса")
        cur.execute("""
            UPDATE apps
            SET open_count = open_count + 1,
                last_opened = ?
            WHERE id = ?
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), app_id))

        conn.commit()
        conn.close()

        log_success1(f"Открыт блок: {app_item['name']} -> {destination}")
        return redirect(destination)
    except Exception as e:
        log_error(f"Ошибка open_app ID={app_id}: {e}")
        flash("Ошибка открытия", "error")
        return redirect(url_for("dashboard"))


@app.route("/delete/<int:app_id>", methods=["POST"])
def delete_app(app_id):
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT image_filename FROM apps WHERE id = ?", (app_id,))
        app_item = cur.fetchone()
        image_filename = app_item["image_filename"] if app_item else ""

        cur.execute("DELETE FROM apps WHERE id = ?", (app_id,))
        conn.commit()
        conn.close()
        conn = None
        if image_filename:
            delete_block_image(image_filename)

        log_success(f"Удалён блок ID {app_id}")
        flash("Удалено", "success")
        return redirect(url_for("dashboard"))
    except Exception as e:
        if conn is not None:
            conn.rollback()
            conn.close()
        log_error(f"Ошибка delete_app ID={app_id}: {e}")
        flash("Не удалилось", "error")
        return redirect(url_for("dashboard"))


@app.route("/reorder", methods=["POST"])
def reorder_apps():
    """
    Надёжно сохраняет порядок видимых карточек.

    Frontend может отправить полный список, выбранную категорию или результат поиска.
    Невидимые карточки сохраняют свои места, поэтому order_index не дублируется
    и порядок не ломается при фильтрации.
    """
    conn = None

    try:
        payload = request.get_json(silent=True) or {}
        ids = payload.get("ids", [])
        category_scope = str(payload.get("category", "__all__") or "__all__")

        if not isinstance(ids, list) or not ids:
            return jsonify({"ok": False, "error": "empty ids"}), 400

        clean_ids = []
        seen_ids = set()

        for item in ids:
            try:
                app_id = int(item)
            except (TypeError, ValueError):
                continue

            if app_id <= 0 or app_id in seen_ids:
                continue

            seen_ids.add(app_id)
            clean_ids.append(app_id)

        if not clean_ids:
            return jsonify({"ok": False, "error": "bad ids"}), 400

        conn = get_db()
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("""
            SELECT id
            FROM apps
            ORDER BY
                CASE WHEN order_index IS NULL THEN 1 ELSE 0 END,
                order_index ASC,
                id ASC
        """)
        all_ids = [int(row["id"]) for row in cur.fetchall()]
        existing_ids = set(all_ids)
        unknown_ids = [app_id for app_id in clean_ids if app_id not in existing_ids]

        if unknown_ids:
            conn.rollback()
            conn.close()
            conn = None
            return jsonify({
                "ok": False,
                "error": "unknown ids",
                "unknown_ids": unknown_ids,
            }), 409

        submitted_set = set(clean_ids)
        submitted_slots = [
            index
            for index, app_id in enumerate(all_ids)
            if app_id in submitted_set
        ]

        if len(submitted_slots) != len(clean_ids):
            conn.rollback()
            conn.close()
            conn = None
            return jsonify({"ok": False, "error": "order mismatch"}), 409

        merged_ids = list(all_ids)
        for slot_index, app_id in zip(submitted_slots, clean_ids):
            merged_ids[slot_index] = app_id

        cur.executemany(
            "UPDATE apps SET order_index = ? WHERE id = ?",
            [
                (order_index, app_id)
                for order_index, app_id in enumerate(merged_ids, start=1)
            ],
        )

        conn.commit()
        conn.close()
        conn = None

        log_success1(
            f"Порядок карточек сохранён: scope={category_scope}, visible={clean_ids}"
        )
        return jsonify({
            "ok": True,
            "updated": len(merged_ids),
            "visible_order": clean_ids,
        })
    except sqlite3.OperationalError as e:
        if conn is not None:
            try:
                conn.rollback()
                conn.close()
            except Exception:
                pass

        log_error(f"Ошибка блокировки БД reorder_apps: {e}")
        return jsonify({"ok": False, "error": "database busy"}), 503
    except Exception as e:
        if conn is not None:
            try:
                conn.rollback()
                conn.close()
            except Exception:
                pass

        log_error(f"Ошибка reorder_apps: {e}")
        return jsonify({"ok": False, "error": "server error"}), 500


@app.route("/api/status/refresh", methods=["POST"])
def refresh_statuses():
    """Запускает принудительное обновление статусов без ожидания результата."""
    started = schedule_auto_ping_all_apps(force=True)

    return jsonify({
        "ok": True,
        "started": started,
        "message": (
            "Проверка статусов запущена"
            if started
            else "Проверка уже выполняется"
        ),
    })


@app.route("/block-image/<path:filename>")
def block_image(filename):
    filename = secure_filename(filename or "")

    if not filename:
        return "", 404

    return send_from_directory(SAVE_IMAGES_DIR, filename)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "MSB Quick Access Center"})


if __name__ == "__main__":
    # The built-in HTTP server is for local development only. Run Gunicorn behind
    # an HTTPS reverse proxy for access from other devices.
    host = os.environ.get("MSB_QUICK_ACCESS_HOST", "127.0.0.1").strip()
    port = int(os.environ.get("MSB_QUICK_ACCESS_PORT", "5050"))
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("Для доступа по сети используйте Gunicorn за HTTPS-прокси; "
                         "встроенный HTTP-сервер доступен только на localhost")
    if not 1 <= port <= 65535:
        raise SystemExit("MSB_QUICK_ACCESS_PORT должен быть в диапазоне 1–65535")

    log_success(f"Локальный запуск: http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)