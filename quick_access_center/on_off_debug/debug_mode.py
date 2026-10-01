#_on_off_debug/debug_mode.py
import os
import sys
from datetime import datetime

# Настройки отладки
DEBUG_SUCCESS_MODE = True
DEBUG_SUCCESS1_MODE = True
DEBUG_ERROR_MODE = True
DEBUG_ERROR1_MODE = True
DEBUG_UNICODE_MODE = True

# Paths are stable regardless of the current working directory. Local data can
# be relocated with MSB_QUICK_ACCESS_DATA_DIR (or logs separately with LOG_DIR).
BASE_LOG_DIR = os.path.abspath(os.path.expanduser(
    os.environ.get("MSB_QUICK_ACCESS_LOG_DIR") or os.path.join(
        os.environ.get("MSB_QUICK_ACCESS_DATA_DIR")
        or os.path.dirname(os.path.abspath(__file__)),
        "logs" if os.environ.get("MSB_QUICK_ACCESS_DATA_DIR") else "log_folder",
    )
))


def write_log(subfolder: str, filename: str, message: str):
    """Записывает сообщение в лог-файл в UTF-8."""
    today = datetime.now().strftime("%d.%m.%Y")
    log_dir = os.path.join(BASE_LOG_DIR, subfolder, today)
    try:
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        log_path = os.path.join(log_dir, filename)
        with open(log_path, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except OSError as error:
        print(f"Log write failed: {error}", file=sys.stderr)


def log_unicode(msg: str) -> None:
    """Пишет строку msg в stderr напрямую в UTF-8."""
    if not DEBUG_UNICODE_MODE:
        return

    try:
        sys.stderr.buffer.write(msg.encode("utf-8"))
        sys.stderr.buffer.write(b"\n")
    except Exception:
        print(msg)


def debug_success_print(message):
    """Печатает и логирует сообщение об успехе."""
    if DEBUG_SUCCESS_MODE:
        print(f"[SUCCESS] {message}")
        write_log("success_print", "s_log.log", str(message))


def debug_success1_print(message):
    """Печатает и логирует сообщение об успехе 1."""
    if DEBUG_SUCCESS1_MODE:
        print(f"[SUCCESS1] {message}")
        write_log("success1_print", "s1_log.log", str(message))


def debug_error_print(message):
    """Печатает и логирует сообщение об ошибке."""
    if DEBUG_ERROR_MODE:
        print(f"[ERROR] {message}")
        write_log("error_print", "e_log.log", str(message))


def debug_error1_print(message: str):
    """Печатает и логирует сообщение об ошибке 1."""
    if DEBUG_ERROR1_MODE:
        print(f"[ERROR1] {message}")
        write_log("error1_print", "e1_log.log", str(message))


def set_debug_mode(
    success: bool = True,
    success1: bool = True,
    error: bool = True,
    error1: bool = True,
    unicode_log: bool = True,
):
    """Устанавливает режимы отладки."""
    global DEBUG_SUCCESS_MODE, DEBUG_SUCCESS1_MODE, DEBUG_ERROR_MODE, DEBUG_ERROR1_MODE, DEBUG_UNICODE_MODE

    DEBUG_SUCCESS_MODE = success
    DEBUG_SUCCESS1_MODE = success1
    DEBUG_ERROR_MODE = error
    DEBUG_ERROR1_MODE = error1
    DEBUG_UNICODE_MODE = unicode_log
