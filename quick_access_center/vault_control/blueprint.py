# vault_control/blueprint.py
"""Отдельный админ-раздел для зашифрованных логинов и паролей карточек."""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime
from typing import Callable, Optional

from cryptography.fernet import InvalidToken
from flask import (
    Blueprint,
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from vault_control.autologin import (
    canonical_login_url,
    describe_supported_login_urls,
    invalid_login_url_entries,
    is_supported_login_url,
    private_http_allowed,
    supported_login_urls,
)
from vault_control.vault_settings import (
    clear_failed_logins,
    clear_vault_session,
    decrypt_secret,
    encrypt_secret,
    format_seconds,
    get_client_ip,
    get_csrf_token,
    get_fernet,
    get_login_lock_status,
    get_vault_config,
    is_ip_allowed,
    is_safe_next_url,
    is_vault_configured,
    is_vault_logged_in,
    register_failed_login,
    reload_vault_config,
    reset_csrf_token,
    validate_csrf_token,
    vault_login_required,
    verify_vault_login,
)

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


LOG_SOURCE = "vault_control.blueprint"
_GET_DB: Optional[Callable] = None


def _log_success(message: str) -> None:
    _debug_success_print(f"[{LOG_SOURCE}] {message}")


def _log_detail(message: str) -> None:
    _debug_success1_print(f"[{LOG_SOURCE}] {message}")


def _log_warning(message: str) -> None:
    _debug_error1_print(f"[{LOG_SOURCE}] {message}")


def _log_error(message: str) -> None:
    _debug_error_print(f"[{LOG_SOURCE}] {message}")


def _get_db():
    if _GET_DB is None:
        raise RuntimeError("Vault DB callback не подключён")
    return _GET_DB()


def init_vault_db() -> None:
    conn = _get_db()
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys = ON")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id INTEGER NOT NULL,
                title_enc TEXT NOT NULL DEFAULT '',
                username_enc TEXT NOT NULL DEFAULT '',
                password_enc TEXT NOT NULL DEFAULT '',
                notes_enc TEXT NOT NULL DEFAULT '',
                auto_login INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
            )
        """)
        # Existing Vault databases predate the opt-in auto-login flag.
        cur.execute("PRAGMA table_info(app_credentials)")
        if "auto_login" not in {row[1] for row in cur.fetchall()}:
            cur.execute(
                "ALTER TABLE app_credentials ADD COLUMN auto_login INTEGER NOT NULL DEFAULT 0"
            )
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_app_credentials_app_id
            ON app_credentials(app_id)
        """)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_app_credentials_one_auto_login
            ON app_credentials(app_id) WHERE auto_login = 1
        """)
        conn.commit()
        _log_success("Таблица app_credentials готова")
    finally:
        conn.close()


def _get_app(app_id: int):
    conn = _get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM apps WHERE id = ?", (app_id,))
        return cur.fetchone()
    finally:
        conn.close()


def _get_credential(credential_id: int):
    conn = _get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM app_credentials WHERE id = ?", (credential_id,))
        return cur.fetchone()
    finally:
        conn.close()


def _decrypt_credential(row) -> dict:
    return {
        "id": int(row["id"]),
        "app_id": int(row["app_id"]),
        "title": decrypt_secret(row["title_enc"]),
        "username": decrypt_secret(row["username_enc"]),
        "password": decrypt_secret(row["password_enc"]),
        "notes": decrypt_secret(row["notes_enc"]),
        "auto_login": bool(row["auto_login"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _require_csrf():
    if not validate_csrf_token():
        _log_warning(f"CSRF отклонён: ip={get_client_ip()}, path={request.path}")
        abort(400, description="Неверный CSRF-токен")


def _requested_auto_login(app_item, username: str, password: str) -> bool:
    requested = request.form.get("auto_login") == "1"
    if requested and not is_supported_login_url(app_item["url"]):
        abort(400, description="Автовход не разрешён для этой ссылки")
    if requested and (not username or not password):
        abort(400, description="Для автовхода нужны логин и пароль")
    return requested


def _render_login(error_message: str = "", next_url: str = "/vault/", login_value: str = ""):
    config = get_vault_config()
    current_ip = get_client_ip()

    return render_template(
        "vault_control/login.html",
        error_message=error_message,
        next_url=next_url if is_safe_next_url(next_url) else "/vault/",
        login_value=login_value,
        vault_configured=is_vault_configured(config),
        vault_enabled=config["enabled"],
        vault_current_ip=current_ip,
        vault_ip_allowed=is_ip_allowed(current_ip),
        vault_session_minutes=config["session_minutes"],
        csrf_token=get_csrf_token(),
    )


def create_vault_blueprint() -> Blueprint:
    bp = Blueprint(
        "vault_control",
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/vault_static",
        url_prefix="/vault",
    )

    @bp.route("/login", methods=["GET", "POST"])
    def vault_login():
        config = get_vault_config()
        current_ip = get_client_ip()
        next_url = request.values.get("next", "/vault/").strip() or "/vault/"

        if not config["enabled"]:
            abort(404)

        if request.method == "GET":
            if is_vault_logged_in():
                return redirect(next_url if is_safe_next_url(next_url) else url_for("vault_control.vault_index"))

            return _render_login(
                error_message=request.args.get("error", "").strip(),
                next_url=next_url,
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Для страницы входа не отдаём технический abort(400): устаревшая
        # вкладка или cookie должны показать понятное сообщение в той же форме.
        if not validate_csrf_token():
            reset_csrf_token()
            _log_warning(
                f"Vault login CSRF обновлён: ip={current_ip}, username={username or 'empty'}"
            )
            return _render_login(
                error_message=(
                    "Форма входа устарела или была открыта до перезапуска сервиса. "
                    "Токен обновлён — введите пароль ещё раз."
                ),
                next_url=next_url,
                login_value=username,
            )

        if not is_vault_configured(config):
            return _render_login(
                error_message="Хранилище ещё не настроено. Выполните python vault_control/setup_vault.py.",
                next_url=next_url,
                login_value=username,
            )

        if not is_ip_allowed(current_ip):
            _log_warning(f"Vault login запрещён по IP: ip={current_ip}, username={username}")
            return _render_login(
                error_message=f"Ваш IP не разрешён для хранилища: {current_ip}",
                next_url=next_url,
                login_value=username,
            )

        lock_status = get_login_lock_status(username, current_ip)
        if lock_status["locked"]:
            return _render_login(
                error_message=(
                    "Слишком много неправильных попыток. "
                    f"Повторите через {format_seconds(lock_status['remaining_seconds'])}"
                ),
                next_url=next_url,
                login_value=username,
            )

        if verify_vault_login(username, password):
            clear_failed_logins(username, current_ip)
            clear_vault_session()
            now = time.time()
            session.permanent = True
            session["vault_logged_in"] = True
            session["vault_user"] = username
            session["vault_login_at"] = str(now)
            session["vault_last_activity"] = str(now)
            session["vault_ip"] = current_ip
            reset_csrf_token()
            session.modified = True

            _log_success(f"Vault login OK: ip={current_ip}, username={username}")
            return redirect(next_url if is_safe_next_url(next_url) else url_for("vault_control.vault_index"))

        failed_info = register_failed_login(username, current_ip)
        delay_seconds = int(config.get("failed_delay_seconds", 1))
        if delay_seconds:
            time.sleep(delay_seconds)

        _log_warning(
            "Vault login failed: "
            f"ip={current_ip}, username={username}, "
            f"remaining={failed_info['remaining_attempts']}, locked={failed_info['locked']}"
        )

        if failed_info["locked"]:
            error_message = (
                "Слишком много неправильных попыток. "
                f"Доступ заблокирован на {format_seconds(failed_info['remaining_seconds'])}"
            )
        else:
            error_message = (
                "Неверный отдельный логин или пароль. "
                f"Осталось попыток: {failed_info['remaining_attempts']}"
            )

        return _render_login(
            error_message=error_message,
            next_url=next_url,
            login_value=username,
        )

    @bp.route("/logout", methods=["POST"])
    def vault_logout():
        _require_csrf()
        current_ip = get_client_ip()
        username = session.get("vault_user", "unknown")
        clear_vault_session()
        _log_detail(f"Vault logout: ip={current_ip}, username={username}")
        return redirect(url_for("vault_control.vault_login"))

    @bp.route("/")
    @vault_login_required
    def vault_index():
        search = request.args.get("search", "").strip()
        conn = _get_db()
        try:
            cur = conn.cursor()
            params = []
            where_sql = ""
            if search:
                where_sql = "WHERE a.name LIKE ? OR a.url LIKE ? OR a.address LIKE ? OR a.app_type LIKE ?"
                pattern = f"%{search}%"
                params = [pattern, pattern, pattern, pattern]

            cur.execute(
                f"""
                SELECT
                    a.id,
                    a.name,
                    a.url,
                    a.address,
                    a.app_type,
                    a.image_filename,
                    COUNT(c.id) AS credential_count
                FROM apps a
                LEFT JOIN app_credentials c ON c.app_id = a.id
                {where_sql}
                GROUP BY a.id
                ORDER BY a.order_index ASC, a.id ASC
                """,
                tuple(params),
            )
            apps = cur.fetchall()
        finally:
            conn.close()

        return render_template(
            "vault_control/index.html",
            apps=apps,
            search=search,
            csrf_token=get_csrf_token(),
            vault_user=session.get("vault_user", ""),
            autologin_urls=supported_login_urls(),
            autologin_invalid=invalid_login_url_entries(),
            autologin_private_http=private_http_allowed(),
        )

    @bp.route("/app/<int:app_id>")
    @vault_login_required
    def app_vault(app_id: int):
        app_item = _get_app(app_id)
        if not app_item:
            abort(404)

        edit_id = request.args.get("edit", type=int)
        conn = _get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM app_credentials WHERE app_id = ? ORDER BY id ASC",
                (app_id,),
            )
            credential_rows = cur.fetchall()
        finally:
            conn.close()

        credentials = [_decrypt_credential(row) for row in credential_rows]
        edit_credential = next((item for item in credentials if item["id"] == edit_id), None)

        return render_template(
            "vault_control/app_vault.html",
            app_item=app_item,
            credentials=credentials,
            edit_credential=edit_credential,
            auto_login_supported=is_supported_login_url(app_item["url"]),
            auto_login_urls=describe_supported_login_urls(),
            csrf_token=get_csrf_token(),
            vault_user=session.get("vault_user", ""),
        )

    @bp.route("/app/<int:app_id>/autologin", methods=["POST"])
    @vault_login_required
    def autologin_credential(app_id: int):
        """Release only the explicitly selected credential for a pinned login URL.

        The browser extension requests this with the existing Vault session and
        Vault CSRF token. Never put a password in a redirect, query string or log.
        """
        _require_csrf()
        conn = _get_db()
        try:
            app_item = conn.execute("SELECT url FROM apps WHERE id = ?", (app_id,)).fetchone()
            if not app_item:
                abort(404)
            if not is_supported_login_url(app_item["url"]):
                return jsonify({"ok": False, "error": "unsupported_target"}), 409
            # Canonical form of the card's own allowlisted URL: the extension
            # opens exactly this page and nothing derived from it.
            login_url = canonical_login_url(app_item["url"])

            row = conn.execute(
                """SELECT username_enc, password_enc FROM app_credentials
                   WHERE app_id = ? AND auto_login = 1""",
                (app_id,),
            ).fetchone()
            if not row or not row["username_enc"] or not row["password_enc"]:
                return jsonify({"ok": False, "error": "not_enabled"}), 409

            try:
                cipher = get_fernet()
                username = cipher.decrypt(row["username_enc"].encode("utf-8")).decode("utf-8")
                password = cipher.decrypt(row["password_enc"].encode("utf-8")).decode("utf-8")
            except (InvalidToken, UnicodeError, ValueError, RuntimeError):
                _log_warning(f"Запись для автовхода повреждена: app_id={app_id}")
                return jsonify({"ok": False, "error": "credential_unavailable"}), 409

            if not username or not password:
                return jsonify({"ok": False, "error": "credential_unavailable"}), 409

            conn.execute(
                """UPDATE apps SET open_count = open_count + 1, last_opened = ?
                   WHERE id = ?""",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), app_id),
            )
            conn.commit()
            return jsonify({
                "ok": True,
                "login_url": login_url,
                "username": username,
                "password": password,
            })
        finally:
            conn.close()

    @bp.route("/app/<int:app_id>/credential", methods=["POST"])
    @vault_login_required
    def create_credential(app_id: int):
        _require_csrf()
        app_item = _get_app(app_id)
        if not app_item:
            abort(404)

        title = request.form.get("title", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        notes = request.form.get("notes", "").strip()

        if not title:
            flash("Укажите название доступа", "error")
            return redirect(url_for("vault_control.app_vault", app_id=app_id))

        auto_login = _requested_auto_login(app_item, username, password)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = _get_db()
        try:
            cur = conn.cursor()
            if auto_login:
                cur.execute("UPDATE app_credentials SET auto_login = 0 WHERE app_id = ?", (app_id,))
            cur.execute(
                """
                INSERT INTO app_credentials (
                    app_id, title_enc, username_enc, password_enc, notes_enc,
                    auto_login, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app_id,
                    encrypt_secret(title),
                    encrypt_secret(username),
                    encrypt_secret(password),
                    encrypt_secret(notes),
                    int(auto_login),
                    now,
                    now,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        _log_success(f"Vault credential добавлен: app_id={app_id}")
        flash("Доступ сохранён в зашифрованном виде", "success")
        return redirect(url_for("vault_control.app_vault", app_id=app_id))

    @bp.route("/credential/<int:credential_id>/edit", methods=["POST"])
    @vault_login_required
    def update_credential(credential_id: int):
        _require_csrf()
        row = _get_credential(credential_id)
        if not row:
            abort(404)

        app_id = int(row["app_id"])
        app_item = _get_app(app_id)
        if not app_item:
            abort(404)
        title = request.form.get("title", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        notes = request.form.get("notes", "").strip()

        if not title:
            flash("Укажите название доступа", "error")
            return redirect(url_for("vault_control.app_vault", app_id=app_id, edit=credential_id))

        auto_login = _requested_auto_login(app_item, username, password)
        conn = _get_db()
        try:
            cur = conn.cursor()
            if auto_login:
                cur.execute("UPDATE app_credentials SET auto_login = 0 WHERE app_id = ?", (app_id,))
            cur.execute(
                """
                UPDATE app_credentials
                SET title_enc = ?, username_enc = ?, password_enc = ?, notes_enc = ?,
                    auto_login = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    encrypt_secret(title),
                    encrypt_secret(username),
                    encrypt_secret(password),
                    encrypt_secret(notes),
                    int(auto_login),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    credential_id,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        _log_success(f"Vault credential обновлён: credential_id={credential_id}, app_id={app_id}")
        flash("Доступ обновлён", "success")
        return redirect(url_for("vault_control.app_vault", app_id=app_id))

    @bp.route("/credential/<int:credential_id>/delete", methods=["POST"])
    @vault_login_required
    def delete_credential(credential_id: int):
        _require_csrf()
        row = _get_credential(credential_id)
        if not row:
            abort(404)

        app_id = int(row["app_id"])
        conn = _get_db()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM app_credentials WHERE id = ?", (credential_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        _log_success(f"Vault credential удалён: credential_id={credential_id}, app_id={app_id}")
        flash("Доступ удалён", "success")
        return redirect(url_for("vault_control.app_vault", app_id=app_id))

    return bp


def init_vault_control(app: Flask, get_db_callback: Callable) -> None:
    global _GET_DB
    _GET_DB = get_db_callback

    config = reload_vault_config(log=True)
    init_vault_db()
    app.config["SESSION_REFRESH_EACH_REQUEST"] = True
    app.register_blueprint(create_vault_blueprint())

    if not is_vault_configured(config):
        _log_warning(
            "Хранилище подключено, но отдельный пароль/ключ ещё не созданы. "
            "Выполните: python vault_control/setup_vault.py"
        )
    else:
        _log_success("Отдельное админ-хранилище паролей подключено")
