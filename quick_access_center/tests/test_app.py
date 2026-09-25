"""End-to-end Flask tests using a fresh temporary database and throwaway secrets."""

from __future__ import annotations

import io
import os
import re
import secrets
import sys
import tempfile
import unittest
from concurrent.futures import Future
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from PIL import Image
from werkzeug.security import generate_password_hash


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


class QuickAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared_dir = tempfile.TemporaryDirectory(prefix="quick-access-tests-")
        cls.env_patch = patch.dict(os.environ, {
            "MSB_QUICK_ACCESS_DATA_DIR": cls.shared_dir.name,
            "MSB_QUICK_ACCESS_LOG_DIR": os.path.join(cls.shared_dir.name, "logs"),
            "MSB_QUICK_ACCESS_SECRET_KEY": secrets.token_urlsafe(48),
            "MSB_QUICK_ACCESS_COOKIE_SECURE": "0",  # local HTTP test_client
            "MAIN_ACCESS_ENABLED": "1",
            "MAIN_ACCESS_USERNAME": "test-admin",
            "MAIN_ACCESS_PASSWORD_HASH": generate_password_hash("example-main-password"),
            "MAIN_ACCESS_ALLOWED_IPS": "127.0.0.1,::1",
            "MAIN_ACCESS_TRUST_PROXY": "0",
            "MAIN_ACCESS_FAILED_DELAY_SECONDS": "0",
            "VAULT_ACCESS_ENABLED": "1",
            "VAULT_ACCESS_USERNAME": "test-vault",
            "VAULT_ACCESS_PASSWORD_HASH": generate_password_hash("example-vault-password"),
            "VAULT_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
            "VAULT_ACCESS_ALLOWED_IPS": "127.0.0.1,::1",
            "VAULT_ACCESS_TRUST_PROXY": "0",
            "VAULT_ACCESS_FAILED_DELAY_SECONDS": "0",
        })
        cls.env_patch.start()
        import app
        from vault_control.blueprint import init_vault_db
        cls.module = app
        cls.init_vault_db = staticmethod(init_vault_db)
        cls.original_schedule = staticmethod(app.schedule_auto_ping_all_apps)
        cls.original_db = app.DB_NAME
        cls.original_images = app.SAVE_IMAGES_DIR

    @classmethod
    def tearDownClass(cls):
        cls.env_patch.stop()
        cls.shared_dir.cleanup()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=self.shared_dir.name)
        folder = Path(self.temp_dir.name)
        self.module.DB_NAME = str(folder / "quick_access.db")
        self.module.SAVE_IMAGES_DIR = str(folder / "images")
        (folder / "images").mkdir()
        self.module.init_db()
        self.init_vault_db()
        self.client = self.module.app.test_client()
        self.disable_background = patch.object(self.module, "schedule_auto_ping_all_apps", return_value=False)
        self.disable_background.start()

    def tearDown(self):
        self.disable_background.stop()
        self.module.DB_NAME = self.original_db
        self.module.SAVE_IMAGES_DIR = self.original_images
        self.temp_dir.cleanup()

    def csrf_from(self, html: str) -> str:
        match = re.search(r'name="csrf_token" value="([^" ]+)"', html)
        self.assertIsNotNone(match, "No CSRF field was rendered")
        return match.group(1)

    def login(self) -> str:
        page = self.client.get("/access-control")
        self.assertEqual(page.status_code, 200)
        token = self.csrf_from(page.get_data(as_text=True))
        response = self.client.post("/access-control/login", data={
            "username": "test-admin", "password": "example-main-password", "csrf_token": token,
        })
        self.assertEqual(response.status_code, 302)
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        return self.csrf_from(dashboard.get_data(as_text=True))

    def add(self, token: str, name: str, url: str, category: str = "Demo") -> int:
        response = self.client.post("/add", data={
            "csrf_token": token, "name": name, "target": url, "app_type": category,
        })
        self.assertEqual(response.status_code, 302)
        with closing(self.module.get_db()) as db:
            return db.execute("SELECT id FROM apps WHERE name = ?", (name,)).fetchone()[0]

    def test_auth_csrf_and_card_crud(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.client.get("/health").status_code, 302)
        self.assertEqual(self.client.post("/access-control/login", data={
            "username": "test-admin", "password": "example-main-password",
        }).status_code, 400)

        token = self.login()
        self.assertEqual(self.client.get("/health").get_json()["status"], "ok")
        self.assertEqual(self.client.post("/add", data={
            "name": "Denied", "target": "https://example.com",
        }).status_code, 400)
        app_id = self.add(token, "Alpha", "https://example.com")
        self.assertIn('value="https://example.com"',
                      self.client.get(f"/edit/{app_id}").get_data(as_text=True))
        self.assertEqual(self.client.post(f"/edit/{app_id}", data={
            "name": "New", "target": "https://example.com",
        }).status_code, 400)
        self.assertEqual(self.client.post(f"/edit/{app_id}", data={
            "csrf_token": token, "name": "New", "target": "https://example.com",
        }).status_code, 302)
        with closing(self.module.get_db()) as db:
            self.assertEqual(db.execute("SELECT url FROM apps WHERE id=?", (app_id,)).fetchone()[0],
                             "https://example.com")

        redirect = self.client.get(f"/open/{app_id}")
        self.assertEqual(redirect.status_code, 302)
        self.assertEqual(redirect.location, "https://example.com")
        self.assertEqual(self.client.post(f"/delete/{app_id}").status_code, 400)
        self.assertEqual(self.client.post(f"/delete/{app_id}", data={
            "csrf_token": token,
        }).status_code, 302)
        with closing(self.module.get_db()) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM apps").fetchone()[0], 0)
        self.assertEqual(self.client.post("/access-control/logout").status_code, 400)
        self.assertEqual(self.client.post("/access-control/logout", data={
            "csrf_token": token,
        }).status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_reorder_and_status_api_require_csrf(self):
        token = self.login()
        first = self.add(token, "First", "https://example.com", "Demo")
        middle = self.add(token, "Middle", "https://example.org", "Other")
        last = self.add(token, "Last", "https://example.net", "Demo")
        self.assertEqual(self.client.post("/reorder", json={"ids": [last, first]}).status_code, 400)
        result = self.client.post("/reorder", json={"ids": [last, first], "category": "Demo"},
                                  headers={"X-CSRF-Token": token})
        self.assertTrue(result.get_json()["ok"])
        with closing(self.module.get_db()) as db:
            self.assertEqual([row[0] for row in db.execute(
                "SELECT id FROM apps ORDER BY order_index")], [last, middle, first])
        self.assertEqual(self.client.post("/api/status/refresh").status_code, 400)
        result = self.client.post("/api/status/refresh", headers={"X-CSRF-Token": token})
        self.assertEqual(result.status_code, 200)
        self.assertFalse(result.get_json()["started"])  # worker patched out, no network

    def test_vault_requires_own_csrf_and_encrypts_fields(self):
        token = self.login()
        app_id = self.add(token, "Vault owner", "https://example.com")
        self.assertEqual(self.client.get(f"/vault/app/{app_id}").status_code, 302)
        login_html = self.client.get("/vault/login").get_data(as_text=True)
        vault_token = self.csrf_from(login_html)
        self.assertEqual(self.client.post("/vault/login", data={
            "username": "test-vault", "password": "example-vault-password",
            "csrf_token": vault_token,
        }).status_code, 302)
        vault_token = self.csrf_from(self.client.get(f"/vault/app/{app_id}").get_data(as_text=True))
        credentials = {"title": "Example", "username": "dummy", "password": "not-a-real-password", "notes": "memo"}
        path = f"/vault/app/{app_id}/credential"
        self.assertEqual(self.client.post(path, data=credentials).status_code, 400)
        self.assertEqual(self.client.post(path, data={**credentials, "csrf_token": vault_token}).status_code, 302)
        with closing(self.module.get_db()) as db:
            entry = db.execute("SELECT password_enc, notes_enc FROM app_credentials").fetchone()
            self.assertNotEqual(entry["password_enc"], credentials["password"])
            self.assertTrue(entry["password_enc"].startswith("gAAAA"))
            self.assertNotEqual(entry["notes_enc"], credentials["notes"])
        self.assertIn(b"not-a-real-password", self.client.get(f"/vault/app/{app_id}").data)
        self.client.post(f"/delete/{app_id}", data={"csrf_token": token})
        with closing(self.module.get_db()) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM app_credentials").fetchone()[0], 0)

    def test_spoofed_proxy_header_cannot_bypass_ip_allowlist(self):
        from access_control.access_settings import reload_access_config
        token = self.login()
        try:
            with patch.dict(os.environ, {
                "MAIN_ACCESS_TRUST_PROXY": "1", "MAIN_ACCESS_TRUSTED_PROXIES": "127.0.0.1",
            }):
                reload_access_config()
                response = self.client.post(
                    "/reorder", json={"ids": [1]}, headers={
                        "X-CSRF-Token": token, "X-Forwarded-For": "127.0.0.1",
                    }, environ_overrides={"REMOTE_ADDR": "203.0.113.42"},
                )
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.get_json()["error"], "access_denied")
        finally:
            reload_access_config()

    def test_image_must_be_real_and_bounded(self):
        token = self.login()
        def upload(payload, filename):
            response = self.client.post("/add", data={
                "csrf_token": token, "name": "Image card", "target": "https://example.com",
                "image": (io.BytesIO(payload), filename),
            }, content_type="multipart/form-data")
            status = response.status_code
            response.close()
            return status

        self.assertEqual(upload(b"not an image", "forged.png"), 302)
        with closing(self.module.get_db()) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM apps").fetchone()[0], 0)
        image = io.BytesIO()
        Image.new("RGB", (2, 2), (12, 24, 36)).save(image, format="PNG")
        self.assertEqual(upload(image.getvalue(), "wrong.jpg"), 302)
        self.assertEqual(upload(image.getvalue(), "valid.png"), 302)
        with closing(self.module.get_db()) as db:
            row = db.execute("SELECT image_filename FROM apps").fetchone()
            self.assertIsNotNone(row)
            filename = row[0]
        image_response = self.client.get("/block-image/" + filename)
        self.assertEqual(image_response.status_code, 200)
        image_response.close()
        # Exercise the request limit without allocating a multi-megabyte test file.
        with patch.dict(self.module.app.config, {"MAX_CONTENT_LENGTH": 1024}):
            self.assertEqual(upload(b"x" * 2048, "oversized.png"), 413)
        with closing(self.module.get_db()) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM apps").fetchone()[0], 1)

    def test_failed_edit_keeps_existing_image(self):
        import sqlite3
        token = self.login()
        image = io.BytesIO()
        Image.new("RGB", (2, 2)).save(image, format="PNG")
        response = self.client.post("/add", data={
            "csrf_token": token, "name": "With image", "target": "https://example.com",
            "image": (io.BytesIO(image.getvalue()), "logo.png"),
        }, content_type="multipart/form-data")
        response.close()
        with closing(self.module.get_db()) as db:
            row = db.execute("SELECT id, image_filename FROM apps").fetchone()
        app_id, old_image = row["id"], row["image_filename"]
        image_path = Path(self.module.SAVE_IMAGES_DIR) / old_image
        self.assertTrue(image_path.exists())

        class BrokenCommit:
            def __init__(self, wrapped):
                self.wrapped = wrapped
            def __getattr__(self, name):
                return getattr(self.wrapped, name)
            def commit(self):
                raise sqlite3.OperationalError("simulated write failure")

        original_get_db = self.module.get_db
        with patch.object(self.module, "get_db", side_effect=lambda: BrokenCommit(original_get_db())):
            self.assertEqual(self.client.post(f"/edit/{app_id}", data={
                "csrf_token": token, "name": "Changed", "target": "https://example.com",
                "remove_image": "1",
            }).status_code, 302)
        self.assertTrue(image_path.exists())
        with closing(self.module.get_db()) as db:
            saved = db.execute("SELECT name, image_filename FROM apps WHERE id=?", (app_id,)).fetchone()
        self.assertEqual((saved["name"], saved["image_filename"]), ("With image", old_image))
        self.assertEqual(self.client.post(f"/edit/{app_id}", data={
            "csrf_token": token, "name": "Changed", "target": "https://example.com",
            "remove_image": "1",
        }).status_code, 302)
        self.assertFalse(image_path.exists())

    def test_only_http_targets_are_accepted(self):
        validate = self.module.normalize_target_to_url
        self.assertEqual(validate("Https://example.com/a"), "https://example.com/a")
        self.assertEqual(validate("127.0.0.1:8080"), "http://127.0.0.1:8080")
        for bad in ("file:///etc/passwd", "javascript:alert(1)", "https://user:pass@example.com",
                    "http://example.com:0", "http://example.com:99999", "/local"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    validate(bad)

    def test_background_status_updates_database(self):
        token = self.login()
        app_id = self.add(token, "Health check", "https://example.com")
        result = {"status": "active", "host": "example.com", "received": 3,
                  "total": 3, "result": "HTTP OK 3/3"}
        with patch.object(self.module, "run_service_check", return_value=result):
            self.assertTrue(self.original_schedule(force=True))
            future = self.module._status_refresh_future
            if future is not None:
                future.result(timeout=5)
        with closing(self.module.get_db()) as db:
            row = db.execute("SELECT status, ping_result FROM apps WHERE id=?", (app_id,)).fetchone()
        self.assertEqual((row["status"], row["ping_result"]), ("active", "HTTP OK 3/3"))

    def test_fast_background_check_cannot_deadlock(self):
        finished = Future()
        finished.set_result(None)
        self.module._status_refresh_last_started = 0.0
        self.module._status_refresh_future = None
        with patch.object(self.module._status_refresh_executor, "submit", return_value=finished):
            self.assertTrue(self.original_schedule(force=True))
        self.assertIsNone(self.module._status_refresh_future)


if __name__ == "__main__":
    unittest.main()
