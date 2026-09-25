"""Pure security helpers and first-run setup, without production secrets."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from werkzeug.security import check_password_hash

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from client_address import resolve_client_ip
from access_control import setup_access
from vault_control import setup_vault


class ProxyTests(unittest.TestCase):
    def test_forged_headers_are_ignored_for_direct_clients(self):
        self.assertEqual(resolve_client_ip(
            "203.0.113.42", "127.0.0.1", "127.0.0.1",
            trust_proxy=True, trusted_proxies=["127.0.0.1", "::1"],
        ), "203.0.113.42")

    def test_rightmost_untrusted_hop_wins(self):
        self.assertEqual(resolve_client_ip(
            "127.0.0.1", "127.0.0.1, 198.51.100.7, 10.0.0.9",
            trust_proxy=True, trusted_proxies=["127.0.0.1", "10.0.0.0/24"],
        ), "198.51.100.7")
        self.assertEqual(resolve_client_ip(
            "127.0.0.1", "127.0.0.1, invalid",
            trust_proxy=True, trusted_proxies=["127.0.0.1"],
        ), "unknown")
        self.assertEqual(resolve_client_ip(
            "127.0.0.1", trust_proxy=True, trusted_proxies=["127.0.0.1"],
        ), "unknown")


class SetupTests(unittest.TestCase):
    def test_first_run_hashes_main_password_and_preserves_session_key(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "access.env"
            with patch.object(setup_access, "ENV_PATH", target):
                with patch("builtins.input", return_value=""), patch(
                    "getpass.getpass", side_effect=["example-long-password", "example-long-password"]
                ):
                    setup_access.main()
                data = dict(line.split("=", 1) for line in target.read_text().splitlines()
                            if "=" in line and not line.startswith("#"))
                self.assertTrue(check_password_hash(data["MAIN_ACCESS_PASSWORD_HASH"], "example-long-password"))
                self.assertGreaterEqual(len(data["MAIN_ACCESS_SECRET_KEY"]), 40)
                self.assertNotIn("MAIN_ACCESS_PASSWORD", data)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                first_key = data["MAIN_ACCESS_SECRET_KEY"]
                with patch("builtins.input", side_effect=["yes", "renamed-admin"]), patch(
                    "getpass.getpass", side_effect=["another-long-password", "another-long-password"]
                ):
                    setup_access.main()
                self.assertIn("MAIN_ACCESS_SECRET_KEY=" + first_key, target.read_text())

    def test_vault_first_run_and_rotation_keep_encryption_key(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "vault.env"
            with patch.dict(os.environ, {"MSB_QUICK_ACCESS_DATA_DIR": temp}), patch.object(
                setup_vault, "ENV_PATH", target
            ):
                with patch("builtins.input", return_value=""), patch(
                    "getpass.getpass", side_effect=["example-vault-password", "example-vault-password"]
                ):
                    setup_vault.main()
                data = dict(line.split("=", 1) for line in target.read_text().splitlines()
                            if "=" in line and not line.startswith("#"))
                original_key = data["VAULT_ENCRYPTION_KEY"]
                Fernet(original_key.encode())
                self.assertTrue(check_password_hash(data["VAULT_ACCESS_PASSWORD_HASH"], "example-vault-password"))
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                with patch("builtins.input", side_effect=["yes", "new-vault-user"]), patch(
                    "getpass.getpass", side_effect=["another-vault-password", "another-vault-password"]
                ):
                    setup_vault.main()
                self.assertIn("VAULT_ENCRYPTION_KEY=" + original_key, target.read_text())

    def test_vault_refuses_new_key_when_database_contains_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "vault.env"
            db_dir = Path(temp) / "base"
            db_dir.mkdir()
            with sqlite3.connect(db_dir / "quick_access.db") as db:
                db.execute("CREATE TABLE app_credentials(id INTEGER PRIMARY KEY)")
                db.execute("INSERT INTO app_credentials DEFAULT VALUES")
            with patch.dict(os.environ, {"MSB_QUICK_ACCESS_DATA_DIR": temp}), patch.object(
                setup_vault, "ENV_PATH", target
            ):
                with self.assertRaisesRegex(RuntimeError, "В БД есть пароли"):
                    setup_vault.main()
                self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
