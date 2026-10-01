"""Unit tests for the configurable auto-login allowlist (no real credentials)."""

from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from vault_control.autologin import (  # noqa: E402
    ACTIVITY_LOGIN_URL,
    ALLOW_PRIVATE_HTTP_ENV,
    BUILT_IN_LOGIN_URLS,
    EXTRA_LOGIN_URLS_ENV,
    canonical_login_url,
    describe_supported_login_urls,
    invalid_login_url_entries,
    is_private_host,
    is_supported_login_url,
    normalize_login_url,
    parse_extra_login_urls,
    supported_login_urls,
)

CUSTOM_URL = "https://crm.example.com/login"
LAN_URL = "http://192.168.8.81:8085/login"
# The internal HTTP service is built in but inert until its switch is on.
HTTPS_BUILT_INS = tuple(url for url in BUILT_IN_LOGIN_URLS if url.startswith("https://"))


def configured(value: str):
    """Isolate the test from a developer's local vault.env."""
    return patch.dict(os.environ, {EXTRA_LOGIN_URLS_ENV: value})


class NormalizeLoginUrlTests(unittest.TestCase):
    def test_exact_https_login_url_is_accepted(self):
        self.assertEqual(normalize_login_url(CUSTOM_URL), CUSTOM_URL)
        self.assertEqual(normalize_login_url(f"  {CUSTOM_URL}  "), CUSTOM_URL)
        self.assertEqual(normalize_login_url("https://CRM.Example.COM/login"), CUSTOM_URL)
        self.assertEqual(normalize_login_url("https://crm.example.com:443/login"), CUSTOM_URL)

    def test_downgrades_wildcards_and_unparsable_values_are_rejected(self):
        for raw in [
            "",
            None,
            "crm.example.com/login",
            "http://crm.example.com/login",
            "https://crm.example.com/login?next=/admin",
            "https://crm.example.com/login#form",
            "https://user:pass@crm.example.com/login",
            "https://*.example.com/login",
            "https://crm.example.com/log in",
            "https://crm.example.com:not-a-port/login",
            "ftp://crm.example.com/login",
        ]:
            self.assertIsNone(normalize_login_url(raw), raw)

    def test_explicit_port_and_root_path_are_kept_exact(self):
        self.assertEqual(
            normalize_login_url("https://crm.example.com:8443/login"),
            "https://crm.example.com:8443/login",
        )
        self.assertEqual(normalize_login_url("https://crm.example.com"), "https://crm.example.com/")


class AllowlistTests(unittest.TestCase):
    def test_only_the_reviewed_services_are_allowed_by_default(self):
        with configured(""):
            self.assertEqual(supported_login_urls(), HTTPS_BUILT_INS)
            self.assertTrue(is_supported_login_url(ACTIVITY_LOGIN_URL))
            self.assertFalse(is_supported_login_url(CUSTOM_URL))
            # The built-in HTTP service is reported instead of silently allowed.
            self.assertEqual(invalid_login_url_entries(), (LAN_URL,))

    def test_configured_services_are_added_without_touching_the_built_in_one(self):
        with configured(f"{CUSTOM_URL}, https://hr.example.org/signin\nhttps://crm.example.com/login"):
            self.assertEqual(
                supported_login_urls(),
                HTTPS_BUILT_INS + (CUSTOM_URL, "https://hr.example.org/signin"),
            )
            self.assertTrue(is_supported_login_url(CUSTOM_URL))
            self.assertTrue(is_supported_login_url(ACTIVITY_LOGIN_URL))
            self.assertFalse(is_supported_login_url("https://crm.example.com/login?redirect=x"))
            self.assertFalse(is_supported_login_url("https://crm.example.com/profile"))
            # The built-in internal HTTP service is off until its switch is on.
            self.assertEqual(invalid_login_url_entries(), (LAN_URL,))

    def test_invalid_entries_are_reported_and_never_allowed(self):
        with configured("http://crm.example.com/login, https://*.example.com/login, not a url"):
            self.assertEqual(supported_login_urls(), HTTPS_BUILT_INS)
            self.assertEqual(
                invalid_login_url_entries(),
                (LAN_URL, "http://crm.example.com/login",
                 "https://*.example.com/login", "not a url"),
            )
            for entry in invalid_login_url_entries():
                self.assertFalse(is_supported_login_url(entry))

    def test_a_card_url_cannot_widen_the_allowlist(self):
        with configured(CUSTOM_URL):
            for impostor in [
                "https://crm.example.com.evil.test/login",
                "http://crm.example.com/login",
                "https://crm.example.com/login?next=https://evil.test",
                "https://crm.example.com/login/",
                "https://crm.example.com:9443/login",
            ]:
                self.assertFalse(is_supported_login_url(impostor), impostor)

    def test_human_readable_list_for_the_vault_interface(self):
        with configured(CUSTOM_URL):
            text = describe_supported_login_urls()
            self.assertTrue(text.startswith(ACTIVITY_LOGIN_URL), text)
            self.assertTrue(text.endswith(f"и {CUSTOM_URL}"), text)
        with configured(""):
            self.assertEqual(describe_supported_login_urls(), ", ".join(HTTPS_BUILT_INS[:-1])
                             + f" и {HTTPS_BUILT_INS[-1]}")


class PrivateHttpTests(unittest.TestCase):
    """Plain HTTP stays out unless a private address opts in on both sides."""

    def configured_insecure(self, value: str):
        return patch.dict(os.environ, {EXTRA_LOGIN_URLS_ENV: LAN_URL,
                                       ALLOW_PRIVATE_HTTP_ENV: value})

    def test_http_is_rejected_while_the_switch_is_off(self):
        with self.configured_insecure("0"):
            self.assertEqual(supported_login_urls(), HTTPS_BUILT_INS)
            self.assertEqual(invalid_login_url_entries(), (LAN_URL,))
            self.assertFalse(is_supported_login_url(LAN_URL))

    def test_private_http_is_accepted_only_with_the_switch_on(self):
        with self.configured_insecure("1"):
            self.assertIn(LAN_URL, supported_login_urls())
            self.assertTrue(is_supported_login_url(LAN_URL))
            self.assertEqual(canonical_login_url(LAN_URL), LAN_URL)
            self.assertEqual(invalid_login_url_entries(), ())
            # The exact rule still applies to the private service.
            self.assertFalse(is_supported_login_url(LAN_URL + "?next=/x"))
            self.assertFalse(is_supported_login_url("http://192.168.8.82:8085/login"))

    def test_the_built_in_internal_service_needs_no_extra_configuration(self):
        with patch.dict(os.environ, {EXTRA_LOGIN_URLS_ENV: "", ALLOW_PRIVATE_HTTP_ENV: "1"}):
            self.assertIn(LAN_URL, supported_login_urls())
            self.assertTrue(is_supported_login_url(LAN_URL))

    def test_public_http_and_private_names_are_never_accepted(self):
        with self.configured_insecure("1"):
            for entry in [
                "http://repair-partner-service.meryosab.com/ru/login",
                "http://8.8.8.8/login",
                "http://intranet.local/login",
                "http://169.254.10.4/login",
            ]:
                self.assertIsNone(normalize_login_url(entry, allow_private_http=True), entry)

    def test_private_address_detection(self):
        for host in ["192.168.8.81", "10.0.0.7", "172.16.3.1", "172.31.255.254",
                     "127.0.0.1", "localhost", "::1", "fd00::1"]:
            self.assertTrue(is_private_host(host), host)
        for host in ["8.8.8.8", "172.32.0.1", "192.169.0.1", "intranet.local", "999.1.1.1", ""]:
            self.assertFalse(is_private_host(host), host)


class ExtensionConfigTests(unittest.TestCase):
    """The server allowlist and the extension must name the same login pages."""

    def test_built_in_sites_match_the_server_allowlist(self):
        shipped = json.loads(
            (PROJECT_ROOT / "browser_extension" / "sites.json").read_text(encoding="utf-8")
        )
        extension_urls = {
            normalize_login_url(
                site.get("login_url"),
                allow_private_http=site.get("allow_insecure") is True,
            )
            for site in shipped.get("sites", [])
        }
        self.assertEqual(extension_urls, set(BUILT_IN_LOGIN_URLS))
        insecure_sites = [
            site["login_url"] for site in shipped.get("sites", [])
            if site.get("allow_insecure") is True
        ]
        for url in insecure_sites:  # never a public address
            self.assertTrue(is_private_host(urlsplit(url).hostname), url)

    def test_extension_does_not_request_wildcard_host_permissions(self):
        manifest = json.loads(
            (PROJECT_ROOT / "browser_extension" / "manifest.json").read_text(encoding="utf-8")
        )
        for pattern in manifest.get("host_permissions", []):
            self.assertNotEqual(pattern, "https://*/*")
            self.assertNotEqual(pattern, "http://*/*")
        source = (PROJECT_ROOT / "browser_extension" / "background.js").read_text(encoding="utf-8")
        self.assertNotRegex(source, re.compile(r"login_url\s*[!=]==?\s*message"))
        self.assertIn("findTargetByUrl(message.login_url)", source)


class ParseTests(unittest.TestCase):
    def test_blank_and_duplicate_entries_are_ignored(self):
        self.assertEqual(parse_extra_login_urls(""), ((), ()))
        self.assertEqual(parse_extra_login_urls(None), ((), ()))
        self.assertEqual(
            parse_extra_login_urls(f"{CUSTOM_URL},,{CUSTOM_URL} ,"),
            ((CUSTOM_URL,), ()),
        )


if __name__ == "__main__":
    unittest.main()
