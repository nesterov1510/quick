"""Explicit allowlist for browser-extension auto login targets.

Never send a Vault password to an arbitrary URL stored in a card. Supporting
another service requires reviewing its login flow and listing that exact URL
here (``BUILT_IN_LOGIN_URLS`` or ``VAULT_AUTOLOGIN_SITES`` in
``vault_control/vault.env``), plus a matching entry in
``browser_extension/sites.json`` with the browser's host permission for that
origin.

Entries are exact login URLs. Wildcards, credentials in the URL, query strings
and fragments are rejected: an allowlist that can be widened by editing a card
URL is not an allowlist. ``http://`` is rejected too, except for private
network addresses and only with an explicit opt-in.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Optional, Tuple
from urllib.parse import urlsplit

ACTIVITY_LOGIN_URL = "https://msb-activity.meryosab.com/login"
# The internal service is plain HTTP inside a private network: it is listed
# here, but it becomes usable only with VAULT_AUTOLOGIN_ALLOW_PRIVATE_HTTP=1.
INTERNAL_LAN_LOGIN_URL = "http://192.168.8.81:8085/login"
BUILT_IN_LOGIN_URLS: Tuple[str, ...] = (
    ACTIVITY_LOGIN_URL,
    "https://repair-partner-service.meryosab.com/ru/login",
    "https://msb-career.meryosab.com/admin/login/",
    INTERNAL_LAN_LOGIN_URL,
)
EXTRA_LOGIN_URLS_ENV = "VAULT_AUTOLOGIN_SITES"
ALLOW_PRIVATE_HTTP_ENV = "VAULT_AUTOLOGIN_ALLOW_PRIVATE_HTTP"

# vault.env is re-read only when it actually changed; the dashboard renders
# frequently and must not touch the disk on every request.
_env_cache: dict = {"stamp": None, "values": {}}


def _vault_env_path():
    from vault_control.vault_settings import VAULT_ENV_PATH  # lazy: avoids import cycle

    return VAULT_ENV_PATH


def _vault_env_values() -> dict:
    try:
        path = _vault_env_path()
        stamp = (path.stat().st_mtime_ns, path.stat().st_size) if path.exists() else (0, 0)
    except OSError:
        return {}

    if _env_cache["stamp"] != stamp:
        values: dict = {}
        try:
            if path.exists():
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    clean = line.strip()
                    if not clean or clean.startswith("#") or "=" not in clean:
                        continue
                    key, raw_value = clean.split("=", 1)
                    values[key.strip()] = raw_value.strip().strip('"').strip("'")
        except Exception:
            # A broken vault.env must never widen the allowlist or break the panel.
            return {}
        _env_cache["stamp"] = stamp
        _env_cache["values"] = values

    return _env_cache["values"]


def _config_value(name: str) -> str:
    from_environment = os.environ.get(name)
    if from_environment is not None:
        return from_environment
    return _vault_env_values().get(name, "")


def private_http_allowed() -> bool:
    """Opt-in for plain HTTP inside a private network (password goes unencrypted)."""
    return _config_value(ALLOW_PRIVATE_HTTP_ENV).strip().lower() in {"1", "true", "yes", "on", "да"}


def is_private_host(host: str) -> bool:
    """Only IP literals of private networks and ``localhost`` count.

    A private *domain name* is not accepted: it can resolve anywhere, so it
    would quietly turn the opt-in into "any HTTP site".
    """
    clean = (host or "").strip().lower().strip("[]")
    if clean == "localhost":
        return True
    try:
        address = ipaddress.ip_address(clean)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    # Link-local (169.254/16, fe80::/10) is a misconfiguration rather than a
    # managed internal network, and the browser-side twin rejects it too.
    return bool(address.is_private and not address.is_link_local)


def normalize_login_url(raw: object, allow_private_http: bool = False) -> Optional[str]:
    """Return the canonical form of an exact login URL, else ``None``.

    Only ``https`` without userinfo, query or fragment is accepted, so a card
    pointing at a lookalike domain, an HTTP downgrade or a redirect parameter
    can never match the allowlist. Plain HTTP passes only for a private network
    address and only when the caller allows it.
    """
    text = str(raw or "").strip()
    if not text or any(char.isspace() for char in text) or "*" in text:
        return None

    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None

    if not host or parts.username or parts.password or parts.query or parts.fragment:
        return None

    path = parts.path or "/"
    if parts.scheme == "https":
        netloc = host if port in (None, 443) else f"{host}:{port}"
        return f"https://{netloc}{path}"
    if parts.scheme == "http" and allow_private_http and is_private_host(host):
        netloc = host if port in (None, 80) else f"{host}:{port}"
        return f"http://{netloc}{path}"
    return None


def canonical_login_url(raw: object) -> Optional[str]:
    """Canonical form under the current configuration (used for card URLs)."""
    return normalize_login_url(raw, allow_private_http=private_http_allowed())


def parse_extra_login_urls(
    raw: Optional[str] = None, allow_private_http: Optional[bool] = None
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """Split a comma/newline separated list into accepted and rejected entries."""
    source = _config_value(EXTRA_LOGIN_URLS_ENV) if raw is None else str(raw or "")
    insecure = private_http_allowed() if allow_private_http is None else allow_private_http
    valid: list[str] = []
    invalid: list[str] = []

    for item in source.replace("\n", ",").split(","):
        entry = item.strip()
        if not entry:
            continue
        canonical = normalize_login_url(entry, allow_private_http=insecure)
        if not canonical:
            if entry not in invalid:
                invalid.append(entry)
        elif canonical not in valid:
            valid.append(canonical)

    return tuple(valid), tuple(invalid)


def supported_login_urls() -> Tuple[str, ...]:
    """Every login URL the extension may receive a Vault password for.

    Built-in entries are filtered through the same rules as configured ones, so
    a plain HTTP service stays out of the list until its switch is on instead of
    being shown as allowed.
    """
    insecure = private_http_allowed()
    urls: list[str] = []
    for url in BUILT_IN_LOGIN_URLS + parse_extra_login_urls()[0]:
        canonical = normalize_login_url(url, allow_private_http=insecure)
        if canonical and canonical not in urls:
            urls.append(canonical)
    return tuple(urls)


def invalid_login_url_entries() -> Tuple[str, ...]:
    """Entries ignored because they are not exact login URLs right now."""
    insecure = private_http_allowed()
    invalid: list[str] = []
    for url in BUILT_IN_LOGIN_URLS:
        if not normalize_login_url(url, allow_private_http=insecure) and url not in invalid:
            invalid.append(url)
    for entry in parse_extra_login_urls()[1]:
        if entry not in invalid:
            invalid.append(entry)
    return tuple(invalid)


def is_supported_login_url(url: object) -> bool:
    # An exact URL match also excludes lookalike domains, credentials in URLs,
    # HTTP, alternate ports, fragments and query-string redirects.
    canonical = canonical_login_url(url)
    return bool(canonical) and canonical in supported_login_urls()


def describe_supported_login_urls(urls=None) -> str:
    """Human readable list for the Vault interface."""
    items = list(supported_login_urls() if urls is None else urls)
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " и " + items[-1]
