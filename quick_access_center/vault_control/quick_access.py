"""Server-side ticket exchange for services that explicitly support Quick Access login.

The long-lived service token never leaves this server. It is exchanged for a
short-lived, single-use code; the browser only submits that one-use code to the
service's fixed callback.
"""
from __future__ import annotations

import hmac
import http.client
import json
import re
import urllib.error
import urllib.request
from typing import Tuple
from urllib.parse import urlsplit

from vault_control.autologin import (
    is_quick_access_supported_url,
    normalize_login_url,
    quick_access_client_id,
    quick_access_private_http_allowed,
)

TICKET_PATH = "/auth/quick-access/ticket"
CALLBACK_PATH = "/auth/quick-access/callback"
MAX_RESPONSE_BYTES = 16 * 1024
MAX_TICKET_TTL_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 5.0
_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{32,512}$")


class QuickAccessExchangeError(Exception):
    """A safe, user-displayable Quick Access ticket exchange failure."""


def service_origin(login_url: str) -> str:
    """Return the origin of a validated service login URL."""
    if not is_quick_access_supported_url(login_url):
        raise QuickAccessExchangeError("Сервис не разрешён для входа через Quick Access")
    canonical = normalize_login_url(
        login_url,
        allow_private_http=quick_access_private_http_allowed(),
    )
    if not canonical:
        raise QuickAccessExchangeError("Некорректный адрес сервиса")
    parts = urlsplit(canonical)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def ticket_endpoint(login_url: str) -> str:
    return service_origin(login_url) + TICKET_PATH


def callback_url(login_url: str) -> str:
    return service_origin(login_url) + CALLBACK_PATH


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward an Authorization bearer token through a redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_login_ticket(login_url: str, service_token: str, state: str) -> Tuple[str, int]:
    """Exchange a service-specific PAT for a one-use browser handoff code.

    The exact origin comes from the configured allowlist, not request data. HTTP
    is accepted only when that URL is an explicitly enabled private address.
    Redirects, environment proxies, oversized responses, unexpected content
    types, mismatched state, and codes outside the documented opaque format are
    rejected.
    """
    if not is_quick_access_supported_url(login_url):
        raise QuickAccessExchangeError("Сервис не разрешён для входа через Quick Access")
    if (
        not isinstance(service_token, str)
        or not service_token
        or len(service_token) > 8192
        or any(ord(char) < 33 or ord(char) > 126 for char in service_token)
    ):
        raise QuickAccessExchangeError("Токен сервиса не настроен")
    if not isinstance(state, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", state):
        raise QuickAccessExchangeError("Не удалось создать безопасный запрос входа")

    client_id = quick_access_client_id()
    if not client_id:
        raise QuickAccessExchangeError("Некорректный VAULT_QUICK_ACCESS_CLIENT_ID")

    payload = json.dumps({
        "client_id": client_id,
        "redirect_uri": callback_url(login_url),
        "state": state,
    }, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        ticket_endpoint(login_url),
        data=payload,
        headers={
            "Authorization": f"Bearer {service_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Cache-Control": "no-store",
        },
        method="POST",
    )

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise QuickAccessExchangeError("Сервис не выдал билет для входа")
            content_type = response.headers.get_content_type().lower()
            if content_type != "application/json":
                raise QuickAccessExchangeError("Сервис вернул неожиданный ответ")
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except QuickAccessExchangeError:
        raise
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError, ValueError):
        # Do not include exception text: it may contain remote response details.
        raise QuickAccessExchangeError("Не удалось безопасно связаться с сервисом") from None

    if len(body) > MAX_RESPONSE_BYTES:
        raise QuickAccessExchangeError("Сервис вернул слишком большой ответ")
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise QuickAccessExchangeError("Сервис вернул некорректный ответ") from None

    if not isinstance(data, dict):
        raise QuickAccessExchangeError("Сервис вернул некорректный ответ")
    code = data.get("code")
    returned_state = data.get("state")
    expires_in = data.get("expires_in")
    if not isinstance(code, str) or not _CODE_RE.fullmatch(code):
        raise QuickAccessExchangeError("Сервис вернул некорректный билет")
    if not isinstance(returned_state, str) or not hmac.compare_digest(returned_state, state):
        raise QuickAccessExchangeError("Проверка состояния входа не пройдена")
    if (
        isinstance(expires_in, bool)
        or not isinstance(expires_in, int)
        or not 1 <= expires_in <= MAX_TICKET_TTL_SECONDS
    ):
        raise QuickAccessExchangeError("Срок действия билета сервиса некорректен")

    return code, expires_in
