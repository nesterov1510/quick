"""Server-side MSB Activity ticket exchange for Quick Access login.

The long-lived service token never leaves this server. Quick Access exchanges it
for a short-lived, single-use code; the browser only submits that code and the
attempt metadata to the service's fixed callback.
"""
from __future__ import annotations

import http.client
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from vault_control.autologin import (
    is_quick_access_supported_url,
    normalize_login_url,
    quick_access_private_http_allowed,
)

SERVICE_ID = "msb-activity"
AUTHORIZE_PATH = "/api/quick-access/v1/authorize"
CALLBACK_PATH = "/quick-access/callback"
MAX_RESPONSE_BYTES = 16 * 1024
REQUEST_TIMEOUT_SECONDS = 5.0
_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{32,512}$")
_ATTEMPT_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


class QuickAccessExchangeError(Exception):
    """A safe, user-displayable Quick Access ticket exchange failure."""


def service_origin(login_url: str) -> str:
    """Return the origin of a validated MSB Activity login URL."""
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


def authorize_endpoint(login_url: str) -> str:
    return service_origin(login_url) + AUTHORIZE_PATH


def callback_url(login_url: str) -> str:
    return service_origin(login_url) + CALLBACK_PATH


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward an Authorization bearer token through a redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_login_ticket(
    login_url: str,
    service_token: str,
    state: str,
    attempt_id: str,
) -> str:
    """Exchange a service-specific PAT for a one-use browser handoff code.

    The exact origin comes from the configured allowlist, not request data. HTTP
    is accepted only when that URL is an explicitly enabled private address.
    Redirects, environment proxies, oversized responses, unexpected content
    types, and codes outside the documented opaque format are rejected.
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
    if not isinstance(attempt_id, str) or not _ATTEMPT_RE.fullmatch(attempt_id):
        raise QuickAccessExchangeError("Не удалось создать безопасный запрос входа")

    target_callback = callback_url(login_url)
    payload = json.dumps({
        "service": SERVICE_ID,
        "callback_uri": target_callback,
        "state": state,
        "attempt_id": attempt_id,
    }, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        authorize_endpoint(login_url),
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

    if not isinstance(data, dict) or set(data) != {"code"}:
        raise QuickAccessExchangeError("Сервис вернул некорректный ответ")
    code = data.get("code")
    if not isinstance(code, str) or not _CODE_RE.fullmatch(code):
        raise QuickAccessExchangeError("Сервис вернул некорректный билет")
    return code
