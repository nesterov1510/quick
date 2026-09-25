"""Explicit allowlist for browser-extension auto login targets.

Never send a Vault password to an arbitrary URL stored in a card. Supporting
another service requires reviewing its login flow and extending both this
allowlist and the browser extension's host permissions / form adapter.
"""

ACTIVITY_LOGIN_URL = "https://msb-activity.meryosab.com/login"


def is_supported_login_url(url: str) -> bool:
    # An exact URL match also excludes lookalike domains, credentials in URLs,
    # HTTP, alternate ports, fragments and query-string redirects.
    return url == ACTIVITY_LOGIN_URL
