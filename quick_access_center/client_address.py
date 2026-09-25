"""Resolve a client IP without trusting headers sent by an arbitrary visitor.

The last proxy (request.remote_addr) must be explicitly trusted. Walk X-Forwarded-For
from right to left so a visitor cannot prepend a forged address to the header.
A reverse proxy must append its own observed client address or replace the header.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_trusted(address: str, trusted_proxies: Iterable[str]) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False

    for item in trusted_proxies:
        try:
            if parsed in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def resolve_client_ip(
    remote_addr: str | None,
    forwarded_for: str = "",
    real_ip: str = "",
    *,
    trust_proxy: bool = False,
    trusted_proxies: Iterable[str] = (),
) -> str:
    """Return an IP address or ``unknown`` (which an IP allowlist denies)."""
    remote_addr = (remote_addr or "").strip()
    if not _valid_ip(remote_addr):
        return "unknown"
    if not trust_proxy or not _is_trusted(remote_addr, trusted_proxies):
        return remote_addr

    if forwarded_for:
        addresses = [part.strip() for part in forwarded_for.split(",")]
        for address in reversed(addresses):
            if not _valid_ip(address):
                return "unknown"
            if not _is_trusted(address, trusted_proxies):
                return address
        # All the listed hops are trusted: take the leftmost one.
        return addresses[0]

    if _valid_ip(real_ip.strip()):
        return real_ip.strip()
    return "unknown"
