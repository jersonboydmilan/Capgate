"""Host and address classification shared by policy checks and network tools."""

from __future__ import annotations

import ipaddress
import re
import socket

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
_PRIVATE_SUFFIXES = (".localhost", ".local", ".internal", ".intranet", ".lan", ".corp", ".home.arpa")


class InvalidHost(ValueError):
    pass


def ip_literal(host: str) -> IPAddress | None:
    """Return the IP a host literal denotes, including legacy IPv4 spellings.

    Resolvers accept `127.1`, `0x7f.0.0.1`, `0177.0.0.1` and `2130706433` as
    IPv4 addresses; so must a check that is meant to stop them.
    """
    candidate = host.strip("[]")
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    labels = candidate.split(".")
    if 1 <= len(labels) <= 4 and all(_NUMERIC_LABEL.match(label) for label in labels):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(candidate))
        except OSError:
            raise InvalidHost(f"ambiguous numeric host {host!r}") from None
    return None


def is_public_ip(ip: IPAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        for embedded in (ip.ipv4_mapped, ip.sixtofour, ip.teredo[1] if ip.teredo else None):
            if embedded is not None and not is_public_ip(embedded):
                return False
    return ip.is_global and not ip.is_multicast


def normalize_hostname(host: str) -> str:
    """Lower-case, strip one trailing dot, and require plain ASCII DNS syntax or an IP literal."""
    host = host.lower().rstrip(".")
    if ip_literal(host) is not None:
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            # 127.1, 0x7f.1, 2130706433: valid to some resolvers, read differently by others.
            raise InvalidHost(f"non-canonical IP address {host!r}") from None
        return host
    if not _HOSTNAME.match(host):
        raise InvalidHost(f"host {host!r} is not a plain ASCII DNS name")
    return host


def is_private_host(host: str) -> bool:
    """Classify a host by its name alone (no DNS). Unknown public-looking names return False."""
    ip = ip_literal(host)
    if ip is not None:
        return not is_public_ip(ip)
    return host == "localhost" or host.endswith(_PRIVATE_SUFFIXES) or "." not in host
