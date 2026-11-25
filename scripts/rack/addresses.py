"""Where a URL connects, judged once, and a connection held to that judgement.

A URL whose host connects to this box (a loopback or unspecified address in
any spelling curl accepts, such as `127.1`, or an address of the box's own)
is a forward on a lane box, so the harness refuses it. The host is resolved
as curl resolves it, and the URL is refused when any of its addresses is
local. A second lookup could answer differently (a name rebound to loopback
between the check and the connect), so every request the harness makes after
the check connects only to the addresses the check judged: curl through
`--resolve` (rack.oneiron_api), the model list through `pinned_status` here.
A host that is an address literal needs no lookup and no pin.
"""

from __future__ import annotations

import errno
import http.client
import ipaddress
import socket
import ssl
import urllib.parse
from dataclasses import dataclass


class AddressError(Exception):
    """A URL whose host cannot be resolved, or whose address cannot be judged."""


@dataclass(frozen=True)
class Target:
    """A URL's host as HTTP and TLS name it, its port, and the addresses the check judged."""

    scheme: str
    host: str
    port: int
    # In getaddrinfo's order; for a literal host, the host itself.
    addresses: tuple[str, ...]
    # The host is an address literal: no lookup happens, so nothing needs a pin.
    literal: bool
    # Some address connects to this box.
    local: bool
    # The path and query the request asks for ("/" when the URL has none).
    target: str

    def curl_resolve(self) -> str:
        """curl's `--resolve` entry that holds the host:port to the judged addresses."""
        listed = ",".join(f"[{a}]" if ":" in a else a for a in self.addresses)
        return f"{self.host}:{self.port}:{listed}"


def _address_is_local(sockaddr: tuple) -> bool:
    """Whether a connect to this address reaches this box.

    Loopback and unspecified addresses do, in any spelling (an IPv4-mapped
    one too). Any other address is local when a socket can bind to it, which
    sends nothing; an answer other than "not an address here" counts as local.
    """
    ip = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified:
        return True
    family = socket.AF_INET6 if len(sockaddr) == 4 else socket.AF_INET
    try:
        probe = socket.socket(family, socket.SOCK_DGRAM)
    except OSError:
        return True
    with probe:
        try:
            probe.bind((sockaddr[0], 0, *sockaddr[2:]))
        except OSError as error:
            return error.errno != errno.EADDRNOTAVAIL
    return True


def resolve_target(url: str) -> Target:
    """Where a request to `url` connects (AddressError when it cannot be told)."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if not host:
        raise AddressError("the URL names no host")
    if not host.isascii():
        raise AddressError("the URL's host is not ASCII (a name curl would convert is not pinned)")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise AddressError("the URL's port is not a number") from None
    path = parts.path or "/"
    target = f"{path}?{parts.query}" if parts.query else path
    if host == "localhost" or host.endswith(".localhost"):
        return Target(parts.scheme, host, port, (), False, True, target)
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise AddressError("the URL's host does not resolve") from None
    if not answers:
        raise AddressError("the URL's host does not resolve")
    addresses: list[str] = []
    for *_, sockaddr in answers:
        if sockaddr[0] not in addresses:
            addresses.append(sockaddr[0])
    local = any(_address_is_local(sockaddr) for *_, sockaddr in answers)
    return Target(parts.scheme, host, port, tuple(addresses), literal, local, target)


def local_target(url: str) -> bool:
    """Whether a request to `url` would connect to this box (AddressError when it cannot be told)."""
    return resolve_target(url).local


def _connect(target: Target, timeout: float) -> socket.socket:
    """A TCP connection to one of the judged addresses, never to a fresh lookup."""
    last: OSError | None = None
    for address in target.addresses:
        try:
            return socket.create_connection((address, target.port), timeout=timeout)
        except OSError as error:
            last = error
    raise last if last is not None else OSError("no address to connect to")


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, target: Target, timeout: float):
        super().__init__(target.host, target.port, timeout=timeout)
        self._pinned = target

    def connect(self) -> None:
        self.sock = _connect(self._pinned, self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    """TLS to the judged address, with the certificate checked against the URL's host name."""

    def __init__(self, target: Target, timeout: float):
        self._tls = ssl.create_default_context()
        super().__init__(target.host, target.port, timeout=timeout, context=self._tls)
        self._pinned = target

    def connect(self) -> None:
        sock = _connect(self._pinned, self.timeout)
        self.sock = self._tls.wrap_socket(sock, server_hostname=self._pinned.host)


def pinned_status(target: Target, timeout: float) -> int:
    """The HTTP status of one GET to `target` over a judged address. No redirect is followed.

    No proxy setting is read: the answer must come over the URL's own route.
    """
    if target.scheme == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPS(target, timeout)
    elif target.scheme == "http":
        connection = _PinnedHTTP(target, timeout)
    else:
        raise AddressError("the URL is not http or https")
    try:
        connection.request("GET", target.target)
        answer = connection.getresponse()
        answer.read(65536)
        return answer.status
    finally:
        connection.close()
