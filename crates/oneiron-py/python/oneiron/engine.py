"""oneiron.engine — the full Oneiron server inside this Python process.

Opt-in: the native extension carries it only when built with the ``engine``
cargo feature. :meth:`EmbeddedEngine.start` opens the vault the way
``oneiron serve`` does, once, and serves it in this process.
:meth:`EmbeddedEngine.client` returns an :class:`oneiron.Oneiron` handle
served by that server under the caller's own credential: every verb is the
request a connected handle sends, carried through the server in process, so
the host doors answer as on any server and the server decides each call from
``key``. :meth:`EmbeddedEngine.local_client` attaches a handle to the
engine's own vault instead, and :meth:`EmbeddedEngine.request` and
:meth:`EmbeddedEngine.connect` reach the server's HTTP surface. Nothing
opens the vault a second time, and a large ``vault.export`` streams.

Every engine failure raises :class:`oneiron.OneironError` with its stable
code: ``ENGINE_STOPPED``, ``ENGINE_CLOSED``, ``ENGINE_RELAY_REFUSED``,
``ENGINE_WRONG_THREAD``, ``ENGINE_CONFIG``, ``ENGINE_VAULT_OPEN``,
``ENGINE_START_FAILED``, ``ENGINE_CONNECTION_ENDED``,
``ENGINE_REPLY_TOO_LARGE``, ``ENGINE_BAD_REQUEST``, or
``INTERNAL_SERVER_ERROR`` when no cause is named. A build without the engine
raises ``ENGINE_UNAVAILABLE`` from :meth:`EmbeddedEngine.start`.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from . import Oneiron, OneironError, _translate
from . import _native

__all__ = ["EmbeddedEngine", "EngineConnection", "EngineReply", "EngineRequest"]


@dataclass(frozen=True)
class EngineRequest:
    """One request the app sends its engine: the request a socket's client
    would send, bringing its own auth."""

    method: str
    """The HTTP method, e.g. ``"GET"``."""
    path: str
    """The path and query, e.g. ``"/v1/core/health"``."""
    headers: Sequence[tuple[str, bytes]] | None = None
    """Request headers, repeats allowed; ``None`` sends none."""
    body: bytes | None = None
    """Request body; ``None`` sends an empty body."""


@dataclass(frozen=True)
class EngineReply:
    """The engine's whole reply to one request. A 4xx or 5xx status is a
    reply, not an error."""

    status: int
    """The HTTP status."""
    headers: list[tuple[str, bytes]]
    """Every header the reply carried, repeats included."""
    body: bytes
    """The reply body."""


class EngineConnection:
    """A connection the app holds to its embedded engine's server: bytes both
    ways. The app writes the HTTP/1.1 request and, after a ``101``, the
    upgraded protocol's frames; it reads what the server writes. Every call
    blocks. Once the engine stops or closes, ``receive`` returns empty and
    ``send`` raises."""

    def __init__(self, connection: Any) -> None:
        """Internal-only wrapper seam; use :meth:`EmbeddedEngine.connect`."""
        self._connection = connection

    def send(self, data: bytes) -> None:
        """Writes ``data`` to the server."""
        _translate(lambda: self._connection.send(bytes(data)))

    def receive(self) -> bytes:
        """The next bytes the server wrote; empty once the connection ended."""
        return _translate(self._connection.receive)

    def close(self) -> None:
        """Ends the connection; a blocked ``receive`` returns empty."""
        _translate(self._connection.close)

    def __enter__(self) -> "EngineConnection":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class EmbeddedEngine:
    """The engine inside this process, over the one vault it opened."""

    def __init__(self, engine: Any) -> None:
        """Internal-only wrapper seam; use :meth:`start`."""
        self._engine = engine

    @classmethod
    def start(
        cls,
        path: str | os.PathLike[str],
        *,
        dimensions: int | None = None,
        config_file: str | os.PathLike[str] | None = None,
        secrets: Mapping[str, str | bytes] | None = None,
        memory_bytes: int | None = None,
        cpu_millis_per_second: int | None = None,
    ) -> "EmbeddedEngine":
        """Opens the vault at ``path`` and serves it in this process.

        The config is the one ``oneiron serve --config <config_file>``
        resolves for this path, with ``dimensions`` when given. ``secrets``
        is the host keychain by exact name (``auth_secret``,
        ``vault_password``); a ``str`` value is taken as UTF-8. An absent
        limit is unbounded. Returns once the server is ready.
        """
        native = getattr(_native, "NativeEngine", None)
        if native is None:
            raise OneironError(
                "ENGINE_UNAVAILABLE",
                "this oneiron build has no embedded engine",
                ["Build the native extension with the `engine` cargo feature, or use Oneiron.connect(url, key)."],
            )
        keychain = None
        if secrets is not None:
            keychain = {
                name: value.encode() if isinstance(value, str) else bytes(value)
                for name, value in secrets.items()
            }
        resolved = os.fspath(path)
        config = os.fspath(config_file) if config_file is not None else None
        return cls(
            _translate(
                lambda: native.start(
                    resolved, dimensions, config, keychain, memory_bytes, cpu_millis_per_second
                )
            )
        )

    def client(self, key: str) -> Oneiron:
        """A NEW handle served by this engine under ``key``, the caller's
        own credential, passed verbatim: the credential ``Oneiron.pair``
        returned, or the host secret as a bare bearer. It makes no request,
        ``as_actor`` refuses on it as on any connected handle, and it keeps
        the engine alive."""
        return Oneiron(_translate(lambda: self._engine.client(key)))

    def local_client(self) -> Oneiron:
        """A NEW handle on the engine's own vault, bound to the embedded
        owner as ``open`` binds one: its verbs answer through the vault
        itself, not the server, so the host-door rows only a server answers
        refuse on it (use :meth:`client` for those). It keeps the engine
        alive; each call attaches anew and none reopens the path."""
        return Oneiron(_translate(lambda: self._engine.local_client()))

    def request(self, request: EngineRequest) -> EngineReply:
        """Sends one request on the API's origin and returns the whole reply.
        ``/ws`` is not served through it, and a reply past the buffered
        ceiling raises ``ENGINE_REPLY_TOO_LARGE``; open a connection for
        those. Raises ``ENGINE_STOPPED`` while stopped."""
        status, headers, body = _translate(
            lambda: self._engine.request(
                request.method, request.path, request.headers, request.body
            )
        )
        return EngineReply(status=status, headers=headers, body=body)

    def request_artifact(self, request: EngineRequest) -> EngineReply:
        """:meth:`request` on the artifact app's own origin (``/a/``)."""
        status, headers, body = _translate(
            lambda: self._engine.request_artifact(
                request.method, request.path, request.headers, request.body
            )
        )
        return EngineReply(status=status, headers=headers, body=body)

    def connect(self) -> EngineConnection:
        """Opens a connection the app holds to the engine's server, served as
        a socket's connection, HTTP/1.1 with upgrades: a ``GET /ws`` with its
        upgrade headers holds ``/ws`` on it, and a streamed reply arrives as
        it is written. A stop drains it; after ``wake`` open another."""
        return EngineConnection(_translate(lambda: self._engine.connect()))

    def connect_artifact(self) -> EngineConnection:
        """:meth:`connect` on the artifact app's own origin (``/a/``)."""
        return EngineConnection(_translate(lambda: self._engine.connect_artifact()))

    def wake(self) -> None:
        """Runs what is due; a stopped engine serves again first."""
        _translate(self._engine.wake)

    def stop(self) -> None:
        """Drains, stops every worker, and keeps the vault open for ``wake``."""
        _translate(self._engine.stop)

    def close(self) -> None:
        """Stops the engine in order; its handles refuse ``ENGINE_CLOSED`` after."""
        _translate(self._engine.close)

    def __enter__(self) -> "EmbeddedEngine":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
