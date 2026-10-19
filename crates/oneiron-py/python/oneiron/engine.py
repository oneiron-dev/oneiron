"""oneiron.engine — the full Oneiron server inside this Python process.

Opt-in: the native extension carries it only when built with the ``engine``
cargo feature. :meth:`EmbeddedEngine.start` opens the vault the way
``oneiron serve`` does, once, and serves it in this process.
:meth:`EmbeddedEngine.client` returns an :class:`oneiron.Oneiron` handle
served by that server under the caller's own credential: every verb is the
request a connected handle sends, carried through the server in process, so
the host doors answer as on any server and the server decides each call from
``key``. Nothing opens the vault a second time, and a large ``vault.export``
streams.

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
from collections.abc import Mapping
from typing import Any

from . import Oneiron, OneironError, _translate
from . import _native

__all__ = ["EmbeddedEngine"]


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
        and ``as_actor`` refuses on it as on any connected handle."""
        return Oneiron(_translate(lambda: self._engine.client(key)))

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
