"""oneiron — memory for agents.

Four calls are the whole quickstart: witness a turn, claim a fact, recall it,
read the receipts. ``Oneiron.open()`` gives you an embedded vault bound to a
local owner actor; ``Oneiron.connect(url, key)`` gives you the same handle
against a running ``oneiron-server``. The two differ by one line.

Every method below is a one-line delegate to the private native client. There
are deliberately no service classes, repositories, or per-verb error wrappers:
each verb's semantics live once, in Rust, and anything added here would be a
second place for them to drift.

DTOs are plain dicts with snake_case keys, exactly as the type stubs in
``__init__.pyi`` declare them. Timestamps are Unix **seconds** everywhere and
are never converted; an omitted ``occurred_at`` is stamped with the current
wall clock at the call boundary.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, TypeVar

from ._native import NativeClient as _NativeClient

__all__ = ["Oneiron", "OneironError"]

_T = TypeVar("_T")


class OneironError(RuntimeError):
    """The one error this package raises.

    ``code`` is the engine's own stable string — ``BAD_REQUEST``,
    ``FORBIDDEN``, ``NOT_FOUND``, ``LEASE_REQUIRED``,
    ``VAULT_LOCKED_SINGLE_WRITER``, and any future code — carried verbatim.
    ``suggestions`` is never empty.
    """

    def __init__(self, code: str, message: str, suggestions: list[str]) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.suggestions = tuple(suggestions)


def _typed_error(payload: object, fallback: str) -> OneironError:
    """Rebuilds the typed error from the native payload, or fails closed.

    A payload that is not the ``{code, message, suggestions}`` contract becomes
    a typed ``INTERNAL_SERVER_ERROR`` rather than escaping as a bare
    ``RuntimeError``: that case is a bug in this package or the boundary below
    it, and a caller should still need exactly one ``except`` clause.
    """
    if (
        isinstance(payload, dict)
        and isinstance(payload.get("code"), str)
        and payload["code"]
        and isinstance(payload.get("message"), str)
        and isinstance(payload.get("suggestions"), list)
        and all(isinstance(entry, str) for entry in payload["suggestions"])
    ):
        suggestions = payload["suggestions"] or [
            "Retry the call, and check the Oneiron logs for this operation."
        ]
        return OneironError(payload["code"], payload["message"], suggestions)
    return OneironError(
        "INTERNAL_SERVER_ERROR",
        fallback,
        ["This is an Oneiron SDK bug; please report it with the message above."],
    )


def _translate(operation: Callable[[], _T]) -> _T:
    """Runs ``operation``, converting a native refusal into ``OneironError``.

    ``TypeError`` and ``ValueError`` are caught alongside the native
    ``RuntimeError`` because the verbs serialize their argument INSIDE
    ``operation``: a caller passing a set, ``bytes``, or a ``datetime`` fails in
    ``json.dumps`` rather than below the boundary, and I7 promises one
    ``except`` clause for every failure — not one for refusals and a second for
    unserializable input. Neither is a native payload, so both fall through to
    the ``_typed_error`` fallback as ``INTERNAL_SERVER_ERROR`` carrying the raw
    message.
    """
    try:
        return operation()
    except OneironError:
        raise
    except (RuntimeError, TypeError, ValueError) as error:
        raw = str(error)
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = None
        raise _typed_error(payload, raw) from None


class Oneiron:
    """A handle on one Oneiron memory, embedded or remote."""

    def __init__(self, client: _NativeClient) -> None:
        """Internal-only wrapper seam; use :meth:`open` or :meth:`connect`."""
        self._client = client

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str] | None = None,
        *,
        dimensions: int | None = None,
    ) -> "Oneiron":
        """Opens an embedded vault and returns an actor-bound handle.

        Omitting ``path`` resolves to ``~/.oneiron/default`` against the current
        process home, at call time. The handle is usable immediately; there is
        no ``as_actor`` call to make first.

        A second process opening the same directory raises
        ``VAULT_LOCKED_SINGLE_WRITER``; connect to the owning process instead.
        """
        resolved = os.fspath(path) if path is not None else None
        return cls(_translate(lambda: _NativeClient.open(resolved, dimensions)))

    @classmethod
    def connect(cls, url: str, key: str) -> "Oneiron":
        """Binds a running ``oneiron-server`` through its facade projection.

        ``key`` is a minted slip passed verbatim as
        ``Authorization: Bearer v2.<claims>.<mac-hex>``. This package never
        parses, splits, or validates it: every authority decision is made
        server-side from the MAC-verified ``principal_ref`` and ``actor_class``
        claims.
        """
        return cls(_translate(lambda: _NativeClient.connect(url, key)))

    def as_actor(self, actor_key: str) -> "Oneiron":
        """Returns a NEW handle bound to another actor; this one is unchanged.

        ``actor_key`` uses the pinned ``human:<ref>`` / ``agent:<ref>`` /
        ``system:<ref>`` grammar. On a connected handle this raises
        ``FORBIDDEN``: a remote principal cannot widen or replace the actor its
        slip bound, so reconnect with a differently scoped slip instead.
        """
        return Oneiron(_translate(lambda: self._client.as_actor(actor_key)))

    def witness(self, turn: dict[str, Any]) -> dict[str, Any]:
        """Witnesses one conversational turn.

        Omitting ``occurred_at`` stamps the current wall clock, in Unix
        seconds, at the call boundary.
        """
        return json.loads(_translate(lambda: self._client.witness(json.dumps(turn))))

    def claim_upsert(self, claim: dict[str, Any]) -> dict[str, Any]:
        """Upserts one claim. The consent gate, not this call, decides approval."""
        return json.loads(
            _translate(lambda: self._client.claim_upsert(json.dumps(claim)))
        )

    def recall(
        self,
        query: str,
        *,
        effort: str = "standard",
        scope: dict[str, Any] | None = None,
        limit: int = 10,
        format: str | None = None,
    ) -> dict[str, Any]:
        """Recalls a memory pack.

        ``effort="deep"`` is lease-gated and raises ``LEASE_REQUIRED`` until a
        lease-bearing constructor exists; this package neither mints nor
        simulates a lease. ``format`` takes the engine's exact tokens:
        ``"json"``, ``"yaml"``, ``"toon"``, ``"md"``, ``"txt"``.
        """
        return json.loads(
            _translate(
                lambda: self._client.recall(
                    query,
                    effort,
                    json.dumps(scope) if scope is not None else None,
                    limit,
                    format,
                )
            )
        )

    def receipts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Governance receipts, newest first."""
        return json.loads(_translate(lambda: self._client.receipts(limit)))
