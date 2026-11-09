"""oneiron — memory for agents.

Four calls are the whole quickstart: witness a turn (``vault.witness``), claim
a fact (``vault.claims.upsert``), recall it (``vault.recall``), read the
receipts (``vault.receipts``). ``Oneiron.open()`` gives you an embedded vault
bound to a local owner actor; ``Oneiron.connect(url, key)`` gives you the same
handle against a running ``oneiron-server``, where ``key`` is the credential
``Oneiron.pair(link)`` returned once. The two differ by one line.

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
from typing import TYPE_CHECKING, Any, Callable, TypeVar

if TYPE_CHECKING:
    from .facade_types import LegalHoldNotice, RoomJoinHold

from ._native import NativeClient as _NativeClient

__all__ = ["Oneiron", "OneironError"]

_T = TypeVar("_T")


class OneironError(RuntimeError):
    """The one error this package raises.

    ``code`` is the engine's own stable string — ``BAD_REQUEST``,
    ``FORBIDDEN``, ``NOT_FOUND``, ``LEASE_REQUIRED``,
    ``VAULT_LOCKED_SINGLE_WRITER``, and any future code — carried verbatim.
    ``suggestions`` is never empty. ``hook`` is the verb hook's stop when one
    stopped the call: on ``PENDING_ASK`` it is ``{"status": "pending",
    "invocation", "ask"}``, and :meth:`Oneiron.retry` resends the call under
    that invocation. ``retry_after`` (seconds) and ``resets_at`` (Unix
    seconds, in the source's order) say when to call again, when the
    refusal's source said (FIX 8190). ``reason_codes`` are the refusal's
    stable reason codes, in its producer's order, when it named any (FIX 7398).
    """

    def __init__(
        self,
        code: str,
        message: str,
        suggestions: list[str],
        wrong_root: dict[str, str] | None = None,
        hook: dict[str, Any] | None = None,
        retry_after: int | None = None,
        resets_at: list[int] | None = None,
        reason_codes: list[str] | None = None,
        legal_hold: LegalHoldNotice | None = None,
        room_join_hold: RoomJoinHold | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.suggestions = tuple(suggestions)
        # A ``WRONG_ROOT`` refusal's ``{attempted, replacement, schemaRef}``.
        self.wrong_root = wrong_root
        # The verb hook's stop (ARCH-0080 §3), as the engine's MemoryError names it.
        self.hook = hook
        # When to call again, as the refusal's source said (FIX 8190).
        self.retry_after = retry_after
        self.resets_at = tuple(resets_at) if resets_at is not None else None
        # The refusal's stable reason codes, as its producer named them (FIX 7398).
        self.reason_codes = tuple(reason_codes) if reason_codes is not None else None
        self.legal_hold = legal_hold
        self.room_join_hold = room_join_hold


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
        correction = {key: payload.get(key) for key in ("attempted", "replacement", "schemaRef")}
        wrong_root = correction if all(isinstance(value, str) for value in correction.values()) else None
        hook = payload.get("hook")
        hook = hook if isinstance(hook, dict) and isinstance(hook.get("status"), str) else None
        retry_after = payload.get("retry_after")
        retry_after = retry_after if isinstance(retry_after, int) else None
        resets_at = payload.get("resets_at")
        resets_at = (
            resets_at
            if isinstance(resets_at, list) and all(isinstance(entry, int) for entry in resets_at)
            else None
        )
        reason_codes = payload.get("reason_codes")
        reason_codes = (
            reason_codes
            if isinstance(reason_codes, list) and all(isinstance(entry, str) for entry in reason_codes)
            else None
        )
        legal_hold = payload.get("legal_hold")
        legal_hold = legal_hold if isinstance(legal_hold, dict) else None
        room_join_hold = payload.get("room_join_hold")
        room_join_hold = room_join_hold if isinstance(room_join_hold, dict) else None
        return OneironError(
            payload["code"],
            payload["message"],
            suggestions,
            wrong_root,
            hook,
            retry_after,
            resets_at,
            reason_codes,
            legal_hold,
            room_join_hold,
        )
    return OneironError(
        "INTERNAL_SERVER_ERROR",
        fallback,
        ["This is an Oneiron SDK bug; please report it with the message above."],
    )


def _translate(operation: Callable[[], _T]) -> _T:
    """Runs ``operation``, converting a native refusal into ``OneironError``.

    Argument conversion and JSON serialization run INSIDE ``operation``.
    ``TypeError`` and ``ValueError`` reject malformed input; ``OverflowError``
    also covers negative or huge Python integers extracted into native unsigned
    dimensions/limits. These are ``BAD_REQUEST``, not SDK bugs. Native
    ``RuntimeError`` payloads still pass through ``_typed_error`` unchanged,
    with malformed payloads classified as ``INTERNAL_SERVER_ERROR``.
    """
    try:
        return operation()
    except OneironError:
        raise
    except (TypeError, ValueError, OverflowError) as error:
        raise OneironError(
            "BAD_REQUEST",
            str(error),
            [
                "Pass dimensions and limits as positive Python integers, not floats.",
                "Use the embedding model's dimension count and request a smaller result limit.",
                "Check argument types and JSON values against the oneiron type stubs.",
            ],
        ) from None
    except RuntimeError as error:
        raw = str(error)
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = None
        raise _typed_error(payload, raw) from None


# The generated facade verbs (untangle slice 4.3). The module reads _NativeClient and _translate above.
from ._facade_verbs import _FacadeVerbs  # noqa: E402


class Oneiron(_FacadeVerbs):
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
        device_class: str | None = None,
    ) -> "Oneiron":
        """Opens an embedded vault and returns an actor-bound handle.

        Omitting ``path`` resolves to ``~/.oneiron/default`` against the current
        process home, at call time. The handle is usable immediately; there is
        no ``as_actor`` call to make first.

        ``device_class`` is the kind of machine this install is, as the host
        declares it (FIX 5591): ``"computer"``, the default when omitted, or
        ``"phone"``; any other name raises ``BAD_REQUEST``. It is set before
        the vault opens, so the install enrols as it, and never read off the
        operating system.

        Embedded open is currently supported only on Unix (macOS/Linux).
        On other targets, including Windows, it fails closed because writer
        locking is unsupported; use :meth:`connect` to a supported server host.

        A second process opening the same directory raises
        ``VAULT_LOCKED_SINGLE_WRITER``; connect to the owning process instead.
        """
        resolved = os.fspath(path) if path is not None else None
        return cls(_translate(lambda: _NativeClient.open(resolved, dimensions, device_class)))

    @classmethod
    def open_with_host_root(
        cls,
        path: str | os.PathLike[str] | None,
        host_root_secret: bytes,
        *,
        dimensions: int | None = None,
        device_class: str | None = None,
        hold_checkpoint_root_signer: bool | None = None,
    ) -> dict[str, Any]:
        """:meth:`open`, then this install's own machine profile from the vault's host root secret.

        The owner's acts then carry from this install (FIX 5342).
        ``host_root_secret`` is the secret's exact bytes (a server's configured
        ``auth_secret`` as its UTF-8, or a retained root), never hex or base64
        of them. The native side borrows it for this call only and keeps no
        copy.

        Returns ``{"memory", "host_root"}``: the embedded handle, and what the
        open did with the root, ``{"enrolled", "wrong_root"}``. Rooted-only:
        the vault must already be rooted, and nothing here roots it. An empty
        secret raises ``BAD_REQUEST``; a vault open under the managed or relay
        posture, or a root the provider holds, raises ``FORBIDDEN``; a secret
        that cannot profile this install raises the engine's code and reason,
        and :meth:`open` stays the rootless door. A secret that is not the
        vault's settled root, over a profile that already stands, opens and
        says so in ``host_root["wrong_root"]``: reported, never refused. The
        handle binds the local owner actor, as :meth:`open` does, and carries
        no owner proof. ``device_class`` is :meth:`open`'s.
        With ``hold_checkpoint_root_signer`` (FIX 5343) the handle holds this
        install's host root as its checkpoint signer, unless the secret went
        unused; omitted or ``None`` is ``False``.
        """
        resolved = os.fspath(path) if path is not None else None
        native = _translate(
            lambda: _NativeClient.open_with_host_root(
                resolved, host_root_secret, dimensions, device_class, hold_checkpoint_root_signer
            )
        )
        raw = native.host_root_profile()
        profile = json.loads(raw) if raw is not None else {}
        return {
            "memory": cls(native),
            "host_root": {
                "enrolled": bool(profile.get("enrolled", False)),
                "wrong_root": bool(profile.get("wrong_root", False)),
            },
        }

    @classmethod
    def connect(cls, url: str, key: str) -> "Oneiron":
        """Binds a running ``oneiron-server`` through its facade projection.

        Remote connect remains available on targets without embedded open,
        including Windows; the server must run on a supported host.

        ``key`` is the credential :meth:`pair` returned. This package signs
        every request with it and never reads the slip's claims: write
        identity is the server's to decide from the slip it verifies.
        """
        return cls(_translate(lambda: _NativeClient.connect(url, key)))

    @classmethod
    def pair(cls, link: str) -> dict[str, Any]:
        """Redeems a one-use pairing link and connects with its credential.

        Returns ``{"memory", "credential", "pin", "comm"}``: the connected
        handle, the credential, the checkpoint pin the link named (``None``
        when the vault has no attested checkpoint), and the comm reach the
        server says the credential carries (``"parent"``, ``"subtree"``,
        ``"project"`` or ``"vault"``). Store the credential as
        ``ONEIRON_KEY``; the link cannot be redeemed twice. The pin is already
        checked against the link and is stored nowhere: a machine that will
        run a local replica keeps it beside the server origin and the
        credential, and supplies it when that replica starts.
        """
        paired = json.loads(_translate(lambda: _NativeClient.pair(link)))
        return {
            "memory": cls.connect(paired["url"], paired["credential"]),
            "credential": paired["credential"],
            "pin": paired["pin"],
            "comm": paired["comm"],
        }

    def as_actor(self, actor_key: str) -> "Oneiron":
        """Returns a NEW handle bound to another actor; this one is unchanged.

        ``actor_key`` uses the pinned ``human:<ref>`` / ``agent:<ref>`` /
        ``system:<ref>`` grammar. On a connected handle this raises
        ``FORBIDDEN``: a remote principal cannot widen or replace the actor its
        slip bound, so reconnect with a differently scoped slip instead.
        """
        return Oneiron(_translate(lambda: self._client.as_actor(actor_key)))

    def in_room_turn(self, room_ref: str) -> "Oneiron":
        """Returns a NEW handle whose every verb runs as a turn in a room.

        It names only the room. Each verb reads the room's roster as it stands
        at that call and runs inside that roster's Scope (ARCH-0067 §8); a verb
        that would read around the room raises ``BAD_REQUEST``, and so does
        rebinding the actor or naming another room.
        """
        return Oneiron(_translate(lambda: self._client.in_room_turn(room_ref)))

    def in_off_record_session(self, session_ref: str) -> "Oneiron":
        """Returns a NEW handle whose every verb runs inside an off-record session.

        It binds this handle's principal: the app host's actor when embedded,
        the credential's when connected (OF-063). It grants nothing: inside an
        anonymous session that principal is verified in, a refusal writes no
        receipt; anywhere else verbs record as before.
        """
        return Oneiron(_translate(lambda: self._client.in_off_record_session(session_ref)))

    def with_read_credential(self, credential: str) -> "Oneiron":
        """Returns a NEW handle whose every read runs under a delegated reader's credential.

        ``credential`` is the paired credential ``pair`` returned, verified once
        against this vault as the server's door verifies a served request's.
        Reads refuse when the slip's holder is not this handle's actor;
        rebindings keep the same proof, so every read still checks it against
        the bound actor. A handle without one reads as before. On a connected
        handle this raises ``FORBIDDEN``: it already reads under the credential
        it connected with.
        """
        return Oneiron(_translate(lambda: self._client.with_read_credential(credential)))

    def last_receipt_ref(self) -> str | None:
        """The lasting call receipt the last verb's reply stated, as ``call:<32hex>``.

        It is stated whether the call answered or refused, and
        ``vault.receipts.get`` resolves it for the same actor or the vault's
        owner. Typed returns keep their shape; the ref rides beside them here.
        ``None`` for an embedded handle, before any call, after a call that
        reached no server, and for an anonymous off-record call.
        """
        return self._client.last_receipt_ref()

    def last_hook_notice(self) -> str | None:
        """Content-free hook notice beside the last facade call's reply.

        Typed results keep their shape. The next facade call clears this
        before sending; a cloned or vault-direct handle has none. Session-only
        calls may carry a notice without keeping a durable receipt.
        """
        return self._client.last_hook_notice()

    def native_limit_questions(self) -> list[dict[str, Any]] | None:
        """The engine ``[limits]`` rows this client's own vault crossed, latest per row.

        Each entry is ``{"row", "bound", "measured"}`` with exact integers.
        ``None`` on a remote, attached, or rebound view; an empty list where
        no row crossed yet.
        """
        raw = _translate(lambda: self._client.native_limit_questions())
        return json.loads(raw) if raw is not None else None

    def retry(self, pending: OneironError, verb: str, input: Any) -> Any:
        """Resends the call a ``PENDING_ASK`` refusal answered, under its invocation.

        Pass the caught :class:`OneironError`, the verb's SDK name
        (``vault.claims.upsert``) and the same input (ARCH-0080 §3). While the
        ask is open it raises the same ``PENDING_ASK``; once the ask is
        answered proceed, the saved call runs once and this returns its
        result. Any other refusal is refused before a call is made. Run one
        retry of a pending call at a time.

        The reply is the verb's shared wire JSON, not the projection the
        verb's own method returns (``vault.recall`` keeps
        ``confidenceAdjustment``, for one).
        """
        refusal: dict[str, Any] = {
            "code": pending.code,
            "message": pending.message,
            "suggestions": list(pending.suggestions),
        }
        if pending.hook is not None:
            refusal["hook"] = pending.hook
        return json.loads(
            _translate(lambda: self._client.retry(json.dumps(refusal), verb, json.dumps(input)))
        )

    def lens_frame_event(self, card_id: str, request: dict[str, Any]) -> dict[str, Any]:
        """Sends one event on a lens card the connected server rendered (OF-181).

        ``request`` is the route's body, ``{"event": ..., "idempotencyKey":
        ...}``, with the event as the rendered card names it; its keys keep
        the wire's camelCase (``cardId``, ``occurredAt``). A patch-profile
        caller also names ``"stream": "patch"`` (FIX 11399). The reply is
        the wire JSON: ``{"$state": ...}`` for a local action (beside the
        card's refinement for a patch-profile caller), or ``{"outcome":
        ..., "readReceipt": ...}`` for a deterministic tool. A card the server
        no longer holds raises ``NOT_FOUND``: render the lens again. An
        embedded handle raises ``BAD_REQUEST``: lens frames live on the
        served host that rendered the card, so render the lens through a
        connected handle and send its events on that same handle.
        """
        return json.loads(
            _translate(lambda: self._client.lens_frame_event(card_id, json.dumps(request)))
        )

    def close_lens_frame(self, card_id: str) -> dict[str, Any]:
        """Closes a lens card the connected server rendered and frees its frame (OF-181).

        Answers ``{"closed": bool}``; a card the server does not hold answers
        ``False``. An embedded handle raises ``BAD_REQUEST``.
        """
        return json.loads(_translate(lambda: self._client.close_lens_frame(card_id)))

    def export_to(
        self, path: str | os.PathLike[str], format: str | None = None
    ) -> dict[str, Any]:
        """Exports the whole vault into the file at ``path``, owner only.

        As ``vault.export`` does: ``format`` is ``"archive"`` (the default)
        or ``"okf"``. The file is created or truncated; the answer is the
        archive's receipt, ``{"format", "bytes", "digest"}``. Over a server
        the archive streams through a kept transfer, so no ceiling on a
        reply applies to it. A path whose file cannot be created raises
        ``BAD_REQUEST``.
        """
        resolved = os.fspath(path)
        return json.loads(_translate(lambda: self._client.export_to(resolved, format)))

    @staticmethod
    def vault_secrets_custody_seal(
        view: dict[str, Any], change: str, holder: str | None, recipients: list[str], body: bytes
    ) -> dict[str, Any]:
        """Seals a custody register or rotate on the caller's own side (FIX 11441).

        ``view`` is what ``vault.secrets.custody.get`` answered, ``change`` is
        ``"register"`` or ``"rotate"``, ``holder`` the candidate the input is
        sealed to (the view's own install when ``None``), ``recipients`` the
        candidates permitted to hold the bytes (the holder alone when empty)
        and ``body`` a register's whole record or a rotate's new value.
        Answers the ``vault.secrets.custody.submit`` input that carries it. No
        vault is opened and no call is made.
        """
        return json.loads(
            _translate(
                lambda: _NativeClient.vault_secrets_custody_seal(
                    json.dumps(view), change, holder, recipients, body
                )
            )
        )
