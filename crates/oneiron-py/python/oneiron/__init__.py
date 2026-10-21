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
from typing import Any, Callable, TypeVar

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
    that invocation.
    """

    def __init__(
        self,
        code: str,
        message: str,
        suggestions: list[str],
        wrong_root: dict[str, str] | None = None,
        hook: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.suggestions = tuple(suggestions)
        # A ``WRONG_ROOT`` refusal's ``{attempted, replacement, schemaRef}``.
        self.wrong_root = wrong_root
        # The verb hook's stop (ARCH-0080 §3), as the engine's MemoryError names it.
        self.hook = hook


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
        return OneironError(payload["code"], payload["message"], suggestions, wrong_root, hook)
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
        """
        resolved = os.fspath(path) if path is not None else None
        native = _translate(
            lambda: _NativeClient.open_with_host_root(
                resolved, host_root_secret, dimensions, device_class
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

    def last_receipt_ref(self) -> str | None:
        """The lasting call receipt the last verb's reply stated, as ``call:<32hex>``.

        It is stated whether the call answered or refused, and
        ``vault.receipts.get`` resolves it for the same actor or the vault's
        owner. Typed returns keep their shape; the ref rides beside them here.
        ``None`` for an embedded handle, before any call, after a call that
        reached no server, and for an anonymous off-record call.
        """
        return self._client.last_receipt_ref()

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
        the wire's camelCase (``cardId``, ``occurredAt``). The reply is the
        wire JSON: ``{"$state": ...}`` for a local action, or ``{"outcome":
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

    # BEGIN GENERATED FACADE VERBS
    @property
    def vault(self) -> "Oneiron._VaultVerbs":
        return Oneiron._VaultVerbs(self._client)
    def fetch(self, spec):
        """Fetches one HTTP(S) page through the renderer ladder and retains its source as Imported evidence with Proposed claims; never walks links."""
        return json.loads(_translate(lambda: self._client.fetch(json.dumps(spec))))
    def crawl(self, spec):
        """Crawls from one seed under an explicit attempted-page budget, same-origin by default; retains Imported evidence and Proposed claims, and returns failures and completion."""
        return json.loads(_translate(lambda: self._client.crawl(json.dumps(spec))))
    def report(self, spec):
        """Files one feedback report on a skill or run: its subject, category and evidence; the host supplies the actor."""
        return json.loads(_translate(lambda: self._client.report(json.dumps(spec))))
    @property
    def feedback(self) -> "Oneiron._FeedbackVerbs":
        return Oneiron._FeedbackVerbs(self._client)
    @property
    def self(self) -> "Oneiron._SelfVerbs":
        return Oneiron._SelfVerbs(self._client)
    def cancel(self, task_ref: str) -> dict[str, Any]:
        """Cancels one task under the ladder's ``auto`` default. The receipt says what stopped and what became a proposal instead."""
        return json.loads(_translate(lambda: self._client.cancel(json.dumps({"task_ref": task_ref}))))
    def steer(self, spec):
        """The TASK's spawner nudges its live run; a resend with the same key answers the first receipt."""
        return json.loads(_translate(lambda: self._client.steer(json.dumps(spec))))
    def describe(self, task_ref: str | None = None) -> dict[str, Any]:
        """Describes one task's card, or the whole TASKS section when no task is named."""
        return json.loads(_translate(lambda: self._client.describe(json.dumps({"task_ref": task_ref}))))
    @property
    def tasks(self) -> "Oneiron._TasksVerbs":
        return Oneiron._TasksVerbs(self._client)
    @property
    def ai(self) -> "Oneiron._AiVerbs":
        return Oneiron._AiVerbs(self._client)
    @property
    def reveal(self) -> "Oneiron._RevealVerbs":
        return Oneiron._RevealVerbs(self._client)
    @property
    def host(self) -> "Oneiron._HostVerbs":
        return Oneiron._HostVerbs(self._client)
    def mount(self, spec):
        """Open the caller-scoped live graph or a retained repository snapshot, resolving a snapshot id to its exact fork hash."""
        return json.loads(_translate(lambda: self._client.mount(json.dumps(spec))))
    @property
    def graph_fs(self) -> "Oneiron._GraphFsVerbs":
        return Oneiron._GraphFsVerbs(self._client)
    def execute_code(self, spec):
        """Run foreign JavaScript with only scoped record snapshots and inert, receipted proposals in the existing isolated tier; no host writes, credentials or network grant are lent."""
        return json.loads(_translate(lambda: self._client.execute_code(json.dumps(spec))))
    def can(self, request: dict[str, Any]) -> dict[str, Any]:
        """Read-only ask routing or attributed partial answers."""
        return json.loads(_translate(lambda: self._client.can(json.dumps(request, allow_nan=False))))
    def peek(self, request: dict[str, Any]) -> list[dict[str, Any]]:
        """Read-only ask routing or attributed partial answers."""
        return json.loads(_translate(lambda: self._client.peek(json.dumps(request, allow_nan=False))))
    def ask(self, spec_or_who, what=None, until=None, default="ask_me"):
        """Asks people or an authority a typed question and returns at admission with the ask's handle."""
        if what is None:
            input = spec_or_who
        else:
            who = {"people": [spec_or_who]} if isinstance(spec_or_who, str) else {"people": list(spec_or_who)} if isinstance(spec_or_who, (set, list, tuple)) else spec_or_who
            input = {"who": who, "what": what, "until": until, "default": default}
        return json.loads(_translate(lambda: self._client.ask(json.dumps(input))))
    def wait(self, handle, step_key="sdk.wait"):
        """Waits on an ask, or on a world-privacy request its caller opened, at a step with no other work: pending, changed, ready with its result or the request's applied or declined state, or a park for code mode."""
        return json.loads(_translate(lambda: self._client.wait(json.dumps({"handle": handle, "step_key": step_key}))))
    @property
    def connector(self) -> "Oneiron._ConnectorVerbs":
        return Oneiron._ConnectorVerbs(self._client)
    @property
    def calendar(self) -> "Oneiron._CalendarVerbs":
        return Oneiron._CalendarVerbs(self._client)
    class _VaultVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def commitments(self) -> "Oneiron._VaultCommitmentsVerbs":
            return Oneiron._VaultCommitmentsVerbs(self._client)
        @property
        def reports(self) -> "Oneiron._VaultReportsVerbs":
            return Oneiron._VaultReportsVerbs(self._client)
        @property
        def diagnostics(self) -> "Oneiron._VaultDiagnosticsVerbs":
            return Oneiron._VaultDiagnosticsVerbs(self._client)
        @property
        def coach(self) -> "Oneiron._VaultCoachVerbs":
            return Oneiron._VaultCoachVerbs(self._client)
        @property
        def people(self) -> "Oneiron._VaultPeopleVerbs":
            return Oneiron._VaultPeopleVerbs(self._client)
        @property
        def entities(self) -> "Oneiron._VaultEntitiesVerbs":
            return Oneiron._VaultEntitiesVerbs(self._client)
        @property
        def identity(self) -> "Oneiron._VaultIdentityVerbs":
            return Oneiron._VaultIdentityVerbs(self._client)
        @property
        def shape(self) -> "Oneiron._VaultShapeVerbs":
            return Oneiron._VaultShapeVerbs(self._client)
        @property
        def companions(self) -> "Oneiron._VaultCompanionsVerbs":
            return Oneiron._VaultCompanionsVerbs(self._client)
        @property
        def personas(self) -> "Oneiron._VaultPersonasVerbs":
            return Oneiron._VaultPersonasVerbs(self._client)
        @property
        def fanout(self) -> "Oneiron._VaultFanoutVerbs":
            return Oneiron._VaultFanoutVerbs(self._client)
        @property
        def budgets(self) -> "Oneiron._VaultBudgetsVerbs":
            return Oneiron._VaultBudgetsVerbs(self._client)
        def commit_message(self, spec):
            """Writes one whole MESSAGE atomically through the witness gate; birth supplies its immutable conversation, turn and author axes."""
            return json.loads(_translate(lambda: self._client.vault_commit_message(json.dumps(spec))))
        def begin_message_stream(self, spec):
            """Opens one caller-owned MESSAGE stream, with birth axes for a new message or stored axes for a continuation."""
            return json.loads(_translate(lambda: self._client.vault_begin_message_stream(json.dumps(spec))))
        def append_to_stream(self, spec):
            """Appends one authored delta to this actor's generation-bound stream through its existing write gate."""
            return json.loads(_translate(lambda: self._client.vault_append_to_stream(json.dumps(spec))))
        def flush_stream(self, spec):
            """Publishes the current partial at once when streamed visibility allows it; atomic mode stays private."""
            return json.loads(_translate(lambda: self._client.vault_flush_stream(json.dumps(spec))))
        def finalize_stream(self, spec):
            """Commits the stream as final and releases its handle, returning the immutable terminal receipt."""
            return json.loads(_translate(lambda: self._client.vault_finalize_stream(json.dumps(spec))))
        def cancel_stream(self, spec):
            """Keeps the stream's text as one incomplete MESSAGE with cancelled finality and the caller's explicit reason."""
            return json.loads(_translate(lambda: self._client.vault_cancel_stream(json.dumps(spec))))
        def message_stream_partial(self, spec):
            """Reads only this actor's accepted in-memory partial using its generation-bound stream handle."""
            return json.loads(_translate(lambda: self._client.vault_message_stream_partial(json.dumps(spec))))
        @property
        def messages(self) -> "Oneiron._VaultMessagesVerbs":
            return Oneiron._VaultMessagesVerbs(self._client)
        def witness(self, turn: dict[str, Any]) -> dict[str, Any]:
            """Witnesses one conversational turn.

            Omitting ``occurred_at`` stamps the current wall clock, in Unix
            seconds, at the call boundary.
            """
            return json.loads(_translate(lambda: self._client.vault_witness(json.dumps(turn))))
        @property
        def claims(self) -> "Oneiron._VaultClaimsVerbs":
            return Oneiron._VaultClaimsVerbs(self._client)
        def recall(self, query: str, *, effort: str = 'medium', scope: dict[str, Any] | None = None, limit: int = 10, format: str | None = None, as_of: int | None = None, deadline_ms: int | None = None, media: dict[str, Any] | None = None, query_affect: dict[str, Any] | None = None) -> dict[str, Any]:
            """Recalls a memory pack.

            ``effort="high"`` needs a lease this package never mints: an embedded
            client raises ``LEASE_REQUIRED``; a remote one gets what the server
            serves (reranked on its ``[models]`` reranker, or unreranked and
            saying so). ``effort="call"`` is call mode for live calls:
            light effort under a hard deadline (``deadline_ms``, or the vault's
            call-mode deadline), answering with the best results ready, marked
            ``partial``. ``format`` takes the engine's exact tokens:
            ``"json"``, ``"yaml"``, ``"toon"``, ``"md"``, ``"txt"``.
            ``media`` (``{"space", "mime", "bytes_b64", "kinds"}``) is embedded
            by the server into its declared space; an embedded client raises
            ``MODEL_UNAVAILABLE``. ``query_affect`` (``{"valence", "arousal",
            "dominance"}``: valence in -1..1, arousal and dominance in 0..1)
            ranks by emotion congruence, embedded and remote alike; out of range
            it raises ``BAD_REQUEST``.
            
            Explicit ``scope.world_ref`` recalls of retained foreign worlds carry
            ``item["stale"]``: ``stale_since`` and ``age_secs`` (when known),
            ``reason`` and ``pact_epoch``. This selection grants no read authority.
            """
            return json.loads(_translate(lambda: self._client.vault_recall(query, effort, json.dumps(scope) if scope is not None else None, limit, format, as_of, deadline_ms, json.dumps(media) if media is not None else None, json.dumps(query_affect) if query_affect is not None else None)))
        @property
        def retrieval(self) -> "Oneiron._VaultRetrievalVerbs":
            return Oneiron._VaultRetrievalVerbs(self._client)
        @property
        def affect(self) -> "Oneiron._VaultAffectVerbs":
            return Oneiron._VaultAffectVerbs(self._client)
        @property
        def tagging(self) -> "Oneiron._VaultTaggingVerbs":
            return Oneiron._VaultTaggingVerbs(self._client)
        @property
        def cluster(self) -> "Oneiron._VaultClusterVerbs":
            return Oneiron._VaultClusterVerbs(self._client)
        @property
        def export(self) -> "Oneiron._VaultExportVerbs":
            return Oneiron._VaultExportVerbs(self._client)
        @property
        def scope(self) -> "Oneiron._VaultScopeVerbs":
            return Oneiron._VaultScopeVerbs(self._client)
        @property
        def receipts(self) -> "Oneiron._VaultReceiptsVerbs":
            return Oneiron._VaultReceiptsVerbs(self._client)
        @property
        def assets(self) -> "Oneiron._VaultAssetsVerbs":
            return Oneiron._VaultAssetsVerbs(self._client)
        @property
        def search(self) -> "Oneiron._VaultSearchVerbs":
            return Oneiron._VaultSearchVerbs(self._client)
        @property
        def images(self) -> "Oneiron._VaultImagesVerbs":
            return Oneiron._VaultImagesVerbs(self._client)
        @property
        def explain(self) -> "Oneiron._VaultExplainVerbs":
            return Oneiron._VaultExplainVerbs(self._client)
        @property
        def kv(self) -> "Oneiron._VaultKvVerbs":
            return Oneiron._VaultKvVerbs(self._client)
        @property
        def campaign(self) -> "Oneiron._VaultCampaignVerbs":
            return Oneiron._VaultCampaignVerbs(self._client)
        @property
        def turn_programs(self) -> "Oneiron._VaultTurnProgramsVerbs":
            return Oneiron._VaultTurnProgramsVerbs(self._client)
        @property
        def weave(self) -> "Oneiron._VaultWeaveVerbs":
            return Oneiron._VaultWeaveVerbs(self._client)
        @property
        def inbox(self) -> "Oneiron._VaultInboxVerbs":
            return Oneiron._VaultInboxVerbs(self._client)
        @property
        def skills(self) -> "Oneiron._VaultSkillsVerbs":
            return Oneiron._VaultSkillsVerbs(self._client)
        @property
        def skill_hubs(self) -> "Oneiron._VaultSkillHubsVerbs":
            return Oneiron._VaultSkillHubsVerbs(self._client)
        @property
        def packs(self) -> "Oneiron._VaultPacksVerbs":
            return Oneiron._VaultPacksVerbs(self._client)
        @property
        def projects(self) -> "Oneiron._VaultProjectsVerbs":
            return Oneiron._VaultProjectsVerbs(self._client)
        @property
        def connectors(self) -> "Oneiron._VaultConnectorsVerbs":
            return Oneiron._VaultConnectorsVerbs(self._client)
        @property
        def authority(self) -> "Oneiron._VaultAuthorityVerbs":
            return Oneiron._VaultAuthorityVerbs(self._client)
        @property
        def wire_health(self) -> "Oneiron._VaultWireHealthVerbs":
            return Oneiron._VaultWireHealthVerbs(self._client)
        @property
        def slim(self) -> "Oneiron._VaultSlimVerbs":
            return Oneiron._VaultSlimVerbs(self._client)
        @property
        def mesh(self) -> "Oneiron._VaultMeshVerbs":
            return Oneiron._VaultMeshVerbs(self._client)
        @property
        def inspection(self) -> "Oneiron._VaultInspectionVerbs":
            return Oneiron._VaultInspectionVerbs(self._client)
        @property
        def shared(self) -> "Oneiron._VaultSharedVerbs":
            return Oneiron._VaultSharedVerbs(self._client)
        @property
        def org_admin(self) -> "Oneiron._VaultOrgAdminVerbs":
            return Oneiron._VaultOrgAdminVerbs(self._client)
        @property
        def members(self) -> "Oneiron._VaultMembersVerbs":
            return Oneiron._VaultMembersVerbs(self._client)
        @property
        def federation(self) -> "Oneiron._VaultFederationVerbs":
            return Oneiron._VaultFederationVerbs(self._client)
        @property
        def trusted_contacts(self) -> "Oneiron._VaultTrustedContactsVerbs":
            return Oneiron._VaultTrustedContactsVerbs(self._client)
        @property
        def guests(self) -> "Oneiron._VaultGuestsVerbs":
            return Oneiron._VaultGuestsVerbs(self._client)
        @property
        def support_grants(self) -> "Oneiron._VaultSupportGrantsVerbs":
            return Oneiron._VaultSupportGrantsVerbs(self._client)
        @property
        def residence(self) -> "Oneiron._VaultResidenceVerbs":
            return Oneiron._VaultResidenceVerbs(self._client)
        @property
        def off_record(self) -> "Oneiron._VaultOffRecordVerbs":
            return Oneiron._VaultOffRecordVerbs(self._client)
        @property
        def records(self) -> "Oneiron._VaultRecordsVerbs":
            return Oneiron._VaultRecordsVerbs(self._client)
        @property
        def research(self) -> "Oneiron._VaultResearchVerbs":
            return Oneiron._VaultResearchVerbs(self._client)
        @property
        def evals(self) -> "Oneiron._VaultEvalsVerbs":
            return Oneiron._VaultEvalsVerbs(self._client)
        @property
        def roots(self) -> "Oneiron._VaultRootsVerbs":
            return Oneiron._VaultRootsVerbs(self._client)
        @property
        def cleanup(self) -> "Oneiron._VaultCleanupVerbs":
            return Oneiron._VaultCleanupVerbs(self._client)
        @property
        def usage(self) -> "Oneiron._VaultUsageVerbs":
            return Oneiron._VaultUsageVerbs(self._client)
        @property
        def legal_holds(self) -> "Oneiron._VaultLegalHoldsVerbs":
            return Oneiron._VaultLegalHoldsVerbs(self._client)
        @property
        def courtesy_delete(self) -> "Oneiron._VaultCourtesyDeleteVerbs":
            return Oneiron._VaultCourtesyDeleteVerbs(self._client)
        @property
        def embedding_spaces(self) -> "Oneiron._VaultEmbeddingSpacesVerbs":
            return Oneiron._VaultEmbeddingSpacesVerbs(self._client)
        @property
        def policy(self) -> "Oneiron._VaultPolicyVerbs":
            return Oneiron._VaultPolicyVerbs(self._client)
        @property
        def consent(self) -> "Oneiron._VaultConsentVerbs":
            return Oneiron._VaultConsentVerbs(self._client)
        @property
        def gate(self) -> "Oneiron._VaultGateVerbs":
            return Oneiron._VaultGateVerbs(self._client)
        @property
        def learning(self) -> "Oneiron._VaultLearningVerbs":
            return Oneiron._VaultLearningVerbs(self._client)
        @property
        def seal(self) -> "Oneiron._VaultSealVerbs":
            return Oneiron._VaultSealVerbs(self._client)
        @property
        def settings(self) -> "Oneiron._VaultSettingsVerbs":
            return Oneiron._VaultSettingsVerbs(self._client)
        @property
        def secrets(self) -> "Oneiron._VaultSecretsVerbs":
            return Oneiron._VaultSecretsVerbs(self._client)
        @property
        def widen_proposals(self) -> "Oneiron._VaultWidenProposalsVerbs":
            return Oneiron._VaultWidenProposalsVerbs(self._client)
        @property
        def craft_candidates(self) -> "Oneiron._VaultCraftCandidatesVerbs":
            return Oneiron._VaultCraftCandidatesVerbs(self._client)
        @property
        def lenses(self) -> "Oneiron._VaultLensesVerbs":
            return Oneiron._VaultLensesVerbs(self._client)
        @property
        def disclosure(self) -> "Oneiron._VaultDisclosureVerbs":
            return Oneiron._VaultDisclosureVerbs(self._client)
        @property
        def shares(self) -> "Oneiron._VaultSharesVerbs":
            return Oneiron._VaultSharesVerbs(self._client)
        @property
        def hooks(self) -> "Oneiron._VaultHooksVerbs":
            return Oneiron._VaultHooksVerbs(self._client)
        @property
        def artifacts(self) -> "Oneiron._VaultArtifactsVerbs":
            return Oneiron._VaultArtifactsVerbs(self._client)
        @property
        def code(self) -> "Oneiron._VaultCodeVerbs":
            return Oneiron._VaultCodeVerbs(self._client)
        @property
        def results(self) -> "Oneiron._VaultResultsVerbs":
            return Oneiron._VaultResultsVerbs(self._client)
        @property
        def agents(self) -> "Oneiron._VaultAgentsVerbs":
            return Oneiron._VaultAgentsVerbs(self._client)
        @property
        def repo(self) -> "Oneiron._VaultRepoVerbs":
            return Oneiron._VaultRepoVerbs(self._client)
        @property
        def standing_blocks(self) -> "Oneiron._VaultStandingBlocksVerbs":
            return Oneiron._VaultStandingBlocksVerbs(self._client)
        @property
        def workflows(self) -> "Oneiron._VaultWorkflowsVerbs":
            return Oneiron._VaultWorkflowsVerbs(self._client)
        @property
        def task_types(self) -> "Oneiron._VaultTaskTypesVerbs":
            return Oneiron._VaultTaskTypesVerbs(self._client)
        @property
        def tasks(self) -> "Oneiron._VaultTasksVerbs":
            return Oneiron._VaultTasksVerbs(self._client)
        @property
        def runs(self) -> "Oneiron._VaultRunsVerbs":
            return Oneiron._VaultRunsVerbs(self._client)
        @property
        def consults(self) -> "Oneiron._VaultConsultsVerbs":
            return Oneiron._VaultConsultsVerbs(self._client)
        @property
        def workspace(self) -> "Oneiron._VaultWorkspaceVerbs":
            return Oneiron._VaultWorkspaceVerbs(self._client)
        @property
        def critic(self) -> "Oneiron._VaultCriticVerbs":
            return Oneiron._VaultCriticVerbs(self._client)
        @property
        def rooms(self) -> "Oneiron._VaultRoomsVerbs":
            return Oneiron._VaultRoomsVerbs(self._client)
        @property
        def conversations(self) -> "Oneiron._VaultConversationsVerbs":
            return Oneiron._VaultConversationsVerbs(self._client)
        @property
        def models(self) -> "Oneiron._VaultModelsVerbs":
            return Oneiron._VaultModelsVerbs(self._client)
        @property
        def voices(self) -> "Oneiron._VaultVoicesVerbs":
            return Oneiron._VaultVoicesVerbs(self._client)
        @property
        def graph(self) -> "Oneiron._VaultGraphVerbs":
            return Oneiron._VaultGraphVerbs(self._client)
        @property
        def questions(self) -> "Oneiron._VaultQuestionsVerbs":
            return Oneiron._VaultQuestionsVerbs(self._client)
        @property
        def decisions(self) -> "Oneiron._VaultDecisionsVerbs":
            return Oneiron._VaultDecisionsVerbs(self._client)
        def commit(self, input: dict[str, Any]) -> Any:
            """Commits claims through the gate, each element its own write; each answers its landed receipt, or its typed refusal and refusal receipt when nothing of it persisted."""
            return json.loads(_translate(lambda: self._client.vault_commit(json.dumps(input, allow_nan=False))))
        def remember(self, input: dict[str, Any]) -> Any:
            """Commits one claim through the gate, the same as vault.claims.upsert."""
            return json.loads(_translate(lambda: self._client.vault_remember(json.dumps(input, allow_nan=False))))
        def forget(self, input: dict[str, Any]) -> Any:
            """Retracts claims by exact claim or by subject and predicate; never a hard delete."""
            return json.loads(_translate(lambda: self._client.vault_forget(json.dumps(input, allow_nan=False))))
        @property
        def booking(self) -> "Oneiron._VaultBookingVerbs":
            return Oneiron._VaultBookingVerbs(self._client)
        @property
        def calendar(self) -> "Oneiron._VaultCalendarVerbs":
            return Oneiron._VaultCalendarVerbs(self._client)
        def delete(self, input: dict[str, Any]) -> Any:
            """Deletes one entity under a named reason; an owner verb that only a verified human may call."""
            return json.loads(_translate(lambda: self._client.vault_delete(json.dumps(input, allow_nan=False))))
        @property
        def writes(self) -> "Oneiron._VaultWritesVerbs":
            return Oneiron._VaultWritesVerbs(self._client)
        def hydrate(self, input: dict[str, Any]) -> Any:
            """Hydrates short refs or hex ids to full entity views, with the read's receipt."""
            return json.loads(_translate(lambda: self._client.vault_hydrate(json.dumps(input, allow_nan=False))))
        def get(self, input: dict[str, Any]) -> Any:
            """Reads one entity as a typed view, or none when absent or withheld; the receipt says which."""
            return json.loads(_translate(lambda: self._client.vault_get(json.dumps(input, allow_nan=False))))
        @property
        def refs(self) -> "Oneiron._VaultRefsVerbs":
            return Oneiron._VaultRefsVerbs(self._client)
        @property
        def vectors(self) -> "Oneiron._VaultVectorsVerbs":
            return Oneiron._VaultVectorsVerbs(self._client)
        def neighbors(self, input: dict[str, Any]) -> Any:
            """The weighted-edge neighbourhood of one entity, filtered by edge kind and minimum weight."""
            return json.loads(_translate(lambda: self._client.vault_neighbors(json.dumps(input, allow_nan=False))))
        @property
        def structural(self) -> "Oneiron._VaultStructuralVerbs":
            return Oneiron._VaultStructuralVerbs(self._client)
        @property
        def habits(self) -> "Oneiron._VaultHabitsVerbs":
            return Oneiron._VaultHabitsVerbs(self._client)
        @property
        def productivity(self) -> "Oneiron._VaultProductivityVerbs":
            return Oneiron._VaultProductivityVerbs(self._client)
        @property
        def esign(self) -> "Oneiron._VaultEsignVerbs":
            return Oneiron._VaultEsignVerbs(self._client)
        def batch(self, spec):
            """Commits up to 256 core entity puts atomically, at the grade of the credential that sent them; an embedded handle commits below owner grade."""
            return json.loads(_translate(lambda: self._client.vault_batch(json.dumps(spec))))
        @property
        def consolidation(self) -> "Oneiron._VaultConsolidationVerbs":
            return Oneiron._VaultConsolidationVerbs(self._client)
        @property
        def sieve(self) -> "Oneiron._VaultSieveVerbs":
            return Oneiron._VaultSieveVerbs(self._client)
        @property
        def free_time(self) -> "Oneiron._VaultFreeTimeVerbs":
            return Oneiron._VaultFreeTimeVerbs(self._client)
        @property
        def memory(self) -> "Oneiron._VaultMemoryVerbs":
            return Oneiron._VaultMemoryVerbs(self._client)
        @property
        def channel_identities(self) -> "Oneiron._VaultChannelIdentitiesVerbs":
            return Oneiron._VaultChannelIdentitiesVerbs(self._client)
        @property
        def delivery_window(self) -> "Oneiron._VaultDeliveryWindowVerbs":
            return Oneiron._VaultDeliveryWindowVerbs(self._client)
        @property
        def summaries(self) -> "Oneiron._VaultSummariesVerbs":
            return Oneiron._VaultSummariesVerbs(self._client)
        @property
        def notes(self) -> "Oneiron._VaultNotesVerbs":
            return Oneiron._VaultNotesVerbs(self._client)
        def revert_run(self, spec):
            """The owner compensates all or selected changes of a settled run, preserving later work and listing every change not undone and why."""
            return json.loads(_translate(lambda: self._client.vault_revert_run(json.dumps(spec))))
    class _VaultCommitmentsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """Creates an authored commitment series and its due index atomically, without approving a reminder."""
            return json.loads(_translate(lambda: self._client.vault_commitments_create(json.dumps(spec))))
        def get(self, spec):
            """Reads a commitment with its schedule, birth provenance, separate occurrence and learning times, and lifecycle receipt."""
            return json.loads(_translate(lambda: self._client.vault_commitments_get(json.dumps(spec))))
        def instances(self, spec):
            """Lists the materialized occurrences of a commitment series, including closed obligations."""
            return json.loads(_translate(lambda: self._client.vault_commitments_instances(json.dumps(spec))))
        def proposals(self, spec):
            """Observes real timer-wake reminder proposals and their run approval keys without authorizing delivery."""
            return json.loads(_translate(lambda: self._client.vault_commitments_proposals(json.dumps(spec))))
        def fulfill(self, spec):
            """Explicitly confirms an obligation fulfilled with witness evidence through the existing fulfillment dispatcher."""
            return json.loads(_translate(lambda: self._client.vault_commitments_fulfill(json.dumps(spec))))
        def release(self, spec):
            """Explicitly releases an obligation with witness evidence and clears its due phases in the same transaction."""
            return json.loads(_translate(lambda: self._client.vault_commitments_release(json.dumps(spec))))
        def supersede(self, spec):
            """Explicitly supersedes an obligation with witness evidence and clears its due phases in the same transaction."""
            return json.loads(_translate(lambda: self._client.vault_commitments_supersede(json.dumps(spec))))
    class _VaultReportsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def disclosure(self, spec):
            """The owner decides whether one publisher-routed report's exact quoted text may cross to its publisher: approve once, stop asking, or deny."""
            return json.loads(_translate(lambda: self._client.vault_reports_disclosure(json.dumps(spec))))
        def route(self, spec):
            """The owner replaces one durable subject's maker route: the owner inbox, or one admitted publisher its feedback is delivered to."""
            return json.loads(_translate(lambda: self._client.vault_reports_route(json.dumps(spec))))
        def outbound(self, spec):
            """The owner reads the content-free payload a publisher delivery for one report issue would carry now, with its quoted text only when disclosure approved it."""
            return json.loads(_translate(lambda: self._client.vault_reports_outbound(json.dumps(spec))))
    class _VaultDiagnosticsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec):
            """Lists the engine-authored diagnostic events the caller reads, by class, actor, or evidence, with the read's narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_diagnostics_list(json.dumps(spec))))
        def get(self, spec):
            """Reads one diagnostic event the caller may read, by ref, with the read's narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_diagnostics_get(json.dumps(spec))))
    class _VaultCoachVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def inspect(self, spec):
            """Inspects one blocked report as the Coach reads it: its fenced receipt, linked diagnostic band, working set, and the repair proposal the Coach filed, through the caller's own lane."""
            return json.loads(_translate(lambda: self._client.vault_coach_inspect(json.dumps(spec))))
        @property
        def training_offers(self) -> "Oneiron._VaultCoachTrainingOffersVerbs":
            return Oneiron._VaultCoachTrainingOffersVerbs(self._client)
    class _VaultCoachTrainingOffersVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Read Coach offer snapshots, their exact owner answers and later promise checks; optionally select a seat or only pending offers."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers(json.dumps(spec))))
        def get(self, spec):
            """Read one Coach offer snapshot with its owner answer and receipt-backed promise checks."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_get(json.dumps(spec))))
        def trigger(self, spec):
            """Queue one production Coach training-offer pass under the owner proof; the offer skill decides what to raise and no caller supplies an offer body."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_trigger(json.dumps(spec))))
        def result(self, spec):
            """Read the production Coach offer attempt state and the exact snapshots it raised; a completed pass may raise no offer."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_result(json.dumps(spec))))
        def answer(self, spec):
            """Answer the exact shown Coach snapshot: keep baseline, decline, postpone, approve switch or approve train; training still needs its separate result-swap choice."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_answer(json.dumps(spec))))
        def undo(self, spec):
            """Undo an approved stock switch only while its own seat still holds the switched binding; restore the previous whole binding."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_undo(json.dumps(spec))))
        @property
        def candidates(self) -> "Oneiron._VaultCoachTrainingOffersCandidatesVerbs":
            return Oneiron._VaultCoachTrainingOffersCandidatesVerbs(self._client)
        @property
        def pilots(self) -> "Oneiron._VaultCoachTrainingOffersPilotsVerbs":
            return Oneiron._VaultCoachTrainingOffersPilotsVerbs(self._client)
    class _VaultCoachTrainingOffersCandidatesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Read pinned own-seat stock or training-recipe candidates, including their incumbent and explicit compute destination."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_candidates(json.dumps(spec))))
        def prepare(self, spec):
            """Pin an own-seat catalog stock candidate or existing training recipe and its destination; this nominates only and never switches, downloads or trains."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_candidates_prepare(json.dumps(spec))))
    class _VaultCoachTrainingOffersPilotsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def prepare(self, spec):
            """Prepare an eval-only pilot of a pinned seat candidate, counting its sealed cohort exposure before releasing receipt-backed cases; launch no compute or egress."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_pilots_prepare(json.dumps(spec))))
        def complete(self, spec):
            """Record immutable owner-evaluator pilot measurements bound to counted own-seat families; fixed code derives sufficiency and preserves unknown cost and score."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_pilots_complete(json.dumps(spec))))
        def get(self, spec):
            """Read one counted Coach pilot, its pins, measurement receipts, one-off cost and computed sufficiency card."""
            return json.loads(_translate(lambda: self._client.vault_coach_training_offers_pilots_get(json.dumps(spec))))
    class _VaultPeopleVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec):
            """One page of the people the caller reads, in handle order."""
            return json.loads(_translate(lambda: self._client.vault_people_list(json.dumps(spec))))
        def get(self, spec):
            """One person the vault knows, by their pr handle."""
            return json.loads(_translate(lambda: self._client.vault_people_get(json.dumps(spec))))
        def create(self, spec):
            """The owner creates a distinct PERSON with declared identity hints and existing identity-evidence refs, looking before minting an opaque id without selecting or merging a namesake."""
            return json.loads(_translate(lambda: self._client.vault_people_create(json.dumps(spec))))
    class _VaultEntitiesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def look_before_mint(self, spec):
            """The owner queries the declared PERSON, ORG or PLACE identity hints for N candidates with evidence and provenance; only stored mention evidence is scored by the waterfall, and no entity is restored, linked or minted."""
            return json.loads(_translate(lambda: self._client.vault_entities_look_before_mint(json.dumps(spec))))
        def mention(self, spec):
            """The owner resolves an evidence-backed mention through the existing waterfall, restoring its selected archived record in place and never minting a duplicate."""
            return json.loads(_translate(lambda: self._client.vault_entities_mention(json.dumps(spec))))
    class _VaultIdentityVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def mention(self, spec):
            """The owner reads one saved mention as unresolved, candidates or resolved, preserving the original tagger suggestion and the resolving owner evidence and provenance."""
            return json.loads(_translate(lambda: self._client.vault_identity_mention(json.dumps(spec))))
        def merge(self, spec):
            """The owner merges source identities into a survivor, retaining claim subjects and append-only evidence."""
            return json.loads(_translate(lambda: self._client.vault_identity_merge(json.dumps(spec))))
        def split(self, spec):
            """The owner splits an identity into zero, one or many heads using an evidence-guided reassignment map."""
            return json.loads(_translate(lambda: self._client.vault_identity_split(json.dumps(spec))))
        def facet(self, spec):
            """The owner mints identity facets and forks assigned claims under their masks without restamping original claims."""
            return json.loads(_translate(lambda: self._client.vault_identity_facet(json.dumps(spec))))
        def assert_distinct(self, spec):
            """The owner asserts two identities are distinct through one symmetric claim that suppresses merge re-proposals."""
            return json.loads(_translate(lambda: self._client.vault_identity_assert_distinct(json.dumps(spec))))
        def propose(self, spec):
            """The owner parks a nominated merge or split candidate with no topology effects; distinct pairs suppress merge proposals."""
            return json.loads(_translate(lambda: self._client.vault_identity_propose(json.dumps(spec))))
        def undo(self, spec):
            """The owner undoes one current topology event by appending a counter-event under its observed revision."""
            return json.loads(_translate(lambda: self._client.vault_identity_undo(json.dumps(spec))))
        def resolve(self, spec):
            """The owner resolves an identity to its current head set and reads shell edges, facets and evidence assignments."""
            return json.loads(_translate(lambda: self._client.vault_identity_resolve(json.dumps(spec))))
        @property
        def events(self) -> "Oneiron._VaultIdentityEventsVerbs":
            return Oneiron._VaultIdentityEventsVerbs(self._client)
        @property
        def proposals(self) -> "Oneiron._VaultIdentityProposalsVerbs":
            return Oneiron._VaultIdentityProposalsVerbs(self._client)
    class _VaultIdentityEventsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """The owner reads one topology decision with its actor, evidence, action and current decision revision."""
            return json.loads(_translate(lambda: self._client.vault_identity_events_get(json.dumps(spec))))
    class _VaultIdentityProposalsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def resolve(self, spec):
            """The owner approves, amends then approves, or rejects a parked topology proposal under its observed revision."""
            return json.loads(_translate(lambda: self._client.vault_identity_proposals_resolve(json.dumps(spec))))
        def for_pair(self, spec):
            """The owner reads open merge proposals and effective distinctness claims for an unordered identity pair."""
            return json.loads(_translate(lambda: self._client.vault_identity_proposals_for_pair(json.dumps(spec))))
    class _VaultShapeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, spec=None):
            """The vault's stored seed and its live setup plane held as one document (ARCH-0070); a free read."""
            return json.loads(_translate(lambda: self._client.vault_shape_read(json.dumps({} if spec is None else spec))))
        def plan(self, spec):
            """The difference between a seed, or the stored one, and the vault, item by item at a pinned frontier; a free read that writes nothing."""
            return json.loads(_translate(lambda: self._client.vault_shape_plan(json.dumps(spec))))
        def apply(self, spec):
            """Lands a shape plan one item at a time through the vault's named doors, or resumes its apply; a widening lands only on the owner's word for that item."""
            return json.loads(_translate(lambda: self._client.vault_shape_apply(json.dumps(spec))))
    class _VaultCompanionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def access_requests(self) -> "Oneiron._VaultCompanionsAccessRequestsVerbs":
            return Oneiron._VaultCompanionsAccessRequestsVerbs(self._client)
        @property
        def sharing(self) -> "Oneiron._VaultCompanionsSharingVerbs":
            return Oneiron._VaultCompanionsSharingVerbs(self._client)
    class _VaultCompanionsAccessRequestsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def answer(self, spec):
            """The owner approves or denies one pending companion-profile request, atomically recording the answer and its exact grant."""
            return json.loads(_translate(lambda: self._client.vault_companions_access_requests_answer(json.dumps(spec))))
    class _VaultCompanionsSharingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """One contact's clearance in a companion's source vault, for the principal who controls that vault."""
            return json.loads(_translate(lambda: self._client.vault_companions_sharing_get(json.dumps(spec))))
        def set(self, spec):
            """The owner's standing yes to one frozen clearance offer for a companion's contact."""
            return json.loads(_translate(lambda: self._client.vault_companions_sharing_set(json.dumps(spec))))
    class _VaultPersonasVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def preview(self, spec):
            """Previews the owner's strikeable persona snapshot, with sources and its content-bound consent stamp."""
            return json.loads(_translate(lambda: self._client.vault_personas_preview(json.dumps(spec))))
        def export(self, spec):
            """Issues the exact previewed mode-A persona copy after explicit row strikes; a changed preview refuses stale consent."""
            return json.loads(_translate(lambda: self._client.vault_personas_export(json.dumps(spec))))
        def edit(self, spec):
            """Edits an accepted persona copy into a new receipted export, preserving citations, exclusions and the already handed version."""
            return json.loads(_translate(lambda: self._client.vault_personas_edit(json.dumps(spec))))
    class _VaultFanoutVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def spawn(self, spec):
            """Admits input-order child slots under this credential's attached live run, through the frozen fan-out approval gate and one shared parent spend tree."""
            return json.loads(_translate(lambda: self._client.vault_fanout_spawn(json.dumps(spec))))
        def slots(self, spec):
            """Reads a batch launch in input slot order, with child errors, results, reservations, settled spend and released holds from its shared parent lease tree."""
            return json.loads(_translate(lambda: self._client.vault_fanout_slots(json.dumps(spec))))
        def launch(self, spec):
            """One held or launched fan-out by its launch ref, with the statement frozen before it launched; readable by the vault owner, its creator, or a live lead/board holder of its project, anything else reads as none."""
            return json.loads(_translate(lambda: self._client.vault_fanout_launch(json.dumps(spec))))
        def resume(self, spec):
            """The owner rules on a held fan-out launch by the digest they saw: approve once, approve and remember under a cap, or deny, which keeps the hold visible."""
            return json.loads(_translate(lambda: self._client.vault_fanout_resume(json.dumps(spec))))
        def resume_as(self, spec):
            """A live lead or board holder of a held fan-out launch's project rules on it by the digest they saw: approve once, or deny, which keeps the hold visible; only the owner may remember."""
            return json.loads(_translate(lambda: self._client.vault_fanout_resume_as(json.dumps(spec))))
        def ack(self, spec):
            """The owner acknowledges the width check of a fan-out that already went out, once or remembered under a cap; nothing was held, so nothing is denied."""
            return json.loads(_translate(lambda: self._client.vault_fanout_ack(json.dumps(spec))))
    class _VaultBudgetsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def lease(self) -> "Oneiron._VaultBudgetsLeaseVerbs":
            return Oneiron._VaultBudgetsLeaseVerbs(self._client)
        @property
        def hold(self) -> "Oneiron._VaultBudgetsHoldVerbs":
            return Oneiron._VaultBudgetsHoldVerbs(self._client)
        def local(self, spec):
            """The owner observes a device-local runner budget counter without creating it, including absence after an owner restore."""
            return json.loads(_translate(lambda: self._client.vault_budgets_local(json.dumps(spec))))
        def reservations(self, spec):
            """The owner reads a device-local runner budget counter and one page of the child reservations held against it, without creating or refilling it."""
            return json.loads(_translate(lambda: self._client.vault_budgets_reservations(json.dumps(spec))))
        def settlements(self, spec):
            """The owner reads a served run's persisted physical-rung settlement receipts, with reservation, settled units and stamped cost when priced."""
            return json.loads(_translate(lambda: self._client.vault_budgets_settlements(json.dumps(spec))))
        @property
        def rsi(self) -> "Oneiron._VaultBudgetsRsiVerbs":
            return Oneiron._VaultBudgetsRsiVerbs(self._client)
    class _VaultBudgetsLeaseVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads a persisted spend lease, its remaining allowance and the hard ancestor that binds it."""
            return json.loads(_translate(lambda: self._client.vault_budgets_lease(json.dumps(spec))))
        def open(self, spec):
            """The owner opens a persisted launch spend lease under the maximum the customer set and saw, in its declared unit."""
            return json.loads(_translate(lambda: self._client.vault_budgets_lease_open(json.dumps(spec))))
        def top_up(self, spec):
            """The owner raises a hard lease to a shown replacement maximum; replay adds nothing twice and a child's increase stays within its ancestor's cap."""
            return json.loads(_translate(lambda: self._client.vault_budgets_lease_top_up(json.dumps(spec))))
    class _VaultBudgetsHoldVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads a held run's notice, saved partial results, exact checkpoints and whether its existing lease permits resume."""
            return json.loads(_translate(lambda: self._client.vault_budgets_hold(json.dumps(spec))))
        def resume(self, spec):
            """The owner resumes the same held attempts from their checkpoints after their lease has funds; no model substitution or terminal completion."""
            return json.loads(_translate(lambda: self._client.vault_budgets_hold_resume(json.dumps(spec))))
    class _VaultBudgetsRsiVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads both RSI lines, every soft and pinned share, and whether new loop work is held. A hold reads as suspended, never as a terminal failure."""
            return json.loads(_translate(lambda: self._client.vault_budgets_rsi(json.dumps(spec))))
        def configure(self, spec):
            """The owner creates the vault RSI line once: its token limit, its independent exploration exposure limit, and its soft and owner-pinned shares. Reconfiguration cannot erase receipts or spend."""
            return json.loads(_translate(lambda: self._client.vault_budgets_rsi_configure(json.dumps(spec))))
        def top_up(self, spec):
            """The owner raises one exact limiting RSI line by its units: the token limit, the exploration exposure limit, or one named share. A top-up never lowers a line and never resumes held work by itself."""
            return json.loads(_translate(lambda: self._client.vault_budgets_rsi_top_up(json.dumps(spec))))
        @property
        def hold(self) -> "Oneiron._VaultBudgetsRsiHoldVerbs":
            return Oneiron._VaultBudgetsRsiHoldVerbs(self._client)
    class _VaultBudgetsRsiHoldVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner holds new RSI loop work rather than killing it; admitted reservations can still settle, and pending attempts, candidates and partial outputs stay."""
            return json.loads(_translate(lambda: self._client.vault_budgets_rsi_hold(json.dumps(spec))))
        def resume(self, spec):
            """The owner releases the RSI hold on the same line and receipts, so the same pending try continues without a new experiment or a duplicate terminal receipt."""
            return json.loads(_translate(lambda: self._client.vault_budgets_rsi_hold_resume(json.dumps(spec))))
    class _VaultMessagesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def durability(self, spec):
            """Reads a MESSAGE's completion, terminal-generation receipts and retained document history through the caller's own read lane."""
            return json.loads(_translate(lambda: self._client.vault_messages_durability(json.dumps(spec))))
        def react(self, spec):
            """Puts or removes the caller's own reaction on a message or turn; an owner-grade host also brings a provider's reaction as connector ingress."""
            return json.loads(_translate(lambda: self._client.vault_messages_react(json.dumps(spec))))
    class _VaultClaimsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def upsert(self, spec):
            """Admits an explicitly four-axis claim through the caller credential and existing gate, with host-authored provenance."""
            return json.loads(_translate(lambda: self._client.vault_claims_upsert(json.dumps(spec))))
        def review(self, spec):
            """The owner reviews one proposed claim: the claim as the owner may read it, its opener and tray row, and the review_id that settles exactly this content."""
            return json.loads(_translate(lambda: self._client.vault_claims_review(json.dumps(spec))))
        def settle(self, spec):
            """The owner approves or rejects exactly the reviewed proposed claim through the gate and keeps its Settlement; a claim changed since its review_id is refused."""
            return json.loads(_translate(lambda: self._client.vault_claims_settle(json.dumps(spec))))
        def retract(self, input: dict[str, Any]) -> Any:
            """Retracts one active claim: a deliberate withdrawal that preserves the record."""
            return json.loads(_translate(lambda: self._client.vault_claims_retract(json.dumps(input, allow_nan=False))))
        def list(self, input: dict[str, Any]) -> Any:
            """Lists claims by subject, predicate and lifecycle, with the read's narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_claims_list(json.dumps(input, allow_nan=False))))
        def demote(self, input: dict[str, Any]) -> Any:
            """Demotes one active claim by one rung through the caller credential: decay its claim_of weight, weaken it to a successor at lower confidence, or mark it stale in place so retrieval stops surfacing it."""
            return json.loads(_translate(lambda: self._client.vault_claims_demote(json.dumps(input, allow_nan=False))))
        def list_filtered(self, input: dict[str, Any]) -> Any:
            """Lists surfaceable claims by subject, predicate and lifecycle under the caller retrieval filter met with the actor ceiling, with the read narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_claims_list_filtered(json.dumps(input, allow_nan=False))))
        def read_filtered(self, input: dict[str, Any]) -> Any:
            """Reads one claim as retrieval would surface it under the caller retrieval filter met with the actor ceiling, with the read narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_claims_read_filtered(json.dumps(input, allow_nan=False))))
        def history(self, input: dict[str, Any]) -> Any:
            """The supersession timeline of one claim, oldest first, with the read's narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_claims_history(json.dumps(input, allow_nan=False))))
        def admit(self, input: dict[str, Any]) -> Any:
            """Admits one imported-evidence claim through its ingest source's trust ceiling; the gate still decides."""
            return json.loads(_translate(lambda: self._client.vault_claims_admit(json.dumps(input, allow_nan=False))))
        def vet(self, spec):
            """Vets a reviewed generated-origin Auto claim or proposal through the owner Gate and signed settlement; it still contributes zero corroboration."""
            return json.loads(_translate(lambda: self._client.vault_claims_vet(json.dumps(spec))))
        def vetting(self, spec):
            """Reviews an exact generated-origin Auto claim or proposal before owner vetting, returning the content-bound review handle."""
            return json.loads(_translate(lambda: self._client.vault_claims_vetting(json.dumps(spec))))
        def seed(self, input: dict[str, Any]) -> Any:
            """Seeds claims through their individual gates, forced proposed, returning per claim its landed receipt or its typed refusal and refusal receipt."""
            return json.loads(_translate(lambda: self._client.vault_claims_seed(json.dumps(input, allow_nan=False))))
        def supersede(self, spec):
            """Supersedes through this credential's attached generated-writing run and its existing gates; spec is {newId,oldId,now}, never an actor or source override."""
            return json.loads(_translate(lambda: self._client.vault_claims_supersede(json.dumps(spec))))
    class _VaultRetrievalVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def aging(self) -> "Oneiron._VaultRetrievalAgingVerbs":
            return Oneiron._VaultRetrievalAgingVerbs(self._client)
        @property
        def weights(self) -> "Oneiron._VaultRetrievalWeightsVerbs":
            return Oneiron._VaultRetrievalWeightsVerbs(self._client)
        @property
        def hyde(self) -> "Oneiron._VaultRetrievalHydeVerbs":
            return Oneiron._VaultRetrievalHydeVerbs(self._client)
        def recall(self, spec):
            """Recalls through the normal credential-bound serving pipeline as the owner, with typed opt-in turn and trace capture and the actual finalized run handle."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_recall(json.dumps(spec))))
        def runs(self, spec):
            """The owner reads finalized local retrieval runs and their independent outcome sidecars, newest first."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_runs(json.dumps(spec))))
        def run(self, spec):
            """The owner reads one finalized local serving run, its turn, policy state, trace and explicit outcomes; an unknown run reads as none."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_run(json.dumps(spec))))
        def turn(self, spec):
            """The owner reads the independent finalized retrieval runs linked to one exact turn, in recorded order."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_turn(json.dumps(spec))))
        @property
        def outcomes(self) -> "Oneiron._VaultRetrievalOutcomesVerbs":
            return Oneiron._VaultRetrievalOutcomesVerbs(self._client)
        def trace(self, spec):
            """The owner reads an opt-in trace by its vault-local keyed fork hash; hashes are never comparable across vaults."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_trace(json.dumps(spec))))
        def export(self, spec):
            """The owner exports finalized run evidence without query or pack text, raw frontier samples, trace keys or free-form outcome metadata."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_export(json.dumps(spec))))
        def replay(self, spec):
            """The owner replays recorded state, ordered pack scores and trace from exact finalized runs; no fresh search, clock or outcome-derived feature is used."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_replay(json.dumps(spec))))
        @property
        def policy(self) -> "Oneiron._VaultRetrievalPolicyVerbs":
            return Oneiron._VaultRetrievalPolicyVerbs(self._client)
    class _VaultRetrievalAgingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """The owner reads class-level exponential aging profiles and the trusted manifest hash; confidence never ages."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_aging_get(json.dumps({} if spec is None else spec))))
        def configure(self, spec):
            """The owner edits all class-aging profiles against the current manifest hash without rewriting confidence, lifecycle or claim bodies."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_aging_configure(json.dumps(spec))))
    class _VaultRetrievalWeightsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """The owner reads effective affect, arousal, community and semantic-edge VAD priors with the trusted manifest hash."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_weights_get(json.dumps({} if spec is None else spec))))
        def configure(self, spec):
            """The owner sets independent retrieval priors against the current manifest hash; zero disables each prior without changing confidence or authority."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_weights_configure(json.dumps(spec))))
    class _VaultRetrievalHydeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def configure(self, spec):
            """The owner binds or disables a host HyDE expander for paid recall; replacing the binding cancels unanswered work."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_hyde_configure(json.dumps(spec))))
        def get(self, spec=None):
            """The owner reads the serving host HyDE binding, grounding and bounded retry options."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_hyde_get(json.dumps({} if spec is None else spec))))
        def pending(self, spec):
            """Lists pending expansion and evidence-assessment work for the same credential that called recall; free efforts enqueue nothing."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_hyde_pending(json.dumps(spec))))
        def complete(self, spec):
            """Completes one credential-bound host expansion or evidence assessment, or reports failure; late bytes are receipted and discarded."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_hyde_complete(json.dumps(spec))))
        def receipt(self, spec):
            """Reads one credential-bound host completion receipt, including expired work and late answers discarded at the recall deadline."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_hyde_receipt(json.dumps(spec))))
    class _VaultRetrievalOutcomesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            """The owner attaches an explicit observation to one local serving run; raw reward stays telemetry, never a gated training label."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_outcomes_put(json.dumps(spec))))
        def end(self, spec):
            """The owner records a gate-attributed turn outcome for its exact contributing retrievalRunIds; the engine validates the links and shapes the reward."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_outcomes_end(json.dumps(spec))))
    class _VaultRetrievalPolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """The owner reads the served retrieval policy: active blend weights with their origins, owner pins, the learned posterior and model routing pins."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_policy_get(json.dumps({} if spec is None else spec))))
        def pin(self, spec):
            """The owner pins one retrieval blend weight at a declared share, or clears its pin; learned updates may move only the unpinned remainder."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_policy_pin(json.dumps(spec))))
        def train(self, spec):
            """The owner trains a retrieval-policy candidate from gate-attributed outcomes, judged on held-out runs, without serving it."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_policy_train(json.dumps(spec))))
        def evaluate(self, spec):
            """The owner judges candidate blend weights against the active weights on the same held-out runs the tuner never trains on."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_policy_evaluate(json.dumps(spec))))
        def admit(self, spec):
            """The owner admits candidate blend weights judged on the named evidence manifest; owner pins and held-out regressions refuse admission."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_policy_admit(json.dumps(spec))))
        def update(self, spec):
            """The owner declares one retrieval-policy update: train, admit only a not-worse candidate, and rebuild the learned action posterior."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_policy_update(json.dumps(spec))))
    class _VaultAffectVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def annotations(self) -> "Oneiron._VaultAffectAnnotationsVerbs":
            return Oneiron._VaultAffectAnnotationsVerbs(self._client)
        @property
        def claims(self) -> "Oneiron._VaultAffectClaimsVerbs":
            return Oneiron._VaultAffectClaimsVerbs(self._client)
        @property
        def coping(self) -> "Oneiron._VaultAffectCopingVerbs":
            return Oneiron._VaultAffectCopingVerbs(self._client)
        @property
        def wellness(self) -> "Oneiron._VaultAffectWellnessVerbs":
            return Oneiron._VaultAffectWellnessVerbs(self._client)
    class _VaultAffectAnnotationsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            """Writes one sourced TURN VAD annotation through ordinary scoped claim admission and the caller credential; the receipt states its approval."""
            return json.loads(_translate(lambda: self._client.vault_affect_annotations_put(json.dumps(spec))))
    class _VaultAffectClaimsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def consolidate(self, spec):
            """The owner consolidates a claim from stored TURN VAD evidence, updating only derived affect state and semantic-edge VAD through the existing engine transaction."""
            return json.loads(_translate(lambda: self._client.vault_affect_claims_consolidate(json.dumps(spec))))
    class _VaultAffectCopingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def record(self, spec):
            """Records a first coping outcome from two stored VAD-annotated turns for one person, with scoped claim admission and caller attribution; no factual claim is superseded."""
            return json.loads(_translate(lambda: self._client.vault_affect_coping_record(json.dumps(spec))))
        def update(self, spec):
            """Updates an active coping aggregate from its strategy turn and a later annotated turn through the existing engine transaction, preserving scope and both evidence refs."""
            return json.loads(_translate(lambda: self._client.vault_affect_coping_update(json.dumps(spec))))
        def aggregate(self, spec):
            """Reads all admitted active coping aggregates for one person and optional exact scope, including unsuccessful outcomes and their attribution and evidence refs."""
            return json.loads(_translate(lambda: self._client.vault_affect_coping_aggregate(json.dumps(spec))))
    class _VaultAffectWellnessVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def policy(self) -> "Oneiron._VaultAffectWellnessPolicyVerbs":
            return Oneiron._VaultAffectWellnessPolicyVerbs(self._client)
        def derive(self, spec):
            """Derives one person's non-clinical wellness projection using the existing state measurements and configured mode bands, with a routed receipt and source refs."""
            return json.loads(_translate(lambda: self._client.vault_affect_wellness_derive(json.dumps(spec))))
        def get(self, spec):
            """Reads one person's measured wellness state, configured advisory mode and coping aggregates with source refs, without refreshing or revising factual claims."""
            return json.loads(_translate(lambda: self._client.vault_affect_wellness_get(json.dumps(spec))))
    class _VaultAffectWellnessPolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """Reads the configured non-clinical wellness window, targets and advisory mode bands as the owner; absent policy stays absent."""
            return json.loads(_translate(lambda: self._client.vault_affect_wellness_policy_get(json.dumps({} if spec is None else spec))))
        def configure(self, spec):
            """Configures or clears the existing action-mode policy as the owner; no universal wellness cutoff or diagnostic label is supplied by the engine."""
            return json.loads(_translate(lambda: self._client.vault_affect_wellness_policy_configure(json.dumps(spec))))
    class _VaultTaggingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def status(self, spec):
            """Reads one turn tagging marker as pending retrying settled or failed, with the configured checkpoint, serving model, live marker and failure reason."""
            return json.loads(_translate(lambda: self._client.vault_tagging_status(json.dumps(spec))))
        def tags(self, spec):
            """Reads the tags saved for one turn: mention spans and targets, coreference, mood, PII and other labels, and the derivation that made them."""
            return json.loads(_translate(lambda: self._client.vault_tagging_tags(json.dumps(spec))))
        def history(self, spec):
            """Reads one turn recorded tagging traces oldest first: each attempt, checkpoint, model, try number and saved shadowed skipped or failed outcome."""
            return json.loads(_translate(lambda: self._client.vault_tagging_history(json.dumps(spec))))
        def mentions(self, spec):
            """Reads the saved tagger mentions naming one entity, bounded by limit and each served only while its turn reads for the caller."""
            return json.loads(_translate(lambda: self._client.vault_tagging_mentions(json.dumps(spec))))
    class _VaultClusterVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Proposes deterministic complete-link cohorts from readable stored claims and supplied embeddings; exact subject, predicate-root, world and facet partitions never decide truth."""
            return json.loads(_translate(lambda: self._client.vault_cluster(json.dumps(spec))))
        def proposal(self, spec):
            """Inspects a parked merge or split, its original evidence, current resolution and revision for a gated ruling; every reference must remain readable."""
            return json.loads(_translate(lambda: self._client.vault_cluster_proposal(json.dumps(spec))))
        def propose(self, spec):
            """Parks an explicit merge or split judgment with zero topology effects, under the caller's own owner proof or topology_seal Grant."""
            return json.loads(_translate(lambda: self._client.vault_cluster_propose(json.dumps(spec))))
        def merge(self, spec):
            """Applies a merge judgment through the existing topology gate, preserving claim subjects and recording its redirect shells, evidence and receipt."""
            return json.loads(_translate(lambda: self._client.vault_cluster_merge(json.dumps(spec))))
        def split(self, spec):
            """Applies a split judgment through the existing topology gate, including zero-head retirement, evidence-guided reassignment and explicit residue."""
            return json.loads(_translate(lambda: self._client.vault_cluster_split(json.dumps(spec))))
        def resolve_proposal(self, spec):
            """Approves, amends then approves, or rejects a parked merge or split under the caller's own authority, comparing its revision and recording the ruling atomically."""
            return json.loads(_translate(lambda: self._client.vault_cluster_resolve_proposal(json.dumps(spec))))
    class _VaultExportVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, format: str | None = None) -> dict[str, Any]:
            """Exports the whole vault as one re-importable archive (ZIP, base64 in `archive`)."""
            return json.loads(_translate(lambda: self._client.vault_export(json.dumps({"format": format}))))
        def scoped(self, spec):
            """Exports rows selected under the caller credential and named channel, preserving the engine export fences and provenance withholding."""
            return json.loads(_translate(lambda: self._client.vault_export_scoped(json.dumps(spec))))
    class _VaultScopeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def position(self, spec):
            """Reads a positively stamped record position through the caller credential and existing read gate, with its narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_scope_position(json.dumps(spec))))
        def ceiling(self, spec=None):
            """Reads the caller credential ceiling as a typed ceiling, never as a record position."""
            return json.loads(_translate(lambda: self._client.vault_scope_ceiling(json.dumps({} if spec is None else spec))))
    class _VaultReceiptsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, limit: int = 100, kinds: list[str] | None = None) -> list[dict[str, Any]]:
            """Governance receipts, newest first: the gate decision ledger, or the receipts of the named kinds."""
            return json.loads(_translate(lambda: self._client.vault_receipts(limit, kinds)))
        def get(self, spec):
            """One call receipt by ref, readable by its own actor or the vault's live owner; anything else reads as none."""
            return json.loads(_translate(lambda: self._client.vault_receipts_get(json.dumps(spec))))
        def context(self, spec):
            """Read the frozen context of one actual reply emit, as its actor or the live vault owner; never rebuild the assembly."""
            return json.loads(_translate(lambda: self._client.vault_receipts_context(json.dumps(spec))))
    class _VaultAssetsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def ingest(self, spec):
            """Lands typed text, image or audio bytes as an ASSET and optional source-bound text form, atomically under the caller's content gate."""
            return json.loads(_translate(lambda: self._client.vault_assets_ingest(json.dumps(spec))))
        def resolve(self, spec):
            """Serves an admitted ASSET in the reader's declared image, audio or text form, with a handle and committed served-form receipt refs."""
            return json.loads(_translate(lambda: self._client.vault_assets_resolve(json.dumps(spec))))
    class _VaultSearchVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def vector(self) -> "Oneiron._VaultSearchVectorVerbs":
            return Oneiron._VaultSearchVectorVerbs(self._client)
        def hybrid(self, input: dict[str, Any]) -> Any:
            """Searches explicit vector, text, phonetic, temporal and PPR channels under the caller read ceiling, with optional fixed-time blend replay and per-hit score evidence."""
            return json.loads(_translate(lambda: self._client.vault_search_hybrid(json.dumps(input, allow_nan=False))))
        def temporal(self, input: dict[str, Any]) -> Any:
            """Searches occurrence, learning or both temporal anchors under the caller's read ceiling, with sigma, adaptive widening, hard outer ranges, admitted dates and the effective request sigma and rounds."""
            return json.loads(_translate(lambda: self._client.vault_search_temporal(json.dumps(input, allow_nan=False))))
        def bm25(self, input: dict[str, Any]) -> Any:
            """BM25 text search over the engine index; surfaceable claims only. On a device that syncs only what it opened, a server's door asks the home under the caller's own proof, and its references ride in residence."""
            return json.loads(_translate(lambda: self._client.vault_search_bm25(json.dumps(input, allow_nan=False))))
    class _VaultSearchVectorVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, input: dict[str, Any]) -> Any:
            """Searches the text index or a declared embedding space with per-kind matches and revision pins; text-index MRL reads report refinement, and explicit voice_hot skips rescore at the reduced voice limit."""
            return json.loads(_translate(lambda: self._client.vault_search_vector(json.dumps(input, allow_nan=False))))
        def config(self, spec=None):
            """Reads this vault open's persisted dimensions and optional MRL fast_dims prefix; graph shape is configured before open, never changed by a search."""
            return json.loads(_translate(lambda: self._client.vault_search_vector_config(json.dumps({} if spec is None else spec))))
    class _VaultImagesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def view(self, request: dict[str, Any]) -> dict[str, Any]:
            """The full pixels behind an image's view handle (view, crop or zoom), recorded as a pull."""
            return json.loads(_translate(lambda: self._client.vault_images_view(json.dumps(request, allow_nan=False))))
    class _VaultExplainVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def memory(self, spec):
            """Why one memory appeared in the caller's session: the run that served it and its place, its board tier and the run's score breakdown; none when the session was not served it or the caller cannot read it."""
            return json.loads(_translate(lambda: self._client.vault_explain_memory(json.dumps(spec))))
        def gate(self, spec):
            """Why a write needed approval: the gate decision behind one gate receipt, its outcome, reason codes and cited policy rows; none when the caller may not read it."""
            return json.loads(_translate(lambda: self._client.vault_explain_gate(json.dumps(spec))))
    class _VaultKvVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, request: dict[str, Any]) -> dict[str, Any] | None:
            """Exact actor-owned worldless keyed memory; typed engine errors pass through."""
            return json.loads(_translate(lambda: self._client.vault_kv_get(json.dumps(request, allow_nan=False))))
        def put(self, request: dict[str, Any]) -> dict[str, Any]:
            """Exact actor-owned worldless keyed memory; typed engine errors pass through."""
            return json.loads(_translate(lambda: self._client.vault_kv_put(json.dumps(request, allow_nan=False))))
        def delete(self, request: dict[str, Any]) -> dict[str, Any]:
            """Exact actor-owned worldless keyed memory; typed engine errors pass through."""
            return json.loads(_translate(lambda: self._client.vault_kv_delete(json.dumps(request, allow_nan=False))))
        def search(self, request: dict[str, Any]) -> list[dict[str, Any]]:
            """Exact actor-owned worldless keyed memory; typed engine errors pass through."""
            return json.loads(_translate(lambda: self._client.vault_kv_search(json.dumps(request, allow_nan=False))))
        def namespaces(self, request: dict[str, Any]) -> list[list[str]]:
            """Exact actor-owned worldless keyed memory; typed engine errors pass through."""
            return json.loads(_translate(lambda: self._client.vault_kv_namespaces(json.dumps(request, allow_nan=False))))
    class _VaultCampaignVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def compliance(self) -> "Oneiron._VaultCampaignComplianceVerbs":
            return Oneiron._VaultCampaignComplianceVerbs(self._client)
        def enroll(self, spec):
            """Enrolls a person in a campaign the caller owns, with evidence-backed channels and sticky senders. Writes no earned stage and sends nothing."""
            return json.loads(_translate(lambda: self._client.vault_campaign_enroll(json.dumps(spec))))
        @property
        def stage(self) -> "Oneiron._VaultCampaignStageVerbs":
            return Oneiron._VaultCampaignStageVerbs(self._client)
        def unsubscribe(self, spec):
            """Immediately honors an unsubscribe with a channel-scoped enforcement claim and every suppressed membership head in one transaction."""
            return json.loads(_translate(lambda: self._client.vault_campaign_unsubscribe(json.dumps(spec))))
        @property
        def program(self) -> "Oneiron._VaultCampaignProgramVerbs":
            return Oneiron._VaultCampaignProgramVerbs(self._client)
    class _VaultCampaignComplianceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def install(self, spec):
            """The owner installs cited compliance rows through the versioned amendment classifier; a loosening still waits for an exact-hash owner approval."""
            return json.loads(_translate(lambda: self._client.vault_campaign_compliance_install(json.dumps(spec))))
        def amend(self, spec):
            """Proposes cited compliance rows against the active version. Tightening activates with a notice only within the caller ceiling; loosening waits for the owner stamp."""
            return json.loads(_translate(lambda: self._client.vault_campaign_compliance_amend(json.dumps(spec))))
        def approve(self, spec):
            """The owner approves the exact pending compliance proposal hash against the active version, with a durable authority receipt."""
            return json.loads(_translate(lambda: self._client.vault_campaign_compliance_approve(json.dumps(spec))))
        def reject(self, spec):
            """The owner rejects the exact pending compliance proposal hash without changing the effective rules."""
            return json.loads(_translate(lambda: self._client.vault_campaign_compliance_reject(json.dumps(spec))))
        def verify(self, spec):
            """The owner records cited verification dates for existing compliance rows, including an explicitly stale date, without changing requirements or freshness policy."""
            return json.loads(_translate(lambda: self._client.vault_campaign_compliance_verify(json.dumps(spec))))
        def result(self, spec):
            """Reads the active compliance pack, exact pending proposal, activation notices and amendment or owner-verification receipts from one snapshot."""
            return json.loads(_translate(lambda: self._client.vault_campaign_compliance_result(json.dumps(spec))))
    class _VaultCampaignStageVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def evidence(self, spec):
            """Records earned-stage evidence under an authored ladder transition, in AUTO or propose mode. Owner-attested evidence requires the request owner proof; elapsed time earns nothing."""
            return json.loads(_translate(lambda: self._client.vault_campaign_stage_evidence(json.dumps(spec))))
    class _VaultCampaignProgramVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """Creates a campaign program (ordered steps and an optional saved-query audience) under a campaign the caller owns."""
            return json.loads(_translate(lambda: self._client.vault_campaign_program_create(json.dumps(spec))))
        def read(self, spec):
            """One campaign program under a campaign the caller owns, with whether its audience gets automatic intake now."""
            return json.loads(_translate(lambda: self._client.vault_campaign_program_read(json.dumps(spec))))
        def update(self, spec):
            """Replaces a campaign program's name, steps and audience whole under a version check; work queued at a dropped step stops."""
            return json.loads(_translate(lambda: self._client.vault_campaign_program_update(json.dumps(spec))))
        def archive(self, spec):
            """Archives a campaign program: it stays readable, enrolls no one, and its queued enrollment work stops."""
            return json.loads(_translate(lambda: self._client.vault_campaign_program_archive(json.dumps(spec))))
    class _VaultTurnProgramsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def arm(self, spec):
            """Arms a pinned callable skill entry for the caller's own future turns, in one conversation or any of its own; arming the same definition again returns the standing registration."""
            return json.loads(_translate(lambda: self._client.vault_turn_programs_arm(json.dumps(spec))))
        def disarm(self, spec):
            """Disarms one of the caller's own armed turn programs; true when it was armed."""
            return json.loads(_translate(lambda: self._client.vault_turn_programs_disarm(json.dumps(spec))))
        def admission(self, spec):
            """Reads one page of the admissions a landed turn's wakes decided for the caller's own turn programs, or for every program when the owner asks, withholding each field whose record does not read on the caller's credential."""
            return json.loads(_translate(lambda: self._client.vault_turn_programs_admission(json.dumps(spec))))
    class _VaultWeaveVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def report(self, spec):
            """The live weave report for the bound actor, read through its own scope and the vault's weave policy for its role."""
            return json.loads(_translate(lambda: self._client.vault_weave_report(json.dumps(spec))))
        @property
        def digest(self) -> "Oneiron._VaultWeaveDigestVerbs":
            return Oneiron._VaultWeaveDigestVerbs(self._client)
        def lens(self, spec):
            """Renders the caller's live weave report through the weave-report skill on the server's model, as a card whose wrong controls are its declared actions; the server holds its frame for the card's events."""
            return json.loads(_translate(lambda: self._client.vault_weave_lens(json.dumps(spec))))
        @property
        def link(self) -> "Oneiron._VaultWeaveLinkVerbs":
            return Oneiron._VaultWeaveLinkVerbs(self._client)
        @property
        def owner(self) -> "Oneiron._VaultWeaveOwnerVerbs":
            return Oneiron._VaultWeaveOwnerVerbs(self._client)
        @property
        def item(self) -> "Oneiron._VaultWeaveItemVerbs":
            return Oneiron._VaultWeaveItemVerbs(self._client)
        def enqueue(self, spec):
            """Admits a generated candidate weave recipe under the owner's proof and queues its pinned execution; poll vault.consolidation.status for completion."""
            return json.loads(_translate(lambda: self._client.vault_weave_enqueue(json.dumps(spec))))
        @property
        def schedules(self) -> "Oneiron._VaultWeaveSchedulesVerbs":
            return Oneiron._VaultWeaveSchedulesVerbs(self._client)
        @property
        def setting_changes(self) -> "Oneiron._VaultWeaveSettingChangesVerbs":
            return Oneiron._VaultWeaveSettingChangesVerbs(self._client)
        @property
        def digest_feedback(self) -> "Oneiron._VaultWeaveDigestFeedbackVerbs":
            return Oneiron._VaultWeaveDigestFeedbackVerbs(self._client)
    class _VaultWeaveDigestVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """One of the bound actor's saved weave digests, or the newest, under the current read policy. Its lens is a card; a server holds its frame for the card's events, an embedded handle holds none."""
            return json.loads(_translate(lambda: self._client.vault_weave_digest(json.dumps(spec))))
        def render(self, spec=None):
            """Publishes the bound reader's due digest through the same live scoped lens and returns its saved period and narrowing receipt, or null when nothing is due."""
            return json.loads(_translate(lambda: self._client.vault_weave_digest_render(json.dumps({} if spec is None else spec))))
    class _VaultWeaveLinkVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def wrong(self, spec):
            """A person labels a link in their own lens as wrong; the label teaches the loops and the link stays."""
            return json.loads(_translate(lambda: self._client.vault_weave_link_wrong(json.dumps(spec))))
        def corrections(self, spec):
            """Reads persisted wrong-link labels for a link still admitted by the caller's live weave lens, without changing the link."""
            return json.loads(_translate(lambda: self._client.vault_weave_link_corrections(json.dumps(spec))))
    class _VaultWeaveOwnerVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def link(self) -> "Oneiron._VaultWeaveOwnerLinkVerbs":
            return Oneiron._VaultWeaveOwnerLinkVerbs(self._client)
        @property
        def item(self) -> "Oneiron._VaultWeaveOwnerItemVerbs":
            return Oneiron._VaultWeaveOwnerItemVerbs(self._client)
        @property
        def digest(self) -> "Oneiron._VaultWeaveOwnerDigestVerbs":
            return Oneiron._VaultWeaveOwnerDigestVerbs(self._client)
    class _VaultWeaveOwnerLinkVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def wrong(self, spec):
            """The owner labels a link in the owner lens as wrong, under the owner's own credential; the label teaches the loops and the link stays."""
            return json.loads(_translate(lambda: self._client.vault_weave_owner_link_wrong(json.dumps(spec))))
    class _VaultWeaveOwnerItemVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def wrong(self, spec):
            """The owner labels a claim, project or budget item in the owner lens as wrong, under the owner's own credential; the label teaches the loops and the record stays."""
            return json.loads(_translate(lambda: self._client.vault_weave_owner_item_wrong(json.dumps(spec))))
    class _VaultWeaveOwnerDigestVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def render(self, spec=None):
            """Publishes the owner's due digest through the live owner lens and returns the saved period and narrowing receipt, or null when nothing is due."""
            return json.loads(_translate(lambda: self._client.vault_weave_owner_digest_render(json.dumps({} if spec is None else spec))))
    class _VaultWeaveItemVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def wrong(self, spec):
            """A person labels a claim, project or budget item in their own lens as wrong; the label teaches the loops and the record stays."""
            return json.loads(_translate(lambda: self._client.vault_weave_item_wrong(json.dumps(spec))))
    class _VaultWeaveSchedulesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec=None):
            """Lists every reader's daily or weekly weave digest schedule under the owner's proof."""
            return json.loads(_translate(lambda: self._client.vault_weave_schedules_list(json.dumps({} if spec is None else spec))))
        def put(self, spec):
            """Sets one reader's daily or weekly digest schedule and section recipe under the owner's proof."""
            return json.loads(_translate(lambda: self._client.vault_weave_schedules_put(json.dumps(spec))))
        def clear(self, spec):
            """Stops one reader's digest schedule under the owner's proof, keeping its saved periods."""
            return json.loads(_translate(lambda: self._client.vault_weave_schedules_clear(json.dumps(spec))))
    class _VaultWeaveSettingChangesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec=None):
            """Lists the Coach's proposed and applied changes to the owner's own digest rhythm and section order, newest first, under the owner's proof."""
            return json.loads(_translate(lambda: self._client.vault_weave_setting_changes_list(json.dumps({} if spec is None else spec))))
        def answer(self, spec):
            """Accepts, as the owner's own act, or declines one proposed change to the owner's digest settings; a stale accept applies nothing."""
            return json.loads(_translate(lambda: self._client.vault_weave_setting_changes_answer(json.dumps(spec))))
        def undo(self, spec):
            """Undoes one applied or accepted change to the owner's digest settings, restoring the rhythm and section order before it while the settings are unchanged since."""
            return json.loads(_translate(lambda: self._client.vault_weave_setting_changes_undo(json.dumps(spec))))
    class _VaultWeaveDigestFeedbackVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            """Tells the Coach the owner's own digest preference: a rhythm, a section to lead with, or keep the settings as they are."""
            return json.loads(_translate(lambda: self._client.vault_weave_digest_feedback_put(json.dumps(spec))))
    class _VaultInboxVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def concerns(self) -> "Oneiron._VaultInboxConcernsVerbs":
            return Oneiron._VaultInboxConcernsVerbs(self._client)
        def lens(self, spec):
            """Reads the owner's cross-identity inbox lens in impact order, optionally filtered by identity or agent, with concern groups per agent."""
            return json.loads(_translate(lambda: self._client.vault_inbox_lens(json.dumps(spec))))
        def groups(self, spec):
            """Reads membership of real gate-held Dreamer consent proposals grouped by run, under the owner's proof."""
            return json.loads(_translate(lambda: self._client.vault_inbox_groups(json.dumps(spec))))
    class _VaultInboxConcernsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def review(self, spec=None):
            """Queues the Coach's real health review under the owner's proof; findings and recipients come from engine evidence, never supplied concern rows."""
            return json.loads(_translate(lambda: self._client.vault_inbox_concerns_review(json.dumps({} if spec is None else spec))))
    class _VaultSkillsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def bootstrap(self, spec=None):
            """Reads the bootstrap four and their actual resident source, lifecycle and receipts without seeding or restoring missing skills."""
            return json.loads(_translate(lambda: self._client.vault_skills_bootstrap(json.dumps({} if spec is None else spec))))
        def restoreDefaults(self, spec=None):
            """The owner explicitly re-imports missing or retired bootstrap and pinned first-hub defaults as fresh candidates, leaving unchanged defaults and local forks alone."""
            return json.loads(_translate(lambda: self._client.vault_skills_restoreDefaults(json.dumps({} if spec is None else spec))))
        def import_(self, spec):
            """The owner imports a pinned hub skill through scanning and publisher admission, pending its permission ask."""
            return json.loads(_translate(lambda: self._client.vault_skills_import(json.dumps(spec))))
        def sync(self, spec):
            """The owner syncs a hub skill under its ref policy; widening proposes without changing trusted capabilities."""
            return json.loads(_translate(lambda: self._client.vault_skills_sync(json.dumps(spec))))
        def receipts(self, spec):
            """Reads every hub source and import receipt of a skill, and its held-out admission ruling, as the owner."""
            return json.loads(_translate(lambda: self._client.vault_skills_receipts(json.dumps(spec))))
        def convert(self, spec):
            """Converts selected messages through the configured refiner; user initiation approves conversion, never admission."""
            return json.loads(_translate(lambda: self._client.vault_skills_convert(json.dumps(spec))))
        def get(self, spec):
            """Reads skill lifecycle, exact source, provenance, source availability, scan and admission receipts, and retained fork ancestry."""
            return json.loads(_translate(lambda: self._client.vault_skills_get(json.dumps(spec))))
        def list(self, spec):
            """Lists a page of the owner skill library, including inactive skills and their retained evidence."""
            return json.loads(_translate(lambda: self._client.vault_skills_list(json.dumps(spec))))
        def archive(self, spec):
            """The owner soft-retires an active skill without deleting its body, source or receipts; running callable invocations are cancelled."""
            return json.loads(_translate(lambda: self._client.vault_skills_archive(json.dumps(spec))))
        def restore(self, spec):
            """The owner restores an archived skill through the same admission gates; a hub restore prepares exact consent and reruns held-out scoring."""
            return json.loads(_translate(lambda: self._client.vault_skills_restore(json.dumps(spec))))
        def fork(self, spec):
            """The owner forks a stored skill under a new identity through the existing fork law; retained parent/version and hub ancestry remain inspectable."""
            return json.loads(_translate(lambda: self._client.vault_skills_fork(json.dumps(spec))))
        @property
        def rules(self) -> "Oneiron._VaultSkillsRulesVerbs":
            return Oneiron._VaultSkillsRulesVerbs(self._client)
        @property
        def code_auto_install(self) -> "Oneiron._VaultSkillsCodeAutoInstallVerbs":
            return Oneiron._VaultSkillsCodeAutoInstallVerbs(self._client)
        @property
        def permissions(self) -> "Oneiron._VaultSkillsPermissionsVerbs":
            return Oneiron._VaultSkillsPermissionsVerbs(self._client)
        @property
        def optimize(self) -> "Oneiron._VaultSkillsOptimizeVerbs":
            return Oneiron._VaultSkillsOptimizeVerbs(self._client)
        @property
        def governance(self) -> "Oneiron._VaultSkillsGovernanceVerbs":
            return Oneiron._VaultSkillsGovernanceVerbs(self._client)
        def pack_receipt(self, spec):
            """Reads a terminal pack receipt with its frozen loaded versions and actual-use attribution as the owner."""
            return json.loads(_translate(lambda: self._client.vault_skills_pack_receipt(json.dumps(spec))))
        @property
        def outcomes(self) -> "Oneiron._VaultSkillsOutcomesVerbs":
            return Oneiron._VaultSkillsOutcomesVerbs(self._client)
        @property
        def attribution(self) -> "Oneiron._VaultSkillsAttributionVerbs":
            return Oneiron._VaultSkillsAttributionVerbs(self._client)
    class _VaultSkillsRulesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def set(self, spec):
            """The owner sets or clears a known-bad canonical skill hash rule, independently of advisory scanner prose."""
            return json.loads(_translate(lambda: self._client.vault_skills_rules_set(json.dumps(spec))))
    class _VaultSkillsCodeAutoInstallVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def set(self, spec):
            """The owner sets the code auto-install switch through its existing consent gate; the switch grants no sandbox qualification."""
            return json.loads(_translate(lambda: self._client.vault_skills_code_auto_install_set(json.dumps(spec))))
    class _VaultSkillsPermissionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def approve(self, spec):
            """The owner answers one imported skill permission ask at its exact hub source."""
            return json.loads(_translate(lambda: self._client.vault_skills_permissions_approve(json.dumps(spec))))
    class _VaultSkillsOptimizeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def start(self, spec):
            """The owner starts one skill_optimize attempt on the Dreamer queue; a named identity or alignment skill is excluded and never enqueued."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_start(json.dumps(spec))))
        def result(self, spec):
            """Reads a started skill_optimize job, its drafted proposal, the incumbent, its governance and every held-out verdict on the proposal."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_result(json.dumps(spec))))
        def propose(self, spec):
            """Submits one explicit optimizer candidate against a fixed baseline version and a real drafting attempt; ordinary held-out admission still rules."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_propose(json.dumps(spec))))
        def measure(self, spec):
            """Judges held-out floors before any online slice, then measures the proposal on the effective goal with the registered judge and bounded live arms."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_measure(json.dumps(spec))))
        def score(self, spec):
            """Rules on the submitted proposal through the existing held-out vector gate, floors and tradeoff ladder, without activating it."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_score(json.dumps(spec))))
        def admit(self, spec):
            """Admits only a standing gate acceptance and supersedes its incumbent atomically, with current body, evidence, tier, goal and owner checks."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_admit(json.dumps(spec))))
        @property
        def goal(self) -> "Oneiron._VaultSkillsOptimizeGoalVerbs":
            return Oneiron._VaultSkillsOptimizeGoalVerbs(self._client)
        @property
        def preferences(self) -> "Oneiron._VaultSkillsOptimizePreferencesVerbs":
            return Oneiron._VaultSkillsOptimizePreferencesVerbs(self._client)
        @property
        def tradeoff_asks(self) -> "Oneiron._VaultSkillsOptimizeTradeoffAsksVerbs":
            return Oneiron._VaultSkillsOptimizeTradeoffAsksVerbs(self._client)
    class _VaultSkillsOptimizeGoalVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Reads the optimizer goal identity, effective axes, revision and joined project goal claim."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_goal_get(json.dumps(spec))))
        def bind(self, spec):
            """Joins a skill goal to the human project goal record, or unbinds with null; every join changes its admission revision."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_goal_bind(json.dumps(spec))))
    class _VaultSkillsOptimizePreferencesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Reads authored and learned goal tradeoff rules and the typed judgment band, without changing authority."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_preferences_get(json.dumps(spec))))
        def set(self, spec):
            """The responsible owner sets authored tradeoff rules and the typed judgment band, retaining learned picks and every admission clamp."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_preferences_set(json.dumps(spec))))
    class _VaultSkillsOptimizeTradeoffAsksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec=None):
            """Lists the exact pending optimizer tradeoffs that have reached a role the caller holds, including bound typed judgment evidence."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_tradeoff_asks(json.dumps({} if spec is None else spec))))
        def pick(self, spec):
            """Approves or rejects the exact shown tradeoff; the attributed pick becomes a preference and a proposed project revision, never a Grant."""
            return json.loads(_translate(lambda: self._client.vault_skills_optimize_tradeoff_asks_pick(json.dumps(spec))))
    class _VaultSkillsGovernanceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Reads one skill governance tier as the owner, resolved fail-closed, and whether the automated edit loop may consider it."""
            return json.loads(_translate(lambda: self._client.vault_skills_governance_get(json.dumps(spec))))
        def set(self, spec):
            """The owner marks or clears one skill governance tier; the mark changes no instruction content or version."""
            return json.loads(_translate(lambda: self._client.vault_skills_governance_set(json.dumps(spec))))
    class _VaultSkillsOutcomesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def project(self, spec):
            """Projects the owner's anchored verdict through existing attributed pack outcomes; loading or calling alone never earns a reliability win."""
            return json.loads(_translate(lambda: self._client.vault_skills_outcomes_project(json.dumps(spec))))
        def get(self, spec):
            """Reads the persisted anchored pack credit receipt, including its execution context, direct subjects and lineage shares, as the owner."""
            return json.loads(_translate(lambda: self._client.vault_skills_outcomes_get(json.dumps(spec))))
    class _VaultSkillsAttributionVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def settle(self, spec):
            """The owner settles one amended proposal: exact replacements are recorded, the delta is measured from those ops, hunks are judged and each share routes to its consumer."""
            return json.loads(_translate(lambda: self._client.vault_skills_attribution_settle(json.dumps(spec))))
        def read(self, spec):
            """The owner reads one proposal settlement by receipt: its measured delta, recorded ops, amendment evidence, judgment, preference notes and unclear rows."""
            return json.loads(_translate(lambda: self._client.vault_skills_attribution_read(json.dumps(spec))))
        @property
        def evidence(self) -> "Oneiron._VaultSkillsAttributionEvidenceVerbs":
            return Oneiron._VaultSkillsAttributionEvidenceVerbs(self._client)
        def project(self, spec):
            """The owner runs one attribution pass over recorded evidence, plus the positive lane, returning the judgments and positive proposals it minted."""
            return json.loads(_translate(lambda: self._client.vault_skills_attribution_project(json.dumps(spec))))
        def judgments(self, spec):
            """The owner reads every persisted attribution judgment in both lanes, the projector cursor and the unclear ledger."""
            return json.loads(_translate(lambda: self._client.vault_skills_attribution_judgments(json.dumps(spec))))
        def proposals(self, spec):
            """The owner reads the pending skill edit proposals, preference proposals and positive skill proposals attribution has minted."""
            return json.loads(_translate(lambda: self._client.vault_skills_attribution_proposals(json.dumps(spec))))
        @property
        def positive(self) -> "Oneiron._VaultSkillsAttributionPositiveVerbs":
            return Oneiron._VaultSkillsAttributionPositiveVerbs(self._client)
    class _VaultSkillsAttributionEvidenceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def record(self, spec):
            """The owner records one attempt outcome as attribution evidence, grounded against its stamped pack receipt; recording never classifies it."""
            return json.loads(_translate(lambda: self._client.vault_skills_attribution_evidence_record(json.dumps(spec))))
    class _VaultSkillsAttributionPositiveVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def retire(self, spec):
            """The owner retires one positive skill proposal once the optimizer has drafted from it or declined it."""
            return json.loads(_translate(lambda: self._client.vault_skills_attribution_positive_retire(json.dumps(spec))))
    class _VaultSkillHubsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def default(self) -> "Oneiron._VaultSkillHubsDefaultVerbs":
            return Oneiron._VaultSkillHubsDefaultVerbs(self._client)
        def put(self, spec):
            """The owner registers or revises a hub source; hub trust never grants activation authority."""
            return json.loads(_translate(lambda: self._client.vault_skill_hubs_put(json.dumps(spec))))
        def get(self, spec):
            """Reads one configured hub as the owner."""
            return json.loads(_translate(lambda: self._client.vault_skill_hubs_get(json.dumps(spec))))
        @property
        def publishers(self) -> "Oneiron._VaultSkillHubsPublishersVerbs":
            return Oneiron._VaultSkillHubsPublishersVerbs(self._client)
        @property
        def refs(self) -> "Oneiron._VaultSkillHubsRefsVerbs":
            return Oneiron._VaultSkillHubsRefsVerbs(self._client)
    class _VaultSkillHubsDefaultVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """Reads the first hub identity, configured mirror endpoint and pinned skill-root ref; owner hub and ref setters configure that source."""
            return json.loads(_translate(lambda: self._client.vault_skill_hubs_default_get(json.dumps({} if spec is None else spec))))
    class _VaultSkillHubsPublishersVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def admit(self, spec):
            """The owner admits a foreign publisher to offer candidates from one configured hub, and nothing else."""
            return json.loads(_translate(lambda: self._client.vault_skill_hubs_publishers_admit(json.dumps(spec))))
        def revoke(self, spec):
            """The owner revokes the exact offer-only publisher grant; foreign hooks recheck it before running."""
            return json.loads(_translate(lambda: self._client.vault_skill_hubs_publishers_revoke(json.dumps(spec))))
    class _VaultSkillHubsRefsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Reads one hub ref policy, pin and separate seen and trusted revisions as the owner."""
            return json.loads(_translate(lambda: self._client.vault_skill_hubs_refs_get(json.dumps(spec))))
        def set(self, spec):
            """The owner changes one hub ref policy and pin without fetching or trusting new bytes."""
            return json.loads(_translate(lambda: self._client.vault_skill_hubs_refs_set(json.dumps(spec))))
    class _VaultPacksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def install(self, spec):
            """The owner fetches a pinned hub pack as its foreign publisher; code stays Candidate and hooks wait for consent."""
            return json.loads(_translate(lambda: self._client.vault_packs_install(json.dumps(spec))))
        def sync(self, spec):
            """The owner syncs a hub pack at its stored ref policy; wider hooks keep their old bindings until re-consent."""
            return json.loads(_translate(lambda: self._client.vault_packs_sync(json.dumps(spec))))
        def get(self, spec):
            """Reads an installed pack and its exact source, pin, publisher and requested powers as the owner."""
            return json.loads(_translate(lambda: self._client.vault_packs_get(json.dumps(spec))))
        @property
        def hooks(self) -> "Oneiron._VaultPacksHooksVerbs":
            return Oneiron._VaultPacksHooksVerbs(self._client)
        def put(self, spec):
            """The owner installs a pack folder, or replaces the pack installed under its name, each file sent as text or as content_base64 bytes; the put is the consent for its hooks."""
            return json.loads(_translate(lambda: self._client.vault_packs_put(json.dumps(spec))))
        def preview(self, spec):
            """The owner previews a pack folder before vault.packs.put: the world its travelling agent would land in, with a please double-check notice when that world's current setting does not cover this machine; nothing is staged or written."""
            return json.loads(_translate(lambda: self._client.vault_packs_preview(json.dumps(spec))))
        @property
        def connector(self) -> "Oneiron._VaultPacksConnectorVerbs":
            return Oneiron._VaultPacksConnectorVerbs(self._client)
        def remove(self, spec):
            """The owner removes an installed pack: it leaves the Active catalog and its hook bindings stop; a built-in goes back to its Candidate."""
            return json.loads(_translate(lambda: self._client.vault_packs_remove(json.dumps(spec))))
        @property
        def sections(self) -> "Oneiron._VaultPacksSectionsVerbs":
            return Oneiron._VaultPacksSectionsVerbs(self._client)
        @property
        def setup(self) -> "Oneiron._VaultPacksSetupVerbs":
            return Oneiron._VaultPacksSetupVerbs(self._client)
    class _VaultPacksHooksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def bind(self, spec):
            """The owner consents to the installed pack hook capabilities, including a widening update; publisher identity stays foreign."""
            return json.loads(_translate(lambda: self._client.vault_packs_hooks_bind(json.dumps(spec))))
        def list(self, spec=None):
            """Reads live pack hook bindings and their effective read grants as the owner, excluding revoked foreign publisher grants."""
            return json.loads(_translate(lambda: self._client.vault_packs_hooks_list(json.dumps({} if spec is None else spec))))
        @property
        def grant(self) -> "Oneiron._VaultPacksHooksGrantVerbs":
            return Oneiron._VaultPacksHooksGrantVerbs(self._client)
        def qualify(self, spec):
            """The owner qualifies a Candidate hub hook pack by real sandbox replay; qualification does not consent to wider hooks."""
            return json.loads(_translate(lambda: self._client.vault_packs_hooks_qualify(json.dumps(spec))))
    class _VaultPacksHooksGrantVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def set(self, spec):
            """The owner sets or changes a live hook binding's read grant; outcomes still run as the hook's author. Returns the assigned grant."""
            return json.loads(_translate(lambda: self._client.vault_packs_hooks_grant_set(json.dumps(spec))))
        def get(self, spec):
            """Reads a live hook binding's effective read grant as the owner: its manual assignment, or the author's ceiling when none was set."""
            return json.loads(_translate(lambda: self._client.vault_packs_hooks_grant_get(json.dumps(spec))))
    class _VaultPacksConnectorVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def prepare(self, spec):
            """Prepares an immutable connector pack admission, comparing the resolved declaration with the installed transport and drafting an ungranted slate."""
            return json.loads(_translate(lambda: self._client.vault_packs_connector_prepare(json.dumps(spec))))
        def get(self, spec):
            """Reads a connector pack source, resolved manifest, advisory evidence, qualification and owner-stampable capability rows."""
            return json.loads(_translate(lambda: self._client.vault_packs_connector_get(json.dumps(spec))))
        def qualify(self, spec):
            """Runs the real connector probes bound to the exact pack source and protocol; qualification grants nothing without the owner slate and actor grant."""
            return json.loads(_translate(lambda: self._client.vault_packs_connector_qualify(json.dumps(spec))))
        def accept(self, spec):
            """Stamps the exact connector pack manifest and grant rows once, or revokes a row; qualification stays independent."""
            return json.loads(_translate(lambda: self._client.vault_packs_connector_accept(json.dumps(spec))))
        def update(self, spec):
            """Holds a connector pack at its new immutable source and protocol, carrying narrow rows and re-asking only for expanded capabilities."""
            return json.loads(_translate(lambda: self._client.vault_packs_connector_update(json.dumps(spec))))
        @property
        def grants(self) -> "Oneiron._VaultPacksConnectorGrantsVerbs":
            return Oneiron._VaultPacksConnectorGrantsVerbs(self._client)
    class _VaultPacksConnectorGrantsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Reads current per-capability authority for one actor on the reviewed connector pack source."""
            return json.loads(_translate(lambda: self._client.vault_packs_connector_grants_get(json.dumps(spec))))
        def put(self, spec):
            """Grants declared connector pack rows to one actor through the existing owner consent gate and installed endpoint."""
            return json.loads(_translate(lambda: self._client.vault_packs_connector_grants_put(json.dumps(spec))))
    class _VaultPacksSectionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def propose(self, spec):
            """The caller offers one typed plugin section manifest for an existing skill or a pinned hub package; it waits as a proposed install claim and registers nothing."""
            return json.loads(_translate(lambda: self._client.vault_packs_sections_propose(json.dumps(spec))))
        def list(self, spec):
            """Plugin sections as they stand: install offers awaiting the owner, admitted sections with their granted manifests, and the sections installed packs project."""
            return json.loads(_translate(lambda: self._client.vault_packs_sections_list(json.dumps(spec))))
        def grant(self, spec):
            """The owner grants exactly the reviewed plugin section install: the claim settles through its review handle and the section is admitted under that same consent."""
            return json.loads(_translate(lambda: self._client.vault_packs_sections_grant(json.dumps(spec))))
        def revoke(self, spec):
            """The owner revokes a plugin section grant by retracting its install claim; the section and its advertised verbs leave the next board rebuild."""
            return json.loads(_translate(lambda: self._client.vault_packs_sections_revoke(json.dumps(spec))))
        def suggest(self, spec):
            """Runs one workflow-pattern suggestion pass over a pinned hub on the caller's credential: a repeating pattern nominates at most one pack as an attributed proposal."""
            return json.loads(_translate(lambda: self._client.vault_packs_sections_suggest(json.dumps(spec))))
        @property
        def suggestions(self) -> "Oneiron._VaultPacksSectionsSuggestionsVerbs":
            return Oneiron._VaultPacksSectionsSuggestionsVerbs(self._client)
    class _VaultPacksSectionsSuggestionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """The owner's plugin suggestion knob: whether workflow-pattern suggestion passes may run at all."""
            return json.loads(_translate(lambda: self._client.vault_packs_sections_suggestions_get(json.dumps({} if spec is None else spec))))
        def set(self, spec):
            """The owner turns plugin suggestions on or off; off silences every later pass before any catalog is consulted."""
            return json.loads(_translate(lambda: self._client.vault_packs_sections_suggestions_set(json.dumps(spec))))
    class _VaultPacksSetupVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def prepare(self, spec):
            """The owner opens, or resumes, a pack's guided setup; opening grants nothing."""
            return json.loads(_translate(lambda: self._client.vault_packs_setup_prepare(json.dumps(spec))))
        def get(self, spec):
            """A pack's guided setup as it stands, for the owner."""
            return json.loads(_translate(lambda: self._client.vault_packs_setup_get(json.dumps(spec))))
        def answer(self, spec):
            """The owner's one typed answer or card action in a pack's guided setup; a credential value never passes here."""
            return json.loads(_translate(lambda: self._client.vault_packs_setup_answer(json.dumps(spec))))
        def verify(self, spec):
            """Checks one pack connection with the engine's fixed read-only provider call for its declared check."""
            return json.loads(_translate(lambda: self._client.vault_packs_setup_verify(json.dumps(spec))))
    class _VaultProjectsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def goal(self) -> "Oneiron._VaultProjectsGoalVerbs":
            return Oneiron._VaultProjectsGoalVerbs(self._client)
        def propose(self, spec):
            """The drafting agent proposes a project card on a source message; the card writes no project and confers no authority."""
            return json.loads(_translate(lambda: self._client.vault_projects_propose(json.dumps(spec))))
        def proposals(self, spec):
            """The project cards shown in a conversation, each with its state."""
            return json.loads(_translate(lambda: self._client.vault_projects_proposals(json.dumps(spec))))
        def dismiss_card(self, spec):
            """The card's person dismisses a project card so it never mints; false when it was dismissed already."""
            return json.loads(_translate(lambda: self._client.vault_projects_dismiss_card(json.dumps(spec))))
        def confirm(self, spec):
            """The owner's tap that confirms a host-held project card; only the host's own door can complete it."""
            return json.loads(_translate(lambda: self._client.vault_projects_confirm(json.dumps(spec))))
        @property
        def roster(self) -> "Oneiron._VaultProjectsRosterVerbs":
            return Oneiron._VaultProjectsRosterVerbs(self._client)
        def route_tradeoff(self, spec):
            """Asks the A/B tradeoff question pending on a skill proposal on a project TASK, as a visible turn in its home room."""
            return json.loads(_translate(lambda: self._client.vault_projects_route_tradeoff(json.dumps(spec))))
    class _VaultProjectsGoalVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def intake(self) -> "Oneiron._VaultProjectsGoalIntakeVerbs":
            return Oneiron._VaultProjectsGoalIntakeVerbs(self._client)
        def get(self, spec):
            """Reads the full effective goal record and its claim together; interview drafts and loop proposals never replace it."""
            return json.loads(_translate(lambda: self._client.vault_projects_goal_get(json.dumps(spec))))
        def revisions(self, spec):
            """The learned goal preferences proposed for a project's goal in force and not dismissed, oldest first."""
            return json.loads(_translate(lambda: self._client.vault_projects_goal_revisions(json.dumps(spec))))
        def dismiss(self, spec):
            """The owner dismisses the proposal one tradeoff question made for a project's goal; false for an identical retry."""
            return json.loads(_translate(lambda: self._client.vault_projects_goal_dismiss(json.dumps(spec))))
    class _VaultProjectsGoalIntakeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """What a project's goal-intake interview starts from, for a member of its home room."""
            return json.loads(_translate(lambda: self._client.vault_projects_goal_intake(json.dumps(spec))))
        def complete(self, spec):
            """Completes the witnessed human goal-intake interview with the full confirmed record; no agent proposal can write the effective goal."""
            return json.loads(_translate(lambda: self._client.vault_projects_goal_intake_complete(json.dumps(spec))))
    class _VaultProjectsRosterVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def write(self, spec):
            """Writes an existing project's signed roster as the bound caller, filing joins for the newly seated subjects it stands for and an invitation for each unrelated person, who accepts through vault.rooms.consent."""
            return json.loads(_translate(lambda: self._client.vault_projects_roster_write(json.dumps(spec))))
    class _VaultConnectorsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def proxy(self) -> "Oneiron._VaultConnectorsProxyVerbs":
            return Oneiron._VaultConnectorsProxyVerbs(self._client)
        @property
        def subscriptions(self) -> "Oneiron._VaultConnectorsSubscriptionsVerbs":
            return Oneiron._VaultConnectorsSubscriptionsVerbs(self._client)
    class _VaultConnectorsProxyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def admit(self, spec):
            """The owner admits the OpenAI memory proxy for one paired actor, stamping its read and remember slate and activating its connector key."""
            return json.loads(_translate(lambda: self._client.vault_connectors_proxy_admit(json.dumps(spec))))
        def revoke_write(self, spec):
            """The owner withdraws only the proxy remember grant at the reviewed key and slate revision; read access, stored memories and the connector remain intact."""
            return json.loads(_translate(lambda: self._client.vault_connectors_proxy_revoke_write(json.dumps(spec))))
    class _VaultConnectorsSubscriptionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            """The owner subscribes an agent to the messages a built-in channel (slack or line) routes to it, so each one wakes the agent to answer."""
            return json.loads(_translate(lambda: self._client.vault_connectors_subscriptions_put(json.dumps(spec))))
        def list(self, spec):
            """An agent's connector event subscriptions, standing and revoked, for the owner."""
            return json.loads(_translate(lambda: self._client.vault_connectors_subscriptions_list(json.dumps(spec))))
        def revoke(self, spec):
            """The owner stops one connector event subscription; the agent's key for the channel stays."""
            return json.loads(_translate(lambda: self._client.vault_connectors_subscriptions_revoke(json.dumps(spec))))
    class _VaultAuthorityVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def audit(self, spec):
            """One page of the dated authority log audit, for the owner: grants, revokes and confirms. On a vault that adopted a checkpoint image a page can also carry cold, checkpoint-attested rows it does not store, with no clock or kind."""
            return json.loads(_translate(lambda: self._client.vault_authority_audit(json.dumps(spec))))
        @property
        def history(self) -> "Oneiron._VaultAuthorityHistoryVerbs":
            return Oneiron._VaultAuthorityHistoryVerbs(self._client)
        @property
        def handoff_alarms(self) -> "Oneiron._VaultAuthorityHandoffAlarmsVerbs":
            return Oneiron._VaultAuthorityHandoffAlarmsVerbs(self._client)
    class _VaultAuthorityHistoryVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def export(self, spec=None):
            """Exports the full original signed authority history, including quarantined forks, as base64 envelopes for the owner. No signing secret leaves."""
            return json.loads(_translate(lambda: self._client.vault_authority_history_export(json.dumps({} if spec is None else spec))))
        def import_(self, spec):
            """Imports original base64 signed authority envelopes atomically for the owner, preserving bytes and refolding locally. Invalid signatures, foreign genesis and missing parents write nothing."""
            return json.loads(_translate(lambda: self._client.vault_authority_history_import(json.dumps(spec))))
    class _VaultAuthorityHandoffAlarmsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec=None):
            """Every saved authority handoff fork alarm, for the owner."""
            return json.loads(_translate(lambda: self._client.vault_authority_handoff_alarms(json.dumps({} if spec is None else spec))))
        def acknowledge(self, spec):
            """The owner acknowledges one saved handoff fork alarm."""
            return json.loads(_translate(lambda: self._client.vault_authority_handoff_alarms_acknowledge(json.dumps(spec))))
    class _VaultWireHealthVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def thresholds(self) -> "Oneiron._VaultWireHealthThresholdsVerbs":
            return Oneiron._VaultWireHealthThresholdsVerbs(self._client)
    class _VaultWireHealthThresholdsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """The owner reads the serving host's per-verb and per-actor wire detection thresholds and their window; crossings ask a health question, never refuse for rate."""
            return json.loads(_translate(lambda: self._client.vault_wire_health_thresholds_get(json.dumps(spec))))
        def set(self, spec):
            """The owner replaces the serving host's positive wire detection thresholds and window, receiving the previous and installed policy without adding a rate refusal."""
            return json.loads(_translate(lambda: self._client.vault_wire_health_thresholds_set(json.dumps(spec))))
    class _VaultSlimVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def policy(self, spec):
            """Reads the serving host idle policy: the long outbound wait, no exit on idle and lazy heap rebuild."""
            return json.loads(_translate(lambda: self._client.vault_slim_policy(json.dumps(spec))))
        def state(self, spec):
            """Observes FULL or SLIM atomically with this process id and the retained journaled resume pointer, without waking the vault."""
            return json.loads(_translate(lambda: self._client.vault_slim_state(json.dumps(spec))))
        def resume_step(self, spec):
            """Reads a saved model checkpoint or outbound intent by its retained identity, including after FULL or restart, without reissuing it."""
            return json.loads(_translate(lambda: self._client.vault_slim_resume_step(json.dumps(spec))))
        def drop_heavy(self, spec):
            """Drops rebuildable heap in process and returns the completed engine transition, drop counts or typed refusal; one journaled outbound step is required."""
            return json.loads(_translate(lambda: self._client.vault_slim_drop_heavy(json.dumps(spec))))
        def resume(self, spec):
            """Resumes logical FULL in the same process and returns its completion receipt; indexes rebuild lazily and no saved outbound step is reissued."""
            return json.loads(_translate(lambda: self._client.vault_slim_resume(json.dumps(spec))))
    class _VaultMeshVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def path_receipts(self, spec):
            """The newest path receipts this machine's paired-machine mesh left, newest first and bounded: direct or relayed, admitted, refused or failed, for the owner."""
            return json.loads(_translate(lambda: self._client.vault_mesh_path_receipts(json.dumps(spec))))
        def identity(self, spec):
            """This install's public mesh keys and both binding proofs, for the owner; no private key or grant is returned."""
            return json.loads(_translate(lambda: self._client.vault_mesh_identity(json.dumps(spec))))
        def bind_machine(self, spec):
            """Bind a paired MACHINE's address and transport key using both possession proofs; the binding starts with no ALPN grants."""
            return json.loads(_translate(lambda: self._client.vault_mesh_bind_machine(json.dumps(spec))))
        def set_alpn_grant(self, spec):
            """Allow or revoke one exact ALPN for a paired MACHINE and endpoint key, under the caller's own owner proof."""
            return json.loads(_translate(lambda: self._client.vault_mesh_set_alpn_grant(json.dumps(spec))))
        def revoke_machine(self, spec):
            """Permanently revoke a MACHINE's mesh admission and all its ALPN grants; a new enrollment needs a new MACHINE and pairing."""
            return json.loads(_translate(lambda: self._client.vault_mesh_revoke_machine(json.dumps(spec))))
        def dial(self, spec):
            """Dial an explicit mesh address with this install's real key, including before pairing; report admission and close without an application stream."""
            return json.loads(_translate(lambda: self._client.vault_mesh_dial(json.dumps(spec))))
    class _VaultInspectionVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def resolve(self, spec):
            """Resolves an inspection handle for the caller; unreadable, missing and wrong-kind targets all answer with no item."""
            return json.loads(_translate(lambda: self._client.vault_inspection_resolve(json.dumps(spec))))
    class _VaultSharedVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def propose_delete(self, spec):
            """Starts a shared vault's delete_vault act, returned as a typed pending act."""
            return json.loads(_translate(lambda: self._client.vault_shared_propose_delete(json.dumps(spec))))
        def propose_transfer(self, spec):
            """Starts a shared vault's transfer_ownership act: a live Owner hands the vault to another person."""
            return json.loads(_translate(lambda: self._client.vault_shared_propose_transfer(json.dumps(spec))))
        def propose_remove_owner(self, spec):
            """Starts a shared vault's remove_owner act, with its export-first answer."""
            return json.loads(_translate(lambda: self._client.vault_shared_propose_remove_owner(json.dumps(spec))))
        def execute(self, spec):
            """A live Owner runs a matured shared-vault act and gets its receipt."""
            return json.loads(_translate(lambda: self._client.vault_shared_execute(json.dumps(spec))))
        def receipt(self, spec):
            """One shared-act or membership receipt its reader was told about, by id."""
            return json.loads(_translate(lambda: self._client.vault_shared_receipt(json.dumps(spec))))
        def outcomes(self, spec):
            """The reader's own outcome notices for a shared vault."""
            return json.loads(_translate(lambda: self._client.vault_shared_outcomes(json.dumps(spec))))
        def deletion(self, spec=None):
            """The executed delete-the-vault act, if any."""
            return json.loads(_translate(lambda: self._client.vault_shared_deletion(json.dumps({} if spec is None else spec))))
        def object(self, spec):
            """A holder of a pending shared act's objector role objects inside its veto window."""
            return json.loads(_translate(lambda: self._client.vault_shared_object(json.dumps(spec))))
        def withdraw_objection(self, spec):
            """The holder withdraws their objection; past the deadline the last withdrawal releases the act."""
            return json.loads(_translate(lambda: self._client.vault_shared_withdraw_objection(json.dumps(spec))))
        def started(self, spec):
            """The caller's own notices of shared acts started in the vault."""
            return json.loads(_translate(lambda: self._client.vault_shared_started(json.dumps(spec))))
        def matured(self, spec):
            """The caller's own notices of shared acts whose veto window has passed."""
            return json.loads(_translate(lambda: self._client.vault_shared_matured(json.dumps(spec))))
        def erase_ask(self, spec):
            """A Member requests, or an Admin proposes, that the Owners erase a record; it erases nothing."""
            return json.loads(_translate(lambda: self._client.vault_shared_erase_ask(json.dumps(spec))))
        def erase_asks(self, spec):
            """The erase asks the caller may see: every ask for an Owner, their own for anyone else."""
            return json.loads(_translate(lambda: self._client.vault_shared_erase_asks(json.dumps(spec))))
        def close_erase_ask(self, spec):
            """An Owner closes an open erase ask, as erased (naming its erase act) or declined."""
            return json.loads(_translate(lambda: self._client.vault_shared_close_erase_ask(json.dumps(spec))))
        @property
        def policy(self) -> "Oneiron._VaultSharedPolicyVerbs":
            return Oneiron._VaultSharedPolicyVerbs(self._client)
    class _VaultSharedPolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """A live Owner reads every shared-act policy row of a shared vault: the rows its kind ships, the vault's own rows, the row each act resolves to, and the policy_hash a change binds."""
            return json.loads(_translate(lambda: self._client.vault_shared_policy_get(json.dumps(spec))))
        def propose(self, spec):
            """A live policy editor proposes one shared-act policy row change against the policy_hash they read; it applies only when every live editor approves it, and one no vetoes it."""
            return json.loads(_translate(lambda: self._client.vault_shared_policy_propose(json.dumps(spec))))
        def answer(self, spec):
            """A live policy editor approves or vetoes a pending shared-act policy change under their own credential; the last approval of the live editor set writes the row."""
            return json.loads(_translate(lambda: self._client.vault_shared_policy_answer(json.dumps(spec))))
        def change(self, spec):
            """A live Owner reads one shared-act policy change: its row, approvals, veto, state and the live editors it still waits on."""
            return json.loads(_translate(lambda: self._client.vault_shared_policy_change(json.dumps(spec))))
    class _VaultOrgAdminVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def configure(self, spec):
            """The owner fixes an organization's Admin identities and closed named-power set once; no root or private-vault power can be configured."""
            return json.loads(_translate(lambda: self._client.vault_org_admin_configure(json.dumps(spec))))
        def powers(self, spec):
            """The caller reads only the organization's fixed named Admin powers that their own credential carries."""
            return json.loads(_translate(lambda: self._client.vault_org_admin_powers(json.dumps(spec))))
    class _VaultMembersVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def reset_project_access(self, spec):
            """An Admin resets only a non-root shared project's signed access roster through the existing project-proof gate; it never changes a personal root or grants an unsigned override."""
            return json.loads(_translate(lambda: self._client.vault_members_reset_project_access(json.dumps(spec))))
        def delegate(self, spec):
            """A live parent Admin or Owner mints one explicit scope narrowing for a holder, bounded by policy and a server-clock expiry of at most 90 days; the Delegate cannot delegate onward."""
            return json.loads(_translate(lambda: self._client.vault_members_delegate(json.dumps(spec))))
        def projection(self, spec):
            """Read a member's visible role grants, scopes, expiry and person/relationship through the caller's own scoped read; relationship labels confer no additional authority."""
            return json.loads(_translate(lambda: self._client.vault_members_projection(json.dumps(spec))))
        def add(self, spec):
            """An Admin invites a live person into a shared vault at a non-root role; they join when they accept. Given the invitee's own device key, the host also mints the invitee a slip good only for this invitation while it is pending."""
            return json.loads(_translate(lambda: self._client.vault_members_add(json.dumps(spec))))
        def invitation_slip(self, spec):
            """An Admin mints a pending invitation's slip for the public key the invitee generated on their own device: a founding invitation's, or one whose slip was lost."""
            return json.loads(_translate(lambda: self._client.vault_members_invitation_slip(json.dumps(spec))))
        def change(self, spec):
            """An Admin assigns another non-root role to a member who is not an Owner."""
            return json.loads(_translate(lambda: self._client.vault_members_change(json.dumps(spec))))
        def remove(self, spec):
            """An Admin removes one member from a shared vault."""
            return json.loads(_translate(lambda: self._client.vault_members_remove(json.dumps(spec))))
        def leave(self, spec):
            """A member leaves a shared vault under their own proof; an Owner leaves through remove_owner instead."""
            return json.loads(_translate(lambda: self._client.vault_members_leave(json.dumps(spec))))
        def invitations(self, spec):
            """The caller's own pending invitations into a shared vault."""
            return json.loads(_translate(lambda: self._client.vault_members_invitations(json.dumps(spec))))
        def accept(self, spec):
            """The invitee accepts their own invitation and joins the shared vault at its role."""
            return json.loads(_translate(lambda: self._client.vault_members_accept(json.dumps(spec))))
        def decline(self, spec):
            """The invitee declines their own invitation; nothing is granted."""
            return json.loads(_translate(lambda: self._client.vault_members_decline(json.dumps(spec))))
        def withdraw_invitation(self, spec):
            """An Admin with the add_member power takes back a pending invitation."""
            return json.loads(_translate(lambda: self._client.vault_members_withdraw_invitation(json.dumps(spec))))
    class _VaultFederationVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def coreference(self) -> "Oneiron._VaultFederationCoreferenceVerbs":
            return Oneiron._VaultFederationCoreferenceVerbs(self._client)
        @property
        def burst(self) -> "Oneiron._VaultFederationBurstVerbs":
            return Oneiron._VaultFederationBurstVerbs(self._client)
        @property
        def connect(self) -> "Oneiron._VaultFederationConnectVerbs":
            return Oneiron._VaultFederationConnectVerbs(self._client)
    class _VaultFederationCoreferenceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def link(self, spec):
            """The owner atomically links two people with proposed or confirmed identity status, without pooling their claims or granting reads."""
            return json.loads(_translate(lambda: self._client.vault_federation_coreference_link(json.dumps(spec))))
        def confirm(self, spec):
            """The owner atomically confirms cross-vault identity without changing either person or their claims."""
            return json.loads(_translate(lambda: self._client.vault_federation_coreference_confirm(json.dumps(spec))))
        def share_consent(self, spec):
            """The owner consents to exporting an existing identity link into exactly one named federation pact."""
            return json.loads(_translate(lambda: self._client.vault_federation_coreference_share_consent(json.dumps(spec))))
        def unlink(self, spec):
            """The owner atomically removes both identity-link orientations and retracts link metadata while retaining the original claims."""
            return json.loads(_translate(lambda: self._client.vault_federation_coreference_unlink(json.dumps(spec))))
    class _VaultFederationBurstVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def baseline(self, spec):
            """The owner reads one peer's named or observed baseline, relative rate and streak, and current vault-size context."""
            return json.loads(_translate(lambda: self._client.vault_federation_burst_baseline(json.dumps(spec))))
        @property
        def policy(self) -> "Oneiron._VaultFederationBurstPolicyVerbs":
            return Oneiron._VaultFederationBurstPolicyVerbs(self._client)
        def ingress(self, spec):
            """The owner admits a peer host signed Connect delivery through current federation admission and receives its discriminated burst receipt."""
            return json.loads(_translate(lambda: self._client.vault_federation_burst_ingress(json.dumps(spec))))
        def disposition(self, spec):
            """The owner reads an authenticated batch original disposition, named baseline context and current durable replay state."""
            return json.loads(_translate(lambda: self._client.vault_federation_burst_disposition(json.dumps(spec))))
        @property
        def review(self) -> "Oneiron._VaultFederationBurstReviewVerbs":
            return Oneiron._VaultFederationBurstReviewVerbs(self._client)
        def replay(self, spec):
            """The owner retries one retained authenticated batch through its current grant and federation admission without another burst debit."""
            return json.loads(_translate(lambda: self._client.vault_federation_burst_replay(json.dumps(spec))))
    class _VaultFederationBurstPolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads one grant-bound peer's relative-burst outcome policy."""
            return json.loads(_translate(lambda: self._client.vault_federation_burst_policy(json.dumps(spec))))
        def set(self, spec):
            """The owner sets a named baseline and allow, isolate-and-propose or defer routing for one peer without changing its grant."""
            return json.loads(_translate(lambda: self._client.vault_federation_burst_policy_set(json.dumps(spec))))
    class _VaultFederationBurstReviewVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads retained peer review bundles, coalesced once per peer and kept after replay or rejection."""
            return json.loads(_translate(lambda: self._client.vault_federation_burst_review(json.dumps(spec))))
        def release(self, spec):
            """The owner releases a bundle's burst hold for current-grant replay without importing evidence or widening authority."""
            return json.loads(_translate(lambda: self._client.vault_federation_burst_review_release(json.dumps(spec))))
        def reject(self, spec):
            """The owner rejects a bundle's pending batches while retaining its review evidence and terminal dispositions."""
            return json.loads(_translate(lambda: self._client.vault_federation_burst_review_reject(json.dumps(spec))))
    class _VaultFederationConnectVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def identity(self, spec):
            """The owner reads this vault identity and the host key used for reciprocal Connect consent."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_identity(json.dumps(spec))))
        @property
        def grants(self) -> "Oneiron._VaultFederationConnectGrantsVerbs":
            return Oneiron._VaultFederationConnectGrantsVerbs(self._client)
        def offer(self, spec):
            """The owner asks the host to sign one disclosed Connect half without activating it."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_offer(json.dumps(spec))))
        def accept(self, spec):
            """The owner accepts the peer host signed Connect half and receives the matching host counter-half."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_accept(json.dumps(spec))))
        def narrow(self, spec):
            """The owner narrows the current outbound scope without breaking the reciprocal relationship."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_narrow(json.dumps(spec))))
        @property
        def rescope(self) -> "Oneiron._VaultFederationConnectRescopeVerbs":
            return Oneiron._VaultFederationConnectRescopeVerbs(self._client)
        def disconnect(self, spec):
            """The owner unilaterally ends both directions of a pact without claiming to erase the peer retained copy."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_disconnect(json.dumps(spec))))
        def export(self, spec):
            """The owner exports one grant-filtered named-world update signed by the host for its live pact and epoch."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_export(json.dumps(spec))))
        def rejoin(self, spec):
            """The owner admits a peer host signed update through guest admission into the retained foreign-world vault."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_rejoin(json.dumps(spec))))
    class _VaultFederationConnectGrantsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def mint(self, spec):
            """The owner mints an inert Connect guest grant inside the named local-world ceiling."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_grants_mint(json.dumps(spec))))
    class _VaultFederationConnectRescopeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def offer(self, spec):
            """The owner discloses both directions at a new epoch and asks the host to sign a reciprocal re-scope proposal."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_rescope_offer(json.dumps(spec))))
        def accept(self, spec):
            """The owner accepts the peer host signed re-scope and receives the matching signed counter-half."""
            return json.loads(_translate(lambda: self._client.vault_federation_connect_rescope_accept(json.dumps(spec))))
    class _VaultTrustedContactsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def name(self, spec):
            """The vault owner names another live person of the vault as their trusted contact, reached on one outbound channel verb, with an ask-first dial; naming again replaces it and needs the contact's consent again."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_name(json.dumps(spec))))
        def list(self, spec):
            """A live person lists every trusted-contact relation they are a side of: those they named and those naming them, under their own credential."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_list(json.dumps(spec))))
        def consent(self, spec):
            """The named contact, a live person under their own credential, accepts the naming version they were shown and attests they are an adult; the relation is live only after this."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_consent(json.dumps(spec))))
        def revoke(self, spec):
            """Either side of a trusted-contact relation ends it under their own credential; no notice staged from it is sent after this returns, and its open asks close."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_revoke(json.dumps(spec))))
        @property
        def dial(self) -> "Oneiron._VaultTrustedContactsDialVerbs":
            return Oneiron._VaultTrustedContactsDialVerbs(self._client)
        @property
        def tier(self) -> "Oneiron._VaultTrustedContactsTierVerbs":
            return Oneiron._VaultTrustedContactsTierVerbs(self._client)
        @property
        def concern(self) -> "Oneiron._VaultTrustedContactsConcernVerbs":
            return Oneiron._VaultTrustedContactsConcernVerbs(self._client)
    class _VaultTrustedContactsDialVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def set(self, spec):
            """The vault owner changes whether they are asked before their trusted contact is reached (ask_first or just_call); the contact's consent stands."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_dial_set(json.dumps(spec))))
    class _VaultTrustedContactsTierVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def set(self, spec):
            """The vault owner names the trusted-contact tier (concern or imminent) of one RouteToHelp policy row; a row never named is a concern."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_tier_set(json.dumps(spec))))
    class _VaultTrustedContactsConcernVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def asks(self, spec):
            """The vault owner reads their open asks to reach a trusted contact, each raised by a RouteToHelp the policy gate settled."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_concern_asks(json.dumps(spec))))
        def authorize(self, spec):
            """The vault owner answers one open ask, once: a yes stages the fact-of-concern notice (staged, not delivered) and returns the notices that tell the person and the model; a no or a superseded ask stages nothing."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_concern_authorize(json.dumps(spec))))
        def propose(self, spec):
            """The owner's policy gate reads one message the caller reads, fresh; a RouteToHelp asks the owner or stages a just-call notice, and the answer carries only the fact of concern, the gate receipt, open asks and notices."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_concern_propose(json.dumps(spec))))
        def deliver(self, spec):
            """The caller sends the next staged fact-of-concern notice it is the stored sender of, as itself, through the consent-checked outbound dispatch; null when none is eligible, never another sender's notice."""
            return json.loads(_translate(lambda: self._client.vault_trusted_contacts_concern_deliver(json.dumps(spec))))
    class _VaultGuestsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def share(self, spec):
            """The owner shares a locally authored named-world document through its live guest grant as a filtered signed envelope bound to the pact epoch."""
            return json.loads(_translate(lambda: self._client.vault_guests_share(json.dumps(spec))))
        def export_envelope(self, spec):
            """The guest fetches its actual filtered signed document envelope under its own live grant-bound credential over HTTP or the held socket."""
            return json.loads(_translate(lambda: self._client.vault_guests_export_envelope(json.dumps(spec))))
        def reshare(self, spec):
            """The owner attempts a document re-share through the same local-world-only guest door; received foreign worlds and base are refused."""
            return json.loads(_translate(lambda: self._client.vault_guests_reshare(json.dumps(spec))))
        def revoke(self, spec):
            return json.loads(_translate(lambda: self._client.vault_guests_revoke(json.dumps(spec))))
        def mint_slip(self, spec):
            """The owner mints an Ask or active Connect guest capability slip bound to its live grant and the public key generated by the guest on their own device, with an optional signed comm cap (below vault, owners only)."""
            return json.loads(_translate(lambda: self._client.vault_guests_mint_slip(json.dumps(spec))))
    class _VaultSupportGrantsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def mint(self, spec):
            """The owner mints our support person or agent a time-limited, revocable grant, bound to that party's own key, inside explicit bounds."""
            return json.loads(_translate(lambda: self._client.vault_support_grants_mint(json.dumps(spec))))
        def list(self, spec):
            """The owner lists the vault's support grants, newest first, with each one's bounds, deadline, status and revoke command."""
            return json.loads(_translate(lambda: self._client.vault_support_grants_list(json.dumps(spec))))
        def revoke(self, spec):
            """The owner revokes one support grant; what support already read is not recalled."""
            return json.loads(_translate(lambda: self._client.vault_support_grants_revoke(json.dumps(spec))))
    class _VaultResidenceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def mode(self, spec):
            """Switches one of the owner's machines between opened and all residence; that machine's own sync connection applies it. A machine this host does not reach answers state queued, naming the directive."""
            return json.loads(_translate(lambda: self._client.vault_residence_mode(json.dumps(spec))))
        def open(self, spec):
            """Opens one item on the named machine and reports local or home residence; a NOTE includes typed text, its version and requested stable anchors. A machine this host does not reach answers state queued, naming the directive."""
            return json.loads(_translate(lambda: self._client.vault_residence_open(json.dumps(spec))))
        def index(self, spec):
            """The thin index one of the owner's machines holds, window by window: what exists, never a body. A machine this host does not reach answers state queued, naming the directive."""
            return json.loads(_translate(lambda: self._client.vault_residence_index(json.dumps(spec))))
        def prune(self, spec):
            """Drops the opened-item caches one of the owner's machines last touched before a time. A machine this host does not reach answers state queued, naming the directive."""
            return json.loads(_translate(lambda: self._client.vault_residence_prune(json.dumps(spec))))
        def directives(self, spec):
            """The owner reads the residence directives this replica holds and each machine's result as received here; a null result means not received here, not that the machine is idle."""
            return json.loads(_translate(lambda: self._client.vault_residence_directives(json.dumps(spec))))
    class _VaultOffRecordVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def start(self, spec):
            """The vault's owner, or a person or agent who then manages it with the owner, enters an off-record session alone, off record or anonymous, under their own name for it, and answers the handle later calls name it by."""
            return json.loads(_translate(lambda: self._client.vault_off_record_start(json.dumps(spec))))
        def status(self, spec):
            """The session's creator or the vault's owner reads one live off-record session: its mode, backend, entry time, promoted turns and whether it is closing; a room's member reads what their membership shows."""
            return json.loads(_translate(lambda: self._client.vault_off_record_status(json.dumps(spec))))
        def witness(self, spec):
            """The session's creator or the vault's owner witnesses one turn into an off-record session, or a member into a room's; it stays in the room until promoted or dropped at close."""
            return json.loads(_translate(lambda: self._client.vault_off_record_witness(json.dumps(spec))))
        def discard(self, spec):
            """The session's creator or the vault's owner closes an off-record session without saving it: its turns, writes, receipts and spilled outputs are dropped, and promoted turns stay."""
            return json.loads(_translate(lambda: self._client.vault_off_record_discard(json.dumps(spec))))
        def recall(self, spec):
            """The session's creator or the vault's owner recalls over an off-record session and the vault together, on their own credential: rows the room holds and vault rows alike."""
            return json.loads(_translate(lambda: self._client.vault_off_record_recall(json.dumps(spec))))
        @property
        def notes(self) -> "Oneiron._VaultOffRecordNotesVerbs":
            return Oneiron._VaultOffRecordNotesVerbs(self._client)
        @property
        def claims(self) -> "Oneiron._VaultOffRecordClaimsVerbs":
            return Oneiron._VaultOffRecordClaimsVerbs(self._client)
        @property
        def rooms(self) -> "Oneiron._VaultOffRecordRoomsVerbs":
            return Oneiron._VaultOffRecordRoomsVerbs(self._client)
    class _VaultOffRecordNotesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """The session's creator or the vault's owner writes one NOTE into an off-record session through its handle; it lands in the room, never in the vault, and close drops it."""
            return json.loads(_translate(lambda: self._client.vault_off_record_notes_create(json.dumps(spec))))
    class _VaultOffRecordClaimsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def upsert(self, spec):
            """The session's creator or the vault's owner admits one claim into an off-record session through its handle and the gate; it lands in the room beside the vault heads, and close drops it."""
            return json.loads(_translate(lambda: self._client.vault_off_record_claims_upsert(json.dumps(spec))))
    class _VaultOffRecordRoomsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def status(self, spec):
            """Reads a room's off-record notices and waiting save suggestions as the caller's membership shows them, without the talk."""
            return json.loads(_translate(lambda: self._client.vault_off_record_rooms_status(json.dumps(spec))))
        def start(self, spec):
            """A person, or an agent within its Write Grant, starts an off-record stretch in a room they belong to, on their own credential."""
            return json.loads(_translate(lambda: self._client.vault_off_record_rooms_start(json.dumps(spec))))
        def witness(self, spec):
            """Witnesses a turn into a room's off-record stretch as the caller, under their live membership and the current saving grant."""
            return json.loads(_translate(lambda: self._client.vault_off_record_rooms_witness(json.dumps(spec))))
        def save(self, spec):
            """A holder of this vault's write grant saves the visible whole talk so far into this vault, on their own credential."""
            return json.loads(_translate(lambda: self._client.vault_off_record_rooms_save(json.dumps(spec))))
        def save_from_here(self, spec):
            """A holder puts a room's stretch on record for later turns while their vault write grant and room membership stay live."""
            return json.loads(_translate(lambda: self._client.vault_off_record_rooms_save_from_here(json.dumps(spec))))
        def export(self, spec):
            """A person exports only their visible room talk as a JSON attachment and posts a content-free notice; an Owner's export also writes one export audit row and tells the members of each private thread it carries that the Owner is not in."""
            return json.loads(_translate(lambda: self._client.vault_off_record_rooms_export(json.dumps(spec))))
        def suggest_save(self, spec):
            """An agent suggests saving a room's off-record talk on a write or propose credential; nothing is saved until a holder confirms."""
            return json.loads(_translate(lambda: self._client.vault_off_record_rooms_suggest_save(json.dumps(spec))))
        def confirm_save(self, spec):
            """A holder confirms the room's waiting save suggestions with their own save of the visible whole talk; refuses when none waits."""
            return json.loads(_translate(lambda: self._client.vault_off_record_rooms_confirm_save(json.dumps(spec))))
        def decline_save(self, spec):
            """A holder declines the room's waiting save suggestions, posts a content-free notice and saves nothing; refuses when none waits."""
            return json.loads(_translate(lambda: self._client.vault_off_record_rooms_decline_save(json.dumps(spec))))
    class _VaultRecordsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def erase_preview(self, spec):
            """What erasing one record would take: the brief grants it revokes, the records holding the same bytes and the LFS chunks it shares, with the digest erase_confirm takes back."""
            return json.loads(_translate(lambda: self._client.vault_records_erase_preview(json.dumps(spec))))
        def erase_confirm(self, spec):
            """Erase the record the caller previewed, once its preview still has the digest they confirmed; in a shared vault a held record starts its own erase act instead."""
            return json.loads(_translate(lambda: self._client.vault_records_erase_confirm(json.dumps(spec))))
        def erase_sweep(self, spec):
            """Read a redaction receipt's recorded historical-sweep deadline and linked completion as the owner; never starts a sweep."""
            return json.loads(_translate(lambda: self._client.vault_records_erase_sweep(json.dumps(spec))))
    class _VaultResearchVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create_child(self, spec):
            """The owner enqueues an experiment child through ordinary agent dispatch under an unpruned campaign parent; record its actual candidate afterward with research.fork or research.weave."""
            return json.loads(_translate(lambda: self._client.vault_research_create_child(json.dumps(spec))))
        @property
        def archive(self) -> "Oneiron._VaultResearchArchiveVerbs":
            return Oneiron._VaultResearchArchiveVerbs(self._client)
        def bind(self, spec):
            """Binds an autoresearch campaign to its existing root attempt: its ruler, selection policy, cohort, budget share and prior ladder, once. The owner or the agent running that root calls it."""
            return json.loads(_translate(lambda: self._client.vault_research_bind(json.dumps(spec))))
        def fork(self, spec):
            """Records a variation or debug child the campaign's controller enqueued under a measured or buggy parent."""
            return json.loads(_translate(lambda: self._client.vault_research_fork(json.dumps(spec))))
        def weave(self, spec):
            """Records a crossover child of several parents whose candidate landed as a claim through the gate, once a held-out win turned merge crossover on."""
            return json.loads(_translate(lambda: self._client.vault_research_weave(json.dumps(spec))))
        def measure_search(self, spec):
            """Records a node's search-split evidence, its selection signal, once."""
            return json.loads(_translate(lambda: self._client.vault_research_measure_search(json.dumps(spec))))
        def measure_held_out(self, spec):
            """Records a node's held-out evidence, once; only the promotion basis reads it."""
            return json.loads(_translate(lambda: self._client.vault_research_measure_held_out(json.dumps(spec))))
        def evaluate_split(self, spec):
            """The owner scores one arm of a bound claim-authoring campaign on one split under its bound config; the blind taste questions go through the host's decision ladder, and the report is returned, not stored."""
            return json.loads(_translate(lambda: self._client.vault_research_evaluate_split(json.dumps(spec))))
        def mark_invalid(self, spec):
            """Marks a node buggy: it stays as evidence and takes debug children."""
            return json.loads(_translate(lambda: self._client.vault_research_mark_invalid(json.dumps(spec))))
        def prune(self, spec):
            """Stops exploring a branch for a stated cause; its attempts, claims and outputs stay. A stop names the caller."""
            return json.loads(_translate(lambda: self._client.vault_research_prune(json.dumps(spec))))
        def select(self, spec):
            """Runs one selection round through the trusted selection floor and records it; only the owner can say the goal is met."""
            return json.loads(_translate(lambda: self._client.vault_research_select(json.dumps(spec))))
        def promotion_basis(self, spec):
            """Decides a candidate's held-out promotion basis against the incumbent, once."""
            return json.loads(_translate(lambda: self._client.vault_research_promotion_basis(json.dumps(spec))))
        def reserve_confirmation(self, spec):
            """Spends a Promote candidate's one sealed confirmation and releases the campaign's sealed cohort to the controller's referee, counted as a serving."""
            return json.loads(_translate(lambda: self._client.vault_research_reserve_confirmation(json.dumps(spec))))
        def promote(self, spec):
            """Settles a candidate on the sealed referee's scores of it and the incumbent: a strict win, a not-worse sufficiency card and, for a skill, the gate's accepted verdict make it the incumbent."""
            return json.loads(_translate(lambda: self._client.vault_research_promote(json.dumps(spec))))
        def reserve_work(self, spec):
            """Reserves token work for the campaign on the RSI line under its share, and returns the reservation's id."""
            return json.loads(_translate(lambda: self._client.vault_research_reserve_work(json.dumps(spec))))
        def settle_work(self, spec):
            """Settles a work reservation at its actual spend."""
            return json.loads(_translate(lambda: self._client.vault_research_settle_work(json.dumps(spec))))
        def refund_work(self, spec):
            """Refunds a work reservation nothing was spent on."""
            return json.loads(_translate(lambda: self._client.vault_research_refund_work(json.dumps(spec))))
        def reserve_exploration(self, spec):
            """Reserves exploration exposure for the campaign on its own exposure-denominated RSI line, independently of token work, and returns the reservation's id. Settle or refund it through settle_work and refund_work."""
            return json.loads(_translate(lambda: self._client.vault_research_reserve_exploration(json.dumps(spec))))
        def budget(self, spec):
            """Reads the campaign's lease, every reservation it holds or held with its settlement and soft-share overdraft receipt, and the vault RSI lines behind them, including the observable hold state."""
            return json.loads(_translate(lambda: self._client.vault_research_budget(json.dumps(spec))))
        def record_benchmark(self, spec):
            """Records an estimator version's held-out selection benchmark against the DGM parent formula, once per version; a win of at least 30 cases lets its information gain rank parents."""
            return json.loads(_translate(lambda: self._client.vault_research_record_benchmark(json.dumps(spec))))
    class _VaultResearchArchiveVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Reads the complete retained campaign record, including every pruned, buggy and woven candidate, original search and held-out evidence, selection rounds and promotion receipts, under the controller gate."""
            return json.loads(_translate(lambda: self._client.vault_research_archive(json.dumps(spec))))
        def install(self, spec):
            """Installs one immutable campaign output descriptor from a receipted Coach proposal under the current human goal; categorical axes and embedding clusters share the engine validator."""
            return json.loads(_translate(lambda: self._client.vault_research_archive_install(json.dumps(spec))))
        def record(self, spec):
            """Records original placement and quality receipts for one output revision; categorical judgment or pinned embedding placement competes only within its own cell."""
            return json.loads(_translate(lambda: self._client.vault_research_archive_record(json.dumps(spec))))
        def get(self, spec):
            """Reads the installed campaign output descriptor and every original placement and scoring receipt, including losing outputs, under the research controller gate."""
            return json.loads(_translate(lambda: self._client.vault_research_archive_get(json.dumps(spec))))
        def best(self, spec):
            """Rebuilds one best output per cell under the immutable descriptor revision and reports whether bunching warrants a new campaign proposal."""
            return json.loads(_translate(lambda: self._client.vault_research_archive_best(json.dumps(spec))))
        def repropose(self, spec):
            """Installs a receipted descriptor proposal in a new bound campaign when the old archive is bunched; the old descriptor, goal and cell winners remain unchanged."""
            return json.loads(_translate(lambda: self._client.vault_research_archive_repropose(json.dumps(spec))))
        def coverage(self, spec):
            """Pins the incumbent and candidate replay output refs and projects the human goal coverage floor; promotion rechecks these receipts and rejects any lost incumbent cell."""
            return json.loads(_translate(lambda: self._client.vault_research_archive_coverage(json.dumps(spec))))
    class _VaultEvalsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def inventory(self, spec):
            """The owner reads the metadata-only eval-authoring inventory: real receipt families, grounded case candidates, date-cut cohorts and exposure counts. Pin its built_at and digest for cohort setup."""
            return json.loads(_translate(lambda: self._client.vault_evals_inventory(json.dumps(spec))))
        @property
        def cohorts(self) -> "Oneiron._VaultEvalsCohortsVerbs":
            return Oneiron._VaultEvalsCohortsVerbs(self._client)
        def author_now(self, spec):
            """Queue the production Coach eval-authoring pass, coalescing with nightly work; the caller supplies no plan, skill provenance or lease."""
            return json.loads(_translate(lambda: self._client.vault_evals_author_now(json.dumps(spec))))
        @property
        def authoring(self) -> "Oneiron._VaultEvalsAuthoringVerbs":
            return Oneiron._VaultEvalsAuthoringVerbs(self._client)
        @property
        def families(self) -> "Oneiron._VaultEvalsFamiliesVerbs":
            return Oneiron._VaultEvalsFamiliesVerbs(self._client)
        @property
        def cases(self) -> "Oneiron._VaultEvalsCasesVerbs":
            return Oneiron._VaultEvalsCasesVerbs(self._client)
        def exposure(self, spec):
            """Read a cohort's individual exposure ledger and independent candidate, query and promotion counts; unknown cohorts refuse."""
            return json.loads(_translate(lambda: self._client.vault_evals_exposure(json.dumps(spec))))
        def sufficiency(self, spec):
            """Compute the existing sufficiency card from explicit family-grouped measurements; unknown never approves, creates a label ask or deploys."""
            return json.loads(_translate(lambda: self._client.vault_evals_sufficiency(json.dumps(spec))))
        @property
        def labels(self) -> "Oneiron._VaultEvalsLabelsVerbs":
            return Oneiron._VaultEvalsLabelsVerbs(self._client)
    class _VaultEvalsCohortsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Read date-cut cohorts, the fixed reference, retirement decisions, exposure counts and near-copy audits; similarity flags review only."""
            return json.loads(_translate(lambda: self._client.vault_evals_cohorts(json.dumps(spec))))
        def setup(self, spec):
            """The owner sets up sealed cohorts from a pinned real inventory through the existing family, case and audited cut doors. Reports refused decisions; never serves sealed content or fabricates labels or skill provenance."""
            return json.loads(_translate(lambda: self._client.vault_evals_cohorts_setup(json.dumps(spec))))
        def open(self, spec):
            """Count a candidate, query or promotion serving before releasing its sealed cohort in the same owner-validated transaction; retired cohorts refuse."""
            return json.loads(_translate(lambda: self._client.vault_evals_cohorts_open(json.dumps(spec))))
    class _VaultEvalsAuthoringVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def result(self, spec):
            """Read the eval-authoring host attempt's actual state and terminal error; a completed pass may author nothing."""
            return json.loads(_translate(lambda: self._client.vault_evals_authoring_result(json.dumps(spec))))
    class _VaultEvalsFamiliesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Read a seat's family purposes, source roots, derivative lineage and dates, including retirement and training eligibility, without sealed labels."""
            return json.loads(_translate(lambda: self._client.vault_evals_families(json.dumps(spec))))
        def assign(self, spec):
            """Assign source roots their fixed eval family and purpose before deriving cases; conflicting families, purposes or seats refuse."""
            return json.loads(_translate(lambda: self._client.vault_evals_families_assign(json.dumps(spec))))
    class _VaultEvalsCasesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Read development or judge-audit eval cases; sealed confirmation refuses and retired cohorts read as development, never training."""
            return json.loads(_translate(lambda: self._client.vault_evals_cases(json.dumps(spec))))
        def record(self, spec):
            """Record a receipt, repair, paraphrase, summary, translation, synthetic or rubric case through the shared family-inheritance guard; no labels are invented."""
            return json.loads(_translate(lambda: self._client.vault_evals_cases_record(json.dumps(spec))))
    class _VaultEvalsLabelsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def blocked(self, spec):
            """Read only unanswered eval-label asks for this owner, optionally by seat or blocked decision, with scoped cases and quoted human minutes; create no standing label session."""
            return json.loads(_translate(lambda: self._client.vault_evals_labels_blocked(json.dumps(spec))))
        def pick(self, spec):
            """Record either option of the responsible owner's existing eval-label ask once; the same pick repeats safely and a conflicting second pick refuses."""
            return json.loads(_translate(lambda: self._client.vault_evals_labels_pick(json.dumps(spec))))
    class _VaultRootsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def requests(self) -> "Oneiron._VaultRootsRequestsVerbs":
            return Oneiron._VaultRootsRequestsVerbs(self._client)
    class _VaultRootsRequestsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def cancel(self, spec):
            """The owner cancels one root request from any surface he is signed in on, ids only; the target applies it whenever it syncs. The receipt says cancelled, or that the target answered it first, which stands."""
            return json.loads(_translate(lambda: self._client.vault_roots_requests_cancel(json.dumps(spec))))
    class _VaultCleanupVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def run(self, spec):
            """The owner runs one archive-cleanup pass under the current posture; propose-first opens a proposal and archives nothing."""
            return json.loads(_translate(lambda: self._client.vault_cleanup_run(json.dumps(spec))))
    class _VaultUsageVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def events(self) -> "Oneiron._VaultUsageEventsVerbs":
            return Oneiron._VaultUsageEventsVerbs(self._client)
    class _VaultUsageEventsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def undecodable(self, spec):
            """Lists the stored usage events of this server's metering scope that no longer decode, each by an opaque row ref, its byte length and the BLAKE3 hash of its bytes, for the owner or an agent whose own Grant names this verb."""
            return json.loads(_translate(lambda: self._client.vault_usage_events_undecodable(json.dumps(spec))))
        def remove_undecodable(self, spec):
            """Removes one listed undecodable usage event while it still holds the reviewed bytes and does not decode, and answers the receipt kept in that write, for the owner or an agent whose own Grant names this verb."""
            return json.loads(_translate(lambda: self._client.vault_usage_events_remove_undecodable(json.dumps(spec))))
    class _VaultLegalHoldsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def place(self, spec):
            """The owner places a customer legal hold on the named records or gate partitions."""
            return json.loads(_translate(lambda: self._client.vault_legal_holds_place(json.dumps(spec))))
        def widen(self, spec):
            """Adds targets to one of the owner's standing customer legal holds."""
            return json.loads(_translate(lambda: self._client.vault_legal_holds_widen(json.dumps(spec))))
        def list(self, spec=None):
            """Every legal hold the owner may see."""
            return json.loads(_translate(lambda: self._client.vault_legal_holds_list(json.dumps({} if spec is None else spec))))
        def log(self, spec=None):
            """The owner-visible legal hold log, oldest first."""
            return json.loads(_translate(lambda: self._client.vault_legal_holds_log(json.dumps({} if spec is None else spec))))
        def lift_and_erase(self, spec):
            """The owner's one confirm that lifts or narrows the customer holds on the named records and erases them."""
            return json.loads(_translate(lambda: self._client.vault_legal_holds_lift_and_erase(json.dumps(spec))))
    class _VaultCourtesyDeleteVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def send(self, spec):
            """The owner asks a former peer to drop what an ended pact delivered, and queues the signed ask for delivery."""
            return json.loads(_translate(lambda: self._client.vault_courtesy_delete_send(json.dumps(spec))))
        def sent(self, spec=None):
            """Every courtesy delete ask this vault sent, with its delivery status, for the owner."""
            return json.loads(_translate(lambda: self._client.vault_courtesy_delete_sent(json.dumps({} if spec is None else spec))))
        def incoming(self, spec=None):
            """Every courtesy delete ask a former peer sent, with each named world's stale stamp and the owner's answer."""
            return json.loads(_translate(lambda: self._client.vault_courtesy_delete_incoming(json.dumps({} if spec is None else spec))))
        def answer(self, spec):
            """The owner answers one incoming courtesy delete ask from the menu, and sends the answer back when reply_to names where."""
            return json.loads(_translate(lambda: self._client.vault_courtesy_delete_answer(json.dumps(spec))))
    class _VaultEmbeddingSpacesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec=None):
            """Every declared embedding space, the text index, the space each kind slot reads, every move and the probe count per kind."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_list(json.dumps({} if spec is None else spec))))
        def declare(self, spec):
            """Declares or widens one embedding space: id, dimensions, accepts, query_towers and optional evidence floors."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_declare(json.dumps(spec))))
        def bind(self, spec):
            """Binds one kind slot to a declared space, or returns it to its default when no space is named."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_bind(json.dumps(spec))))
        def one_space(self, spec):
            """Binds every kind slot the space accepts, text included, to that one space."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_one_space(json.dumps(spec))))
        def retire(self, spec):
            """Drops a declared space that no slot binds and no open move names, with its vector rows."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_retire(json.dumps(spec))))
        def move(self, spec):
            """Starts moving every kind slot the incumbent serves (the text index when none is named) to the candidate space."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_move(json.dumps(spec))))
        def move_check(self, spec):
            """Runs an embedding space move probes now through both spaces and acts on the reading; it can take minutes."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_move_check(json.dumps(spec))))
        def move_approve(self, spec):
            """The owner says yes to a full candidate over a check that did not read not worse; it swaps in."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_move_approve(json.dumps(spec))))
        def move_undo(self, spec):
            """Binds a swapped-in move incumbent again."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_move_undo(json.dumps(spec))))
        def move_abandon(self, spec):
            """Ends an open embedding space move with no swap."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_move_abandon(json.dumps(spec))))
        @property
        def probes(self) -> "Oneiron._VaultEmbeddingSpacesProbesVerbs":
            return Oneiron._VaultEmbeddingSpacesProbesVerbs(self._client)
    class _VaultEmbeddingSpacesProbesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec=None):
            """Every stored embedding space probe with its id."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_probes_list(json.dumps({} if spec is None else spec))))
        def put(self, spec):
            """Stores one retrieval probe the owner or another model wrote: kind, a text query or a stored image or audio document as its query, family, targets and author."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_probes_put(json.dumps(spec))))
        def delete(self, spec):
            """Removes one stored embedding space probe by its id."""
            return json.loads(_translate(lambda: self._client.vault_embedding_spaces_probes_delete(json.dumps(spec))))
    class _VaultPolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def owner(self) -> "Oneiron._VaultPolicyOwnerVerbs":
            return Oneiron._VaultPolicyOwnerVerbs(self._client)
        @property
        def outbound(self) -> "Oneiron._VaultPolicyOutboundVerbs":
            return Oneiron._VaultPolicyOutboundVerbs(self._client)
        @property
        def relay(self) -> "Oneiron._VaultPolicyRelayVerbs":
            return Oneiron._VaultPolicyRelayVerbs(self._client)
    class _VaultPolicyOwnerVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """The owner reads the content-policy configuration, default manifest hash and effective off/on state."""
            return json.loads(_translate(lambda: self._client.vault_policy_owner_get(json.dumps({} if spec is None else spec))))
        def configure(self, spec):
            """The owner configures or toggles content policy against the current manifest hash without changing other policy tables."""
            return json.loads(_translate(lambda: self._client.vault_policy_owner_configure(json.dumps(spec))))
        @property
        def row(self) -> "Oneiron._VaultPolicyOwnerRowVerbs":
            return Oneiron._VaultPolicyOwnerRowVerbs(self._client)
    class _VaultPolicyOwnerRowVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def change(self, spec):
            """The owner adds, edits or removes a scoped content-policy row through its existing holder-governed writer and receives its change receipt."""
            return json.loads(_translate(lambda: self._client.vault_policy_owner_row_change(json.dumps(spec))))
    class _VaultPolicyOutboundVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def decide(self, spec):
            """Decide an outbound candidate under owner policy with system notices and hash-only receipts; Warn and Skipped preserve its exact bytes."""
            return json.loads(_translate(lambda: self._client.vault_policy_outbound_decide(json.dumps(spec))))
    class _VaultPolicyRelayVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def decide(self, spec):
            """Decide bytes carried by the host-bound attested relay under its own legal policy; outages halt with a service notice and local-model offer."""
            return json.loads(_translate(lambda: self._client.vault_policy_relay_decide(json.dumps(spec))))
    class _VaultConsentVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def approve_once(self, spec):
            """The owner approves exactly one engine-emitted effect digest; no standing grant is created."""
            return json.loads(_translate(lambda: self._client.vault_consent_approve_once(json.dumps(spec))))
        def deny(self, spec):
            """The owner denies exactly one engine-emitted effect digest and records the refusal without granting authority."""
            return json.loads(_translate(lambda: self._client.vault_consent_deny(json.dumps(spec))))
        def create_standing_grant(self, spec):
            """The owner creates a bounded standing action or disclosure grant, with no stored expiry; a wider bound is a new decision."""
            return json.loads(_translate(lambda: self._client.vault_consent_create_standing_grant(json.dumps(spec))))
        def registry(self, spec):
            """The owner reads the unified action and disclosure grant registry, including revoke commands and optionally revoked grants."""
            return json.loads(_translate(lambda: self._client.vault_consent_registry(json.dumps(spec))))
        def failure_signals_held(self, spec=None):
            """Read the carried failure-signal batch's exact content and approval digest as the owner."""
            return json.loads(_translate(lambda: self._client.vault_consent_failure_signals_held(json.dumps({} if spec is None else spec))))
        def revoke(self, spec):
            """The owner immediately revokes a standing consent grant by the reference its receipt or registry emitted."""
            return json.loads(_translate(lambda: self._client.vault_consent_revoke(json.dumps(spec))))
        def bypass_grant_warning(self, spec):
            """The owner previews the exact actor, classes, envelope and project or thread of a scoped bypass; this warning grants nothing."""
            return json.loads(_translate(lambda: self._client.vault_consent_bypass_grant_warning(json.dumps(spec))))
        def create_bypass_grant(self, spec):
            """The owner explicitly acknowledges a scoped bypass warning and atomically creates one receipted standing bypass per class."""
            return json.loads(_translate(lambda: self._client.vault_consent_create_bypass_grant(json.dumps(spec))))
        def active_bypass_grants(self, spec):
            """The owner reads live scoped bypass states and their complete bounds, newest first; vault.consent.revoke ends each grant."""
            return json.loads(_translate(lambda: self._client.vault_consent_active_bypass_grants(json.dumps(spec))))
        def bypassed_effect_receipts(self, spec):
            """The owner reads the existing Gate receipts for effects covered by one bypass grant, including after its revocation."""
            return json.loads(_translate(lambda: self._client.vault_consent_bypassed_effect_receipts(json.dumps(spec))))
        @property
        def graduation(self) -> "Oneiron._VaultConsentGraduationVerbs":
            return Oneiron._VaultConsentGraduationVerbs(self._client)
    class _VaultConsentGraduationVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def policy(self) -> "Oneiron._VaultConsentGraduationPolicyVerbs":
            return Oneiron._VaultConsentGraduationPolicyVerbs(self._client)
        def stats(self, spec):
            """Reads one exact graduation scope outcome history and current consent posture."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_stats(json.dumps(spec))))
        def outcome(self, spec):
            """The owner records an untouched, amended or rejected proposal ruling, receipted and folded through the existing ramp."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_outcome(json.dumps(spec))))
        def offers(self, spec):
            """Reads earned, unsuppressed graduation offers with thresholds, streaks and before/after reach; reading grants nothing."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_offers(json.dumps(spec))))
        def answer(self, spec):
            """The owner answers auto, not-now or manual_pinned; only auto mints the existing standing grant, and not-now resets the streak."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_answer(json.dumps(spec))))
        def trust_table(self, spec):
            """Reads the owner trust table: scope, counts, effective threshold, snooze or manual pin, live grant and offer reach."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_trust_table(json.dumps(spec))))
        @property
        def settings(self) -> "Oneiron._VaultConsentGraduationSettingsVerbs":
            return Oneiron._VaultConsentGraduationSettingsVerbs(self._client)
        def demote(self, spec):
            """The owner demotes an exact scope to propose, revoking its live grant and recording the existing durable demotion receipt."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_demote(json.dumps(spec))))
    class _VaultConsentGraduationPolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Reads runtime consent-graduation policy rows and the effective row for an optional exact scope."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_policy(json.dumps(spec))))
        def set(self, spec):
            """The owner sets a scope-pattern streak, posterior guard and two snooze backoffs; zero-second backoff is supported."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_policy_set(json.dumps(spec))))
        def clear(self, spec):
            """The owner clears one runtime graduation policy row; scopes fall back to the next matching policy."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_policy_clear(json.dumps(spec))))
    class _VaultConsentGraduationSettingsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def unpin(self, spec):
            """The owner reopens a pinned or snoozed graduation scope in settings; no grant is created."""
            return json.loads(_translate(lambda: self._client.vault_consent_graduation_settings_unpin(json.dumps(spec))))
    class _VaultGateVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def policy(self) -> "Oneiron._VaultGatePolicyVerbs":
            return Oneiron._VaultGatePolicyVerbs(self._client)
        @property
        def checker(self) -> "Oneiron._VaultGateCheckerVerbs":
            return Oneiron._VaultGateCheckerVerbs(self._client)
    class _VaultGatePolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """The owner reads Gate policy envelopes, actor ceilings, source permits and checker references, including inert contributions."""
            return json.loads(_translate(lambda: self._client.vault_gate_policy_get(json.dumps(spec))))
        def put(self, spec):
            """The owner installs or edits typed Gate write axes, preserving other tables and meeting independently installed contributions."""
            return json.loads(_translate(lambda: self._client.vault_gate_policy_put(json.dumps(spec))))
        def propose(self, spec):
            """Propose a Gate policy under the caller's own authority; even a tighter contribution remains untrusted and inert."""
            return json.loads(_translate(lambda: self._client.vault_gate_policy_propose(json.dumps(spec))))
    class _VaultGateCheckerVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """The owner reads the calibrated checker verdict role from the vault model manifest."""
            return json.loads(_translate(lambda: self._client.vault_gate_checker_get(json.dumps({} if spec is None else spec))))
        def set(self, spec):
            """The owner sets the calibrated checker model, slot, confidence floor and shadow or enforce mode without changing other model bindings."""
            return json.loads(_translate(lambda: self._client.vault_gate_checker_set(json.dumps(spec))))
    class _VaultLearningVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, spec):
            """The owner reads a measured learning cell, its explicit prior, derived UNTESTED mark, projector heads and anchored evidence; borrowed provenance stays separate from own runs."""
            return json.loads(_translate(lambda: self._client.vault_learning_read(json.dumps(spec))))
        def projection(self, spec):
            """The owner observes the stored projection receipt for an anchored attempt outcome; an absent receipt means projection has not committed, never a successful empty projection."""
            return json.loads(_translate(lambda: self._client.vault_learning_projection(json.dumps(spec))))
    class _VaultSealVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def confess(self, spec):
            """Confess an attempt's objectives without changing any score; named flaws and uncertainty create durable directed rechecks."""
            return json.loads(_translate(lambda: self._client.vault_seal_confess(json.dumps(spec))))
        def audit(self, spec):
            """Draw a passing sealed attempt once at the current audit rate, saving the rate and selection before any checker runs."""
            return json.loads(_translate(lambda: self._client.vault_seal_audit(json.dumps(spec))))
        def receipt(self, spec):
            """Read a sealed attempt, its stamped audit draw, directed and random check completions, weighted findings and separate honesty reward."""
            return json.loads(_translate(lambda: self._client.vault_seal_receipt(json.dumps(spec))))
        def pending(self, spec):
            """Read pending directed rechecks and random audits, optionally for one attempt, without executing a checker."""
            return json.loads(_translate(lambda: self._client.vault_seal_pending(json.dumps(spec))))
        def run(self, spec):
            """Queue the existing Coach seal checker under its ordinary lease, Grant and budget; the returned job never grants extra authority."""
            return json.loads(_translate(lambda: self._client.vault_seal_run(json.dumps(spec))))
        def complete(self, spec):
            """Attest an independent external seal check as the owner; admit immutable findings and project them using the request's stamped rate."""
            return json.loads(_translate(lambda: self._client.vault_seal_complete(json.dumps(spec))))
    class _VaultSettingsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def learning(self) -> "Oneiron._VaultSettingsLearningVerbs":
            return Oneiron._VaultSettingsLearningVerbs(self._client)
        @property
        def wake_policy(self) -> "Oneiron._VaultSettingsWakePolicyVerbs":
            return Oneiron._VaultSettingsWakePolicyVerbs(self._client)
        @property
        def inference_defaults(self) -> "Oneiron._VaultSettingsInferenceDefaultsVerbs":
            return Oneiron._VaultSettingsInferenceDefaultsVerbs(self._client)
    class _VaultSettingsLearningVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads the learned-setting catalog, each knob's value now, and the owner's seed and pin rows at the vault, a project or a task type."""
            return json.loads(_translate(lambda: self._client.vault_settings_learning(json.dumps(spec))))
        def put(self, spec):
            """The owner lays one seed or pin on a learned setting at the vault, a project or a task type, replacing the row of the same key, mode and scope."""
            return json.loads(_translate(lambda: self._client.vault_settings_learning_put(json.dumps(spec))))
        def clear(self, spec):
            """The owner clears one learned-setting row of a key, mode and scope."""
            return json.loads(_translate(lambda: self._client.vault_settings_learning_clear(json.dumps(spec))))
    class _VaultSettingsWakePolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def set(self, spec):
            """The owner sets the dreamer's wake policy: the app's dreamer.wake_policy.set action, run as the caller under the owner's proof."""
            return json.loads(_translate(lambda: self._client.vault_settings_wake_policy_set(json.dumps(spec))))
    class _VaultSettingsInferenceDefaultsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec=None):
            """Reads the per-purpose inference defaults: the app's inference.defaults.read action, which needs the caller's Auto ceiling."""
            return json.loads(_translate(lambda: self._client.vault_settings_inference_defaults(json.dumps({} if spec is None else spec))))
        def replace(self, spec):
            """Replaces the whole per-purpose inference default table: the app's inference.defaults.replace action, which needs the caller's Auto ceiling."""
            return json.loads(_translate(lambda: self._client.vault_settings_inference_defaults_replace(json.dumps(spec))))
    class _VaultSecretsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def lift_history(self, spec):
            """The owner reads the historical secret lift sweep: the run in progress, the last receipt and the open lift proposals by cause. With close, one proposal closes first with the owner's reason and a receipt; with start, a run is queued."""
            return json.loads(_translate(lambda: self._client.vault_secrets_lift_history(json.dumps(spec))))
    class _VaultWidenProposalsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner lists the context-widen proposals agents raised, newest first, or only those pending, approved or declined."""
            return json.loads(_translate(lambda: self._client.vault_widen_proposals(json.dumps(spec))))
        def approve(self, spec):
            """The owner, as the board above, approves one context-widen proposal: the parent's context widens and the child is enqueued."""
            return json.loads(_translate(lambda: self._client.vault_widen_proposals_approve(json.dumps(spec))))
        def decline(self, spec):
            """The owner, as the board above, declines one context-widen proposal for good; the decline stays on record."""
            return json.loads(_translate(lambda: self._client.vault_widen_proposals_decline(json.dumps(spec))))
    class _VaultCraftCandidatesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner lists the craft notes residents' dreaming proposed about themselves that wait on a verdict, newest first, or one resident's, each with the content hash an answer pins."""
            return json.loads(_translate(lambda: self._client.vault_craft_candidates(json.dumps(spec))))
        def answer(self, spec):
            """The owner approves or rejects one craft candidate, bound to the content hash its card showed: an Approved or Rejected row supersedes it, with one receipt. The same answer again returns the first."""
            return json.loads(_translate(lambda: self._client.vault_craft_candidates_answer(json.dumps(spec))))
    class _VaultLensesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def propose(self, spec):
            """Stores one frozen compiled lens tree for a pack slot as this actor's proposal; it mounts only once the owner selects it."""
            return json.loads(_translate(lambda: self._client.vault_lenses_propose(json.dumps(spec))))
        def activate(self, spec):
            """The owner selects a proposed lens revision for its pack slot."""
            return json.loads(_translate(lambda: self._client.vault_lenses_activate(json.dumps(spec))))
        def deactivate(self, spec):
            """The owner clears a pack slot's selected lens; the pack, its skill and the proposal stay."""
            return json.loads(_translate(lambda: self._client.vault_lenses_deactivate(json.dumps(spec))))
        def list(self, spec):
            """One page of the vault's lens proposals, each with its slot state from the owner's current selection. A credential narrowed to some worlds or facets sees only the proposals whose slot skill and pack source it reads, without their trees."""
            return json.loads(_translate(lambda: self._client.vault_lenses_list(json.dumps(spec))))
        def select(self, spec):
            """Selects a rendered atom or Unicode-scalar span under the caller's live key and holds its read handle on that card."""
            return json.loads(_translate(lambda: self._client.vault_lenses_select(json.dumps(spec))))
        def resolve(self, spec):
            """Re-proves a host-issued selection on the caller's held card and reads its source with its pinned cursor span."""
            return json.loads(_translate(lambda: self._client.vault_lenses_resolve(json.dumps(spec))))
        @property
        def result_set(self) -> "Oneiron._VaultLensesResultSetVerbs":
            return Oneiron._VaultLensesResultSetVerbs(self._client)
        def default(self, spec):
            """Composes the default vault lens from the named sources, read under the caller's own scope, as a card. A server holds its frame for the card's events; an embedded handle holds none, so its events need a server."""
            return json.loads(_translate(lambda: self._client.vault_lenses_default(json.dumps(spec))))
    class _VaultLensesResultSetVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def action(self, spec):
            """Re-proves the ticked rows or rendered predicate and their selected handles, then dispatches the declared result-set action through the caller's existing gate."""
            return json.loads(_translate(lambda: self._client.vault_lenses_result_set_action(json.dumps(spec))))
    class _VaultDisclosureVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def offer(self, spec):
            """An agent files a clearance offer for one contact, waiting on the owner's answer until it lapses."""
            return json.loads(_translate(lambda: self._client.vault_disclosure_offer(json.dumps(spec))))
        @property
        def ceiling(self) -> "Oneiron._VaultDisclosureCeilingVerbs":
            return Oneiron._VaultDisclosureCeilingVerbs(self._client)
        @property
        def reveals(self) -> "Oneiron._VaultDisclosureRevealsVerbs":
            return Oneiron._VaultDisclosureRevealsVerbs(self._client)
    class _VaultDisclosureCeilingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Reads the owner registry dial for one model connection, optionally one data class."""
            return json.loads(_translate(lambda: self._client.vault_disclosure_ceiling_get(json.dumps(spec))))
        def set(self, spec):
            """The owner sets one connection or class disclosure ceiling; no read authority changes."""
            return json.loads(_translate(lambda: self._client.vault_disclosure_ceiling_set(json.dumps(spec))))
        def clear(self, spec):
            """The owner clears one dial, restoring connection or actor-class inference."""
            return json.loads(_translate(lambda: self._client.vault_disclosure_ceiling_clear(json.dumps(spec))))
    class _VaultDisclosureRevealsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads model-disclosure asks and receipts, including PERSON handles, without values."""
            return json.loads(_translate(lambda: self._client.vault_disclosure_reveals(json.dumps(spec))))
        def answer(self, spec):
            """The owner approves once, approves standing, or denies the exact frozen reveal ask."""
            return json.loads(_translate(lambda: self._client.vault_disclosure_reveals_answer(json.dumps(spec))))
    class _VaultSharesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """The handle's actor issues a share: the brief, its recipient, the most the view may show and the text that travels."""
            return json.loads(_translate(lambda: self._client.vault_shares_create(json.dumps(spec))))
        def revoke(self, spec):
            return json.loads(_translate(lambda: self._client.vault_shares_revoke(json.dumps(spec))))
        def view(self, spec):
            return json.loads(_translate(lambda: self._client.vault_shares_view(json.dumps(spec))))
    class _VaultHooksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def replay(self, spec):
            """The owner replays a fact hook over past facts on the hook sandbox, as a dry run where nothing lands."""
            return json.loads(_translate(lambda: self._client.vault_hooks_replay(json.dumps(spec))))
        @property
        def regen(self) -> "Oneiron._VaultHooksRegenVerbs":
            return Oneiron._VaultHooksRegenVerbs(self._client)
    class _VaultHooksRegenVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def due(self, spec=None):
            """List, as the authenticated owner, the hook bindings of the vault's own packs whose verb table or sandbox contract changed since their last good body passed, with no regen waiting. Runs no regen."""
            return json.loads(_translate(lambda: self._client.vault_hooks_regen_due(json.dumps({} if spec is None else spec))))
        def get(self, spec):
            """Read one hook binding's regen record as the authenticated owner: its last good body hash, contract stamp, intent and pending decision, with the candidate_hash an adoption names. Null for a binding bound under no record. Changes nothing."""
            return json.loads(_translate(lambda: self._client.vault_hooks_regen_get(json.dumps(spec))))
        def adopt(self, spec):
            """Adopt, as the authenticated owner and as their stamp, the regen candidate pending on one hook binding, named by the candidate_hash vault.hooks.regen.get shows. Answers the pack put receipt; only an installed put advances the record."""
            return json.loads(_translate(lambda: self._client.vault_hooks_regen_adopt(json.dumps(spec))))
    class _VaultArtifactsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def publish_approval(self, spec):
            """Computes the exact publication approval digest for the existing owner approve-once door; it grants nothing."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_publish_approval(json.dumps(spec))))
        def publish(self, spec):
            """Publishes one immutable code fork or numbered blob export with an explicit audience through the existing Gate, returning its pointer and durable receipt ref."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_publish(json.dumps(spec))))
        def repoint(self, spec):
            """Repoints one artifact channel to an exact immutable export through the publication Gate; use a new publish id, and earlier receipts survive."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_repoint(json.dumps(spec))))
        def pointer(self, spec):
            """Reads the current artifact channel pin and audience under the owner credential; null when absent or withheld."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_pointer(json.dumps(spec))))
        def unpublish(self, spec):
            """Removes one artifact channel pointer without deleting its immutable export or earlier publication receipts."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_unpublish(json.dumps(spec))))
        def link_token(self, spec):
            """Mints a serving-only link token and its digest tier; publication still requires a separate exact Gate authorization."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_link_token(json.dumps(spec))))
        @property
        def live_preview(self) -> "Oneiron._VaultArtifactsLivePreviewVerbs":
            return Oneiron._VaultArtifactsLivePreviewVerbs(self._client)
        def view(self, request: dict[str, Any]) -> dict[str, Any] | None:
            """One artifact's kind, head and versions, each with its made_by and born-from."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_view(json.dumps(request, allow_nan=False))))
        def units(self, spec):
            """Inspects real DOCX blocks, XLSX cells and PPTX shapes in one version; other kinds explicitly report no annotation unit adapter."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_units(json.dumps(spec))))
        @property
        def anchors(self) -> "Oneiron._VaultArtifactsAnchorsVerbs":
            return Oneiron._VaultArtifactsAnchorsVerbs(self._client)
        @property
        def threads(self) -> "Oneiron._VaultArtifactsThreadsVerbs":
            return Oneiron._VaultArtifactsThreadsVerbs(self._client)
        def export(self, request: dict[str, Any]) -> dict[str, Any] | None:
            """One version's export file (base64), with its pinned name and media type."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_export(json.dumps(request, allow_nan=False))))
        def born_from(self, request: dict[str, Any]) -> dict[str, Any]:
            """The artifacts and versions a task, ask, run, skill or agent run produced."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_born_from(json.dumps(request, allow_nan=False))))
        def proposals(self, request: dict[str, Any]) -> list[dict[str, Any]]:
            """The proposals waiting beside one artifact for Keep or Discard."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_proposals(json.dumps(request, allow_nan=False))))
        def waits(self, request: dict[str, Any]) -> list[dict[str, Any]]:
            """The organ calls held beside one artifact until one of your nodes can run them, each with why it waits."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_waits(json.dumps(request, allow_nan=False))))
        def release_wait(self, request: dict[str, Any]) -> dict[str, Any]:
            """Lets one held organ call go, by its run ref, under the consent a Discard needs."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_release_wait(json.dumps(request, allow_nan=False))))
        def review_slides(self, request: dict[str, Any]) -> dict[str, Any]:
            """Reviews an artifact's slides through the host's decision ladder and holds the comments as one proposal for Keep."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_review_slides(json.dumps(request, allow_nan=False))))
        def ask(self, spec):
            """Asks one typed question over an artifact's sheet rows, paragraphs or folder items through the host's decision ladder and holds the answers as one proposal for Keep or Discard."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_ask(json.dumps(spec))))
        def admit(self, spec):
            """Admits the caller's own provider measurements for one artifact ask's units in place of the host ladder's, validating each decision and its provider-bound paired readings before holding the answers as one proposal for Keep or Discard."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_admit(json.dumps(spec))))
        def propose_outline(self, spec):
            """Proposes a closed typed deck outline as a brief NOTE for the person to keep or decline."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_propose_outline(json.dumps(spec))))
        def outline(self, spec):
            """Reads a typed deck outline, its current NOTE frontier, its keep and its freshness."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_outline(json.dumps(spec))))
        def keep_outline(self, spec):
            """The owner keeps the exact outline frontier, freezing its version and content hash."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_keep_outline(json.dumps(spec))))
        def decline_outline(self, spec):
            """The owner declines the exact outline frontier, clearing its keep and design directions."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_decline_outline(json.dumps(spec))))
        def design_deck(self, spec):
            """Compiles one to three template directions from the exact fresh keep into validated plans or typed design decisions."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_design_deck(json.dumps(spec))))
        def create_deck(self, spec):
            """Emits one checked deck from a fresh kept outline and a planned template, retaining born-from and unverified fit."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_create_deck(json.dumps(spec))))
        def inspect_deck(self, spec):
            """Inspects one PPTX version for native edit targets and comment identities without minting ids."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_inspect_deck(json.dumps(spec))))
        def propose_deck(self, request: dict[str, Any]) -> dict[str, Any]:
            """Runs one native deck transaction over the head and holds the proposal for Keep."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_propose_deck(json.dumps(request, allow_nan=False))))
        def propose_output(self, request: dict[str, Any]) -> dict[str, Any]:
            """Offers one native organ result as the artifact's next version, held for Keep."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_propose_output(json.dumps(request, allow_nan=False))))
        def keep(self, request: dict[str, Any]) -> dict[str, Any]:
            """Keeps one waiting proposal as a new version, once, with its receipt."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_keep(json.dumps(request, allow_nan=False))))
        def discard(self, request: dict[str, Any]) -> dict[str, Any]:
            """Discards one waiting proposal, once, with its receipt."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_discard(json.dumps(request, allow_nan=False))))
        def undo(self, request: dict[str, Any]) -> dict[str, Any]:
            """Undoes one Keep with a new version; the settle stays consumed."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_undo(json.dumps(request, allow_nan=False))))
        def create(self, spec):
            """Creates an artifact with its first version, as the caller: a person's upload, or an agent's version naming its run."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_create(json.dumps(spec))))
        def put(self, input: dict[str, Any]) -> Any:
            """Registers one blob artifact; its bytes ride vault.artifacts.append."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_put(json.dumps(input, allow_nan=False))))
        @property
        def body(self) -> "Oneiron._VaultArtifactsBodyVerbs":
            return Oneiron._VaultArtifactsBodyVerbs(self._client)
        def append(self, input: dict[str, Any]) -> Any:
            """Appends one version of bytes to a blob artifact's append-only chain."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_append(json.dumps(input, allow_nan=False))))
        def read(self, input: dict[str, Any]) -> Any:
            """Reads one version of a blob artifact's bytes."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_read(json.dumps(input, allow_nan=False))))
    class _VaultArtifactsLivePreviewVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def register(self, spec):
            """Opens a draft-labelled, owner-private live preview only for the exact process, port and lease already declared by the trusted session runtime."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_live_preview_register(json.dumps(spec))))
        def read(self, spec):
            """Reads a live draft endpoint and a caller-specific preview URL as the owner or a named invitee; uninvited callers are refused."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_live_preview_read(json.dumps(spec))))
        def close(self, spec):
            """Closes one owner-private preview lease, invalidating its old URLs, streams and upgrades without changing any published artifact pin."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_live_preview_close(json.dumps(spec))))
        def invite(self, spec):
            """Invites one named principal to a private live preview under the lease owner proof; no public audience is created."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_live_preview_invite(json.dumps(spec))))
        def revoke_invite(self, spec):
            """Revokes one private preview invitation and its personal credentials, including active streams."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_live_preview_revoke_invite(json.dumps(spec))))
        def share(self, spec):
            """Mints a revocable sharing URL for one private live preview, replacing any earlier sharing URL; no artifact is published."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_live_preview_share(json.dumps(spec))))
        def revoke_share(self, spec):
            """Revokes the private preview sharing URL and streams that used it while preserving separate owner and invitee credentials."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_live_preview_revoke_share(json.dumps(spec))))
    class _VaultArtifactsAnchorsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def pin(self, spec):
            """Pins an exact readable locator and quote in an artifact version; opening a thread makes the pin durable."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_anchors_pin(json.dumps(spec))))
    class _VaultArtifactsThreadsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def open(self, spec):
            """Opens an anchored thread with its first comment as the caller, retaining its exact version, locator and quote."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_threads_open(json.dumps(spec))))
        def comment(self, spec):
            """Appends a comment as the caller; returns its first stored part, with every part available through threads.read."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_threads_comment(json.dumps(spec))))
        def read(self, spec):
            """Reads a thread, its opening quote, current anchor, explicit pinned, mapped or drifted disposition, comments and assignment."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_threads_read(json.dumps(spec))))
        def list(self, spec):
            """Lists an artifact's readable threads with their opening pins, current anchors, drift, comments and assignments."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_threads_list(json.dumps(spec))))
        def assign(self, spec):
            """Assigns an anchored thread into a durable task brief with its anchor and transcript; an agent-definition assignee dispatches through the engine."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_threads_assign(json.dumps(spec))))
        def state(self, spec):
            """Opens or resolves a thread through its existing claim gate, preserving its anchor, comments and drift."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_threads_state(json.dumps(spec))))
    class _VaultArtifactsBodyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def import_(self, request: dict[str, Any]) -> dict[str, Any]:
            """Imports one office version as the artifact's live body."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_import(json.dumps(request, allow_nan=False))))
        def head(self, request: dict[str, Any]) -> dict[str, Any] | None:
            """An artifact's live body head, or null."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_head(json.dumps(request, allow_nan=False))))
        def read(self, request: dict[str, Any]) -> dict[str, Any]:
            """Reads a live body, at its head or an earlier frontier."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_read(json.dumps(request, allow_nan=False))))
        def commits(self, request: dict[str, Any]) -> list[dict[str, Any]]:
            """Every commit receipt of a live body, in commit order, or one actor's."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_commits(json.dumps(request, allow_nan=False))))
        def edit(self, request: dict[str, Any]) -> dict[str, Any]:
            """A person's typed operations on the live body."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_edit(json.dumps(request, allow_nan=False))))
        @property
        def fork(self) -> "Oneiron._VaultArtifactsBodyForkVerbs":
            return Oneiron._VaultArtifactsBodyForkVerbs(self._client)
        @property
        def proposal(self) -> "Oneiron._VaultArtifactsBodyProposalVerbs":
            return Oneiron._VaultArtifactsBodyProposalVerbs(self._client)
        def export(self, request: dict[str, Any]) -> dict[str, Any]:
            """Exports the live body as the artifact's next version."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_export(json.dumps(request, allow_nan=False))))
        def preview(self, request: dict[str, Any]) -> dict[str, Any]:
            """The workbook an XLSX export would land now, recalculated."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_preview(json.dumps(request, allow_nan=False))))
        @property
        def deck(self) -> "Oneiron._VaultArtifactsBodyDeckVerbs":
            return Oneiron._VaultArtifactsBodyDeckVerbs(self._client)
    class _VaultArtifactsBodyForkVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def open(self, request: dict[str, Any]) -> dict[str, Any]:
            """Opens a fork of the live body for machine work."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_fork_open(json.dumps(request, allow_nan=False))))
        def edit(self, request: dict[str, Any]) -> dict[str, Any]:
            """The opener's typed operations on its fork."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_fork_edit(json.dumps(request, allow_nan=False))))
        def diff(self, request: dict[str, Any]) -> dict[str, Any]:
            """A fork's three-way diff against the live head."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_fork_diff(json.dumps(request, allow_nan=False))))
        def merge(self, request: dict[str, Any]) -> dict[str, Any]:
            """Lands one reviewed fork on an answer."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_fork_merge(json.dumps(request, allow_nan=False))))
        def discard(self, request: dict[str, Any]) -> dict[str, Any]:
            """Abandons an open fork's unlanded work."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_fork_discard(json.dumps(request, allow_nan=False))))
    class _VaultArtifactsBodyProposalVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, request: dict[str, Any]) -> dict[str, Any]:
            """An office proposal: its members, answers and settlement."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_proposal_read(json.dumps(request, allow_nan=False))))
        def settle(self, request: dict[str, Any]) -> dict[str, Any]:
            """Accepts or rejects an office proposal's reviewed forks."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_proposal_settle(json.dumps(request, allow_nan=False))))
    class _VaultArtifactsBodyDeckVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def review(self, request: dict[str, Any]) -> dict[str, Any]:
            """A deck fork's merge preflight against the live head."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_deck_review(json.dumps(request, allow_nan=False))))
        def merge(self, request: dict[str, Any]) -> dict[str, Any]:
            """A person lands a reviewed deck fork."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_deck_merge(json.dumps(request, allow_nan=False))))
        def export(self, request: dict[str, Any]) -> dict[str, Any]:
            """Projects a deck, landing it as the next version when its export gate is open."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_deck_export(json.dumps(request, allow_nan=False))))
        def gate(self, request: dict[str, Any]) -> dict[str, Any]:
            """The deck export gate for a profile."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_deck_gate(json.dumps(request, allow_nan=False))))
        def oracle(self, request: dict[str, Any]) -> dict[str, Any]:
            """Records the deck oracle's receipt for its export profile."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_deck_oracle(json.dumps(request, allow_nan=False))))
        def preview(self, request: dict[str, Any]) -> dict[str, Any]:
            """The asked slides of a deck's head or a fork's merge candidate, drawn by the host's review renderer (provisional)."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_body_deck_preview(json.dumps(request, allow_nan=False))))
    class _VaultCodeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def diff(self, request: dict[str, Any]) -> dict[str, Any] | None:
            """The semantic changes between two tested states of one code file, each with the operations that made it."""
            return json.loads(_translate(lambda: self._client.vault_code_diff(json.dumps(request, allow_nan=False))))
        def blame(self, request: dict[str, Any]) -> dict[str, Any] | None:
            """Every unit of one tested code file state, blamed by the operations that wrote it."""
            return json.loads(_translate(lambda: self._client.vault_code_blame(json.dumps(request, allow_nan=False))))
        def proposal_view(self, request: dict[str, Any]) -> dict[str, Any] | None:
            """One repo proposal's semantic change from its base, under the provenance it was proposed with."""
            return json.loads(_translate(lambda: self._client.vault_code_proposal_view(json.dumps(request, allow_nan=False))))
        @property
        def symbols(self) -> "Oneiron._VaultCodeSymbolsVerbs":
            return Oneiron._VaultCodeSymbolsVerbs(self._client)
        def proposal_submit(self, spec):
            """Stage one file change of a repository as a Proposed proposal with its retained base, under the review lens catalog the owner sends. Owner only. The engine mints the proposal id; nothing is approved, queued or landed."""
            return json.loads(_translate(lambda: self._client.vault_code_proposal_submit(json.dumps(spec))))
        def conflict_record(self, spec):
            """Record a real Git overlap between two stored one-file proposals at the same retained base, with both trees, paths and a linked reconciliation task. Owner only; neither branch moves."""
            return json.loads(_translate(lambda: self._client.vault_code_conflict_record(json.dumps(spec))))
        def conflict_view(self, spec):
            """Read open repository conflicts and their durable resolution claims, including each reconciliation task. Owner only."""
            return json.loads(_translate(lambda: self._client.vault_code_conflict_view(json.dumps(spec))))
        def proposal_resolve(self, spec):
            """Stage a one-file resolution of an active repository conflict as another Proposed proposal, preserving its original proposals and reconciliation task. Owner only; nothing lands."""
            return json.loads(_translate(lambda: self._client.vault_code_proposal_resolve(json.dumps(spec))))
        def proposal_review(self, spec):
            """Record the authenticated owner's immutable critic opinion on one proposal lens. Independent reviewers only; this is no contract-check execution receipt."""
            return json.loads(_translate(lambda: self._client.vault_code_proposal_review(json.dumps(spec))))
        def proposal_settle(self, spec):
            """Approve or reject one reviewed code proposal as an independent owner, retaining a decision receipt. Approval still needs unanimous critics and never advances head; only the tested merge queue lands it."""
            return json.loads(_translate(lambda: self._client.vault_code_proposal_settle(json.dumps(spec))))
        def proposal_settlement(self, spec):
            """Read a code proposal's review decision receipt and execution lineage, including its conflict, original proposals, reconciliation task and resolution claim. Owner only."""
            return json.loads(_translate(lambda: self._client.vault_code_proposal_settlement(json.dumps(spec))))
        def oplog(self, spec):
            """Read the durable mutation log of one repository in sequence order: prepared, applied and failed mutations. Owner only. It is not a proposal queue and holds no pending proposal."""
            return json.loads(_translate(lambda: self._client.vault_code_oplog(json.dumps(spec))))
        def model_heal_count(self, spec):
            """Read the tally this vault keeps of its own durable executor turns one model needed wire healing for, by full provider/name@revision id, zero when absent. Owner only. A routing signal, not a run correction receipt or repair policy."""
            return json.loads(_translate(lambda: self._client.vault_code_model_heal_count(json.dumps(spec))))
        @property
        def waits(self) -> "Oneiron._VaultCodeWaitsVerbs":
            return Oneiron._VaultCodeWaitsVerbs(self._client)
        def repo_diff(self, request: dict[str, Any]) -> dict[str, Any] | None:
            """Every file changed between two trees of a repository, unit by unit, with the operations that wrote each."""
            return json.loads(_translate(lambda: self._client.vault_code_repo_diff(json.dumps(request, allow_nan=False))))
        def export(self, spec):
            """Export one already-finalized and reviewed document revision through the existing origin publication protocol."""
            return json.loads(_translate(lambda: self._client.vault_code_export(json.dumps(spec))))
        @property
        def origin(self) -> "Oneiron._VaultCodeOriginVerbs":
            return Oneiron._VaultCodeOriginVerbs(self._client)
        @property
        def checkout(self) -> "Oneiron._VaultCodeCheckoutVerbs":
            return Oneiron._VaultCodeCheckoutVerbs(self._client)
        @property
        def views(self) -> "Oneiron._VaultCodeViewsVerbs":
            return Oneiron._VaultCodeViewsVerbs(self._client)
        @property
        def cache(self) -> "Oneiron._VaultCodeCacheVerbs":
            return Oneiron._VaultCodeCacheVerbs(self._client)
        @property
        def snapshots(self) -> "Oneiron._VaultCodeSnapshotsVerbs":
            return Oneiron._VaultCodeSnapshotsVerbs(self._client)
        @property
        def merge_queue(self) -> "Oneiron._VaultCodeMergeQueueVerbs":
            return Oneiron._VaultCodeMergeQueueVerbs(self._client)
    class _VaultCodeSymbolsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def declare(self, spec):
            """Declare the current repository symbols a task will touch, held by the caller until host time plus ttl_seconds. Owner only. An overlap waits behind the tasks it names, never refused; it grants no write, approval or landing."""
            return json.loads(_translate(lambda: self._client.vault_code_symbols_declare(json.dumps(spec))))
        def renew(self, spec):
            """Renew the live symbol declaration the caller holds for one task by its declared lifetime. Owner only."""
            return json.loads(_translate(lambda: self._client.vault_code_symbols_renew(json.dumps(spec))))
        def release(self, spec):
            """Release the symbol declaration the caller holds for one task. Owner only. Keyed by task and holder with no epoch fence; it applies, approves and schedules nothing."""
            return json.loads(_translate(lambda: self._client.vault_code_symbols_release(json.dumps(spec))))
        def definitions(self, spec):
            """Find Rust symbol definitions by exact name within one pinned code snapshot. Owner only. Definitions only: no calls, imports or refs relation, and no other language."""
            return json.loads(_translate(lambda: self._client.vault_code_symbols_definitions(json.dumps(spec))))
    class _VaultCodeWaitsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def resolve(self, spec):
            """Answer one sealed code consent wait as the authenticated owner, on the word the owner gave on its ask. First answer wins; the held effect meets its own current gate once. No raw reply, grant or consumption is taken."""
            return json.loads(_translate(lambda: self._client.vault_code_waits_resolve(json.dumps(spec))))
        def receipt(self, spec):
            """Read one code consent wait as the authenticated owner: its held effect, answer, settlement and replay consumption receipts. Never answers, resumes or sends. Null for an unknown, unsealed or withheld wait."""
            return json.loads(_translate(lambda: self._client.vault_code_waits_receipt(json.dumps(spec))))
    class _VaultCodeOriginVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def register(self, spec):
            """Register a new empty served repository for authenticated Git and vault-LFS, with an explicit default branch; existing names are refused."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_register(json.dumps(spec))))
        @property
        def mirror(self) -> "Oneiron._VaultCodeOriginMirrorVerbs":
            return Oneiron._VaultCodeOriginMirrorVerbs(self._client)
        @property
        def publish(self) -> "Oneiron._VaultCodeOriginPublishVerbs":
            return Oneiron._VaultCodeOriginPublishVerbs(self._client)
        @property
        def authority(self) -> "Oneiron._VaultCodeOriginAuthorityVerbs":
            return Oneiron._VaultCodeOriginAuthorityVerbs(self._client)
        def publications(self, spec):
            """Read durable publication records for one served repository ref and commit without synthesizing a push acknowledgement."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_publications(json.dumps(spec))))
    class _VaultCodeOriginMirrorVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Read one served repository's outbound mirror setup, cadence, pushed refs and last recorded run under the owner's credential."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_mirror_get(json.dumps(spec))))
        def set(self, spec):
            """Set one served origin's HTTPS mirror, its custody-held origin:mirror-push token, cadence and sync strategy (ask_me unless named; the same URL keeps its own); the token binding is checked in the setup write."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_mirror_set(json.dumps(spec))))
        def strategy(self, spec):
            """Set one served origin mirror's sync strategy: ask_me sends nothing until an exact publish request is approved, schedule pushes every published ref on its cadence; it changes only the strategy and its revision."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_mirror_strategy(json.dumps(spec))))
        def clear(self, spec):
            """Stop outbound mirroring of one served repository; the mirror retains its existing refs and bytes."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_mirror_clear(json.dumps(spec))))
        def push(self, spec):
            """Push one origin's published Git refs to its schedule mirror now, recording the real outcome (ask_me refuses publish_request_required); refs pushed are not readiness, which names the LFS objects the history needs."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_mirror_push(json.dumps(spec))))
    class _VaultCodeOriginPublishVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def request(self, spec):
            """Ask to publish one exact commit to one branch of a served origin's mirror, once: the request leases the push on the branch tip an authenticated read saw and records a full-ancestry review of what it would expose."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_publish_request(json.dumps(spec))))
        def review(self, spec):
            """Read one page of an exact publish request's full-ancestry review: each commit the push would expose, with its parents, and every path, mode and object those commits introduce."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_publish_review(json.dumps(spec))))
        def get(self, spec):
            """Read one exact publish request: its tuple, review digest, state, acts and the typed refusal that ended it, if one did."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_publish_get(json.dumps(spec))))
        def approve(self, spec):
            """Approve one pending exact publish request by naming its review digest, as the owner or under one Grant covering the branch and every reviewed path; no second approval is asked."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_publish_approve(json.dumps(spec))))
        def execute(self, spec):
            """Push one approved exact publish request's commit to its branch once, leased on the recorded tip; an unproven outcome settles from the mirror and is never sent again."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_publish_execute(json.dumps(spec))))
        def cancel(self, spec):
            """Cancel one pending or approved exact publish request; a request whose push is in flight or that already settled stays as it is."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_publish_cancel(json.dumps(spec))))
    class _VaultCodeOriginAuthorityVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Read one served origin authority and this host identity under the owner credential."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_authority_get(json.dumps(spec))))
        def set(self, spec):
            """Cut over one existing served origin under the owner proof and expected authority epoch."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_authority_set(json.dumps(spec))))
    class _VaultCodeCheckoutVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def bind(self, spec):
            """Materialize an existing live owner checkout with lease-bound origin remotes and no upstream credential."""
            return json.loads(_translate(lambda: self._client.vault_code_checkout_bind(json.dumps(spec))))
        def claim(self, spec):
            """Claim the caller's checkout on an assigned task, with a bounded TTL and declared idempotence."""
            return json.loads(_translate(lambda: self._client.vault_code_checkout_claim(json.dumps(spec))))
        def get(self, spec):
            """Read checkout custody and vault-clock expiry as a task party, without claiming or renewing it."""
            return json.loads(_translate(lambda: self._client.vault_code_checkout_get(json.dumps(spec))))
        def renew(self, spec):
            """Renew the caller's still-live checkout under its exact holder and epoch fence."""
            return json.loads(_translate(lambda: self._client.vault_code_checkout_renew(json.dumps(spec))))
        def reclaim(self, spec):
            """Reclaim an expired declared-idempotent build or verify checkout as an authorized successor at the named epoch."""
            return json.loads(_translate(lambda: self._client.vault_code_checkout_reclaim(json.dumps(spec))))
        def takeover(self, spec):
            """Explicitly take over a checkout as its task owner, including effect work, at the named epoch."""
            return json.loads(_translate(lambda: self._client.vault_code_checkout_takeover(json.dumps(spec))))
        def publish(self, spec):
            """Publish a stored candidate result for checkout settlement under the caller's live epoch; this does not export a Git head."""
            return json.loads(_translate(lambda: self._client.vault_code_checkout_publish(json.dumps(spec))))
        def settle(self, spec):
            """Consume one published checkout result at its epoch as select, apply, release or discard; an identical retry returns its receipt."""
            return json.loads(_translate(lambda: self._client.vault_code_checkout_settle(json.dumps(spec))))
        def teardown(self, spec):
            """Collect the caller's checkout only with a matching durable pushed-head receipt and clear custody; retain dirty or uncertain trees."""
            return json.loads(_translate(lambda: self._client.vault_code_checkout_teardown(json.dumps(spec))))
    class _VaultCodeViewsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def materialize(self, spec):
            """Materialize a private linked working view from verified tested file frontiers in the authenticated owner account."""
            return json.loads(_translate(lambda: self._client.vault_code_views_materialize(json.dumps(spec))))
        def get(self, spec):
            """Read one working view and its immutable tested base under the authenticated owner account."""
            return json.loads(_translate(lambda: self._client.vault_code_views_get(json.dumps(spec))))
        def read(self, spec):
            """Read the current bytes of one selected input in the authenticated owner working view."""
            return json.loads(_translate(lambda: self._client.vault_code_views_read(json.dumps(spec))))
        def action(self, spec):
            """Freeze current view input identities and return the REAPI action digest with its exact command bytes and input root digest."""
            return json.loads(_translate(lambda: self._client.vault_code_views_action(json.dumps(spec))))
        def build(self, spec):
            """Run a pinned native owner build or verify leg, reusing clean account-local results and retaining secret-consuming exhaust as tainted."""
            return json.loads(_translate(lambda: self._client.vault_code_views_build(json.dumps(spec))))
    class _VaultCodeCacheVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Read one clean immutable account-local build result by action key without executing a command."""
            return json.loads(_translate(lambda: self._client.vault_code_cache_get(json.dumps(spec))))
        def reuse(self, spec):
            """Reuse an authorized clean action result into another matching working view without dispatching a cold build."""
            return json.loads(_translate(lambda: self._client.vault_code_cache_reuse(json.dumps(spec))))
    class _VaultCodeSnapshotsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def ingest(self, spec):
            """Import one committed Git tree, by an absolute folder on the serving host and a full 40-hex commit, as a custody-filtered snapshot. Owner only. It registers no repository, whitelist, membership or receipt."""
            return json.loads(_translate(lambda: self._client.vault_code_snapshots_ingest(json.dumps(spec))))
        def get(self, spec):
            """Read the file manifest of one code snapshot, pinned by its imported artifact and fork hash. Owner only. Files carry blob hashes, not document versions, and the scope key is an index key, not a grant."""
            return json.loads(_translate(lambda: self._client.vault_code_snapshots_get(json.dumps(spec))))
        def read(self, spec):
            """Read one UTF-8 file and its SHA-256 from the frozen blobs of a pinned code snapshot, never from the folder on disk. Owner only."""
            return json.loads(_translate(lambda: self._client.vault_code_snapshots_read(json.dumps(spec))))
    class _VaultCodeMergeQueueVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def enqueue(self, spec):
            """Queue stored repository proposals as one batch on the queue green commit, one to six per call, with no batching window. Owner only. The proposals keep their own bytes and reviews; nothing is checked or landed."""
            return json.loads(_translate(lambda: self._client.vault_code_merge_queue_enqueue(json.dumps(spec))))
        def stage(self, spec):
            """Materialize every nonempty subset of one queued batch as a journaled detached speculative worktree. Owner only. Head and green do not move."""
            return json.loads(_translate(lambda: self._client.vault_code_merge_queue_stage(json.dumps(spec))))
        def observe(self, spec):
            """Read the queue head and green Git commits, the named batches in request order and the stored contract verdicts they name. Owner only. It never recovers or settles, and a verdict is no check execution receipt."""
            return json.loads(_translate(lambda: self._client.vault_code_merge_queue_observe(json.dumps(spec))))
        def requeue_survivors(self, spec):
            """Queue the proposals a diagnosed red batch did not quarantine as a new batch, keeping the red batch and its quarantine. Owner only. No durable parent or child link is written."""
            return json.loads(_translate(lambda: self._client.vault_code_merge_queue_requeue_survivors(json.dumps(spec))))
        def land_reviewed(self, spec):
            """Advance the fast-tested head by one ready batch through reviewed-stack admission alone. Owner only. Each proposal still needs unanimous critic approval and exact bytes and base; the owner proof approves nothing."""
            return json.loads(_translate(lambda: self._client.vault_code_merge_queue_land_reviewed(json.dumps(spec))))
        def settle_slow(self, spec):
            """Settle stored slow results in landing order: green advances past passing ones, and a red one rolls the ungreen suffix back. Owner only. The caller names no commit or result."""
            return json.loads(_translate(lambda: self._client.vault_code_merge_queue_settle_slow(json.dumps(spec))))
        def recover(self, spec):
            """Reconcile an interrupted landing or rollback with its persisted mutation receipts. Owner only. Unreceipted divergence refuses; nothing is approved or rebased."""
            return json.loads(_translate(lambda: self._client.vault_code_merge_queue_recover(json.dumps(spec))))
    class _VaultResultsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def status(self, spec):
            """The owner inspects retained result occurrences, incomplete body descriptors and recorded producing-run effects without entering the run."""
            return json.loads(_translate(lambda: self._client.vault_results_status(json.dumps(spec))))
        def recover(self, spec):
            """The owner reopens retained result status after restart; it never resumes the producer or replays an effect to regenerate output."""
            return json.loads(_translate(lambda: self._client.vault_results_recover(json.dumps(spec))))
        def read(self, spec):
            """The owner reads one exact retained result occurrence card under its current taint and source-row fence, never by content authority alone."""
            return json.loads(_translate(lambda: self._client.vault_results_read(json.dumps(spec))))
        def slice(self, spec):
            """The owner reads a typed byte or line range of one exact result occurrence, with bounded continuations and current taint withholding."""
            return json.loads(_translate(lambda: self._client.vault_results_slice(json.dumps(spec))))
    class _VaultAgentsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """The owner creates an inert custom agent composition with an optional per-domain refusal dial, caller-derived authorship and existing fork/ceiling gates; no attempt is dispatched."""
            return json.loads(_translate(lambda: self._client.vault_agents_create(json.dumps(spec))))
        def get(self, spec):
            """The owner reads one saved agent composition, including its declared refusal dial, version and approval state."""
            return json.loads(_translate(lambda: self._client.vault_agents_get(json.dumps(spec))))
        def update(self, spec):
            """The owner edits the expected definition version and optional refusal dial through the existing immutable-field and ceiling gates; refusal decisions read the live dial."""
            return json.loads(_translate(lambda: self._client.vault_agents_update(json.dumps(spec))))
        @property
        def dreaming(self) -> "Oneiron._VaultAgentsDreamingVerbs":
            return Oneiron._VaultAgentsDreamingVerbs(self._client)
        @property
        def grants(self) -> "Oneiron._VaultAgentsGrantsVerbs":
            return Oneiron._VaultAgentsGrantsVerbs(self._client)
        def base(self, spec=None):
            """The owner reads the base agents' principal ids, the Coach's and the Dreamer's, which vault.agents.grants.mint takes as its agent."""
            return json.loads(_translate(lambda: self._client.vault_agents_base(json.dumps({} if spec is None else spec))))
        @property
        def spawn(self) -> "Oneiron._VaultAgentsSpawnVerbs":
            return Oneiron._VaultAgentsSpawnVerbs(self._client)
        def export_pack(self, request: dict[str, Any]) -> dict[str, Any]:
            """The agent's travelling AgentPack folder (files base64) and what stayed home."""
            return json.loads(_translate(lambda: self._client.vault_agents_export_pack(json.dumps(request, allow_nan=False))))
    class _VaultAgentsDreamingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """The owner reads one agent's dreaming choice: its stored mode, the mode in force and its own dreaming model slot."""
            return json.loads(_translate(lambda: self._client.vault_agents_dreaming_get(json.dumps(spec))))
        def set(self, spec):
            """The owner sets one agent's dreaming choice on the revision read: its own model, the vault weaver's, or off; sharing a model never shares its diary."""
            return json.loads(_translate(lambda: self._client.vault_agents_dreaming_set(json.dumps(spec))))
    class _VaultAgentsGrantsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def mint(self, spec):
            """The owner grants one named agent an explicit verb list inside his exact scope, and optional repo bounds, until he revokes it or until the expiry he sets; a second mint adds a second grant."""
            return json.loads(_translate(lambda: self._client.vault_agents_grants_mint(json.dumps(spec))))
        def revoke(self, spec):
            """The owner revokes one agent grant by its id; the agent stops counting it at once, and a repeat changes nothing."""
            return json.loads(_translate(lambda: self._client.vault_agents_grants_revoke(json.dumps(spec))))
    class _VaultAgentsSpawnVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner launches one reserved planned agent or team under an intent key on this host's planner: the type placed, the plan frozen at the root, then queued; the same key answers what it kept."""
            return json.loads(_translate(lambda: self._client.vault_agents_spawn(json.dumps(spec))))
        def get(self, spec):
            """The owner reads one spawned agent's stored observations by its attempt: its type stamp and frozen plan, the team actually launched, its seat route, critic artifacts and receipt-backed learning."""
            return json.loads(_translate(lambda: self._client.vault_agents_spawn_get(json.dumps(spec))))
    class _VaultRepoVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def git_push(self) -> "Oneiron._VaultRepoGitPushVerbs":
            return Oneiron._VaultRepoGitPushVerbs(self._client)
        @property
        def anchor(self) -> "Oneiron._VaultRepoAnchorVerbs":
            return Oneiron._VaultRepoAnchorVerbs(self._client)
        @property
        def snapshots(self) -> "Oneiron._VaultRepoSnapshotsVerbs":
            return Oneiron._VaultRepoSnapshotsVerbs(self._client)
        @property
        def symbols(self) -> "Oneiron._VaultRepoSymbolsVerbs":
            return Oneiron._VaultRepoSymbolsVerbs(self._client)
        @property
        def views(self) -> "Oneiron._VaultRepoViewsVerbs":
            return Oneiron._VaultRepoViewsVerbs(self._client)
        @property
        def merge_queue(self) -> "Oneiron._VaultRepoMergeQueueVerbs":
            return Oneiron._VaultRepoMergeQueueVerbs(self._client)
        @property
        def work(self) -> "Oneiron._VaultRepoWorkVerbs":
            return Oneiron._VaultRepoWorkVerbs(self._client)
        def proposal_submit(self, spec):
            """Keeps one whole-file change against the attached run's own work as an immutable Proposed proposal, under the owner's review catalog and a host-witnessed provenance; until both exist it holds with a typed code and the work is kept."""
            return json.loads(_translate(lambda: self._client.vault_repo_proposal_submit(json.dumps(spec))))
        @property
        def checkout(self) -> "Oneiron._VaultRepoCheckoutVerbs":
            return Oneiron._VaultRepoCheckoutVerbs(self._client)
        def export(self, spec):
            """Exports one finalized, promoted revision from the attached run's own checkout when one Grant lists publish over the revision's paths; otherwise it holds with a typed code. git_push never implies an export."""
            return json.loads(_translate(lambda: self._client.vault_repo_export(json.dumps(spec))))
    class _VaultRepoGitPushVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def mint(self, spec):
            """The owner grants one live person or agent raw git_push on explicitly named repos, each whole, until he revokes it or until the expiry he sets; a write grant never implies it."""
            return json.loads(_translate(lambda: self._client.vault_repo_git_push_mint(json.dumps(spec))))
        def revoke(self, spec):
            """The owner revokes one git_push Grant by its id; its holder's next push is refused at once, and a repeat changes nothing."""
            return json.loads(_translate(lambda: self._client.vault_repo_git_push_revoke(json.dumps(spec))))
    class _VaultRepoAnchorVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def bind(self, spec):
            """The owner binds one served repo to its CODE anchor in a live PROJECT he names, the anchor a git_push Grant, a run's repo bounds and a publish name it by; a repeat changes nothing."""
            return json.loads(_translate(lambda: self._client.vault_repo_anchor_bind(json.dumps(spec))))
    class _VaultRepoSnapshotsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Reads one snapshot's manifest of a repo the Grant of this credential's attached live run admits, at the commit its full ref names now; the run, never the request, binds the actor, TASK and lease."""
            return json.loads(_translate(lambda: self._client.vault_repo_snapshots_get(json.dumps(spec))))
        def read(self, spec):
            """Reads one file of such a snapshot on a path the attached run's Grant reads."""
            return json.loads(_translate(lambda: self._client.vault_repo_snapshots_read(json.dumps(spec))))
        def ingest(self, spec):
            """Imports the commit an admitted repo's full ref names now, readable paths only, for the attached run."""
            return json.loads(_translate(lambda: self._client.vault_repo_snapshots_ingest(json.dumps(spec))))
    class _VaultRepoSymbolsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def definitions(self, spec):
            """Reads a snapshot's exact-name Rust definitions on paths the attached run's Grant reads."""
            return json.loads(_translate(lambda: self._client.vault_repo_symbols_definitions(json.dumps(spec))))
        def declare(self, spec):
            """Declares current symbols of the attached run's own work on paths its Grant edits, for its TASK; an overlap waits, never refused."""
            return json.loads(_translate(lambda: self._client.vault_repo_symbols_declare(json.dumps(spec))))
        def renew(self, spec):
            """Extends the attached run's own symbol declaration by its declared lifetime."""
            return json.loads(_translate(lambda: self._client.vault_repo_symbols_renew(json.dumps(spec))))
        def release(self, spec):
            """Removes the attached run's own symbol declaration."""
            return json.loads(_translate(lambda: self._client.vault_repo_symbols_release(json.dumps(spec))))
    class _VaultRepoViewsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Reads the attached run's own work, as it was opened."""
            return json.loads(_translate(lambda: self._client.vault_repo_views_get(json.dumps(spec))))
        def read(self, spec):
            """Reads one file of the attached run's own work."""
            return json.loads(_translate(lambda: self._client.vault_repo_views_read(json.dumps(spec))))
    class _VaultRepoMergeQueueVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def observe(self, spec):
            """Reads the merge queue the attached run's own work is pinned under, with its own entries and what each waits behind."""
            return json.loads(_translate(lambda: self._client.vault_repo_merge_queue_observe(json.dumps(spec))))
        def enqueue(self, spec):
            """Queues the attached run's own stored proposals of one work as one batch, under the declaration they were made under."""
            return json.loads(_translate(lambda: self._client.vault_repo_merge_queue_enqueue(json.dumps(spec))))
    class _VaultRepoWorkVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def open(self, spec):
            """Opens a fresh private working set of an admitted repo at its queue's green commit for the attached run, readable paths only."""
            return json.loads(_translate(lambda: self._client.vault_repo_work_open(json.dumps(spec))))
    class _VaultRepoCheckoutVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def bind(self, spec):
            """Materializes the attached run's own live checkout lease of an admitted served repo, for its TASK, with its lease-route remote when a door base is named; no lease is minted and no host path is shown."""
            return json.loads(_translate(lambda: self._client.vault_repo_checkout_bind(json.dumps(spec))))
    class _VaultStandingBlocksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def configure(self, spec):
            """The owner configures one agent's standing block in one world with its name and token floor; reopening the same pair answers the stored handle."""
            return json.loads(_translate(lambda: self._client.vault_standing_blocks_configure(json.dumps(spec))))
        def reconfigure(self, spec):
            """The owner gives a configured standing block a new name and token floor; an unconfigured pair is refused, never implicitly opened."""
            return json.loads(_translate(lambda: self._client.vault_standing_blocks_reconfigure(json.dumps(spec))))
        def get(self, spec):
            """The owner reads one agent's configured standing block in one world: its handle, name and token floor."""
            return json.loads(_translate(lambda: self._client.vault_standing_blocks_get(json.dumps(spec))))
        def list(self, spec):
            """The owner lists every standing block configured for one agent, one per world, in world order."""
            return json.loads(_translate(lambda: self._client.vault_standing_blocks_list(json.dumps(spec))))
    class _VaultWorkflowsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def save(self, spec):
            """The owner saves an ordered composition of live AGENT_DEF steps at a new WORKFLOW id at revision 1; an occupied id is refused and no attempt is dispatched."""
            return json.loads(_translate(lambda: self._client.vault_workflows_save(json.dumps(spec))))
        def get(self, spec):
            """The owner reads one saved workflow, its steps, revision and fork lineage."""
            return json.loads(_translate(lambda: self._client.vault_workflows_get(json.dumps(spec))))
        def update(self, spec):
            """The owner edits exactly the workflow revision they read; the door assigns the next revision and keeps fork lineage, and runs already admitted keep their captured steps."""
            return json.loads(_translate(lambda: self._client.vault_workflows_update(json.dumps(spec))))
        def dispatch(self, spec):
            """The owner starts one root run of a saved workflow under a briefing through the ordinary dispatch admission for every step; each step's definition revision, scope and ceiling are captured, and a retried intent key returns the same run."""
            return json.loads(_translate(lambda: self._client.vault_workflows_dispatch(json.dumps(spec))))
        def dispatch_bound(self, spec):
            """A member binds one run of a saved workflow to an idle standard TASK they own, as themselves, under funding terms they accepted: its root spend scope names them as payer, and a retried intent key with the same terms returns the same run."""
            return json.loads(_translate(lambda: self._client.vault_workflows_dispatch_bound(json.dumps(spec))))
        def status(self, spec):
            """The owner reads one workflow run by its root attempt: the captured step definitions, the active step attempt and each settled step's attempt and result."""
            return json.loads(_translate(lambda: self._client.vault_workflows_status(json.dumps(spec))))
    class _VaultTaskTypesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def pin(self, spec):
            """The owner stores an authored task-type tree on an open team-shape fork, as a candidate; the receipt says whether it is in force."""
            return json.loads(_translate(lambda: self._client.vault_task_types_pin(json.dumps(spec))))
        def get(self, spec):
            """The owner reads the task-type tree in force, or one kept tree version, for the vault or a project."""
            return json.loads(_translate(lambda: self._client.vault_task_types_get(json.dumps(spec))))
    class _VaultTasksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def cancel_force(self, spec):
            """The owner force-stops every live branch of one TASK, unrefusably: each running attempt is cancelled, its live step stops, and the reply carries every branch's landing and cancellation receipts."""
            return json.loads(_translate(lambda: self._client.vault_tasks_cancel_force(json.dumps(spec))))
        @property
        def linear(self) -> "Oneiron._VaultTasksLinearVerbs":
            return Oneiron._VaultTasksLinearVerbs(self._client)
    class _VaultTasksLinearVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def mapping(self) -> "Oneiron._VaultTasksLinearMappingVerbs":
            return Oneiron._VaultTasksLinearMappingVerbs(self._client)
        def provenance(self, spec):
            """One TASK's stored Linear mirror events, newest first: webhook deliveries, sent pushes, mapping and title edits, with their external evidence and receipts."""
            return json.loads(_translate(lambda: self._client.vault_tasks_linear_provenance(json.dumps(spec))))
    class _VaultTasksLinearMappingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """One TASK's Linear issue mapping: its link, watermarks, unresolved conflicts, opt-out, mapping and dirty revisions, and its newest mirror events."""
            return json.loads(_translate(lambda: self._client.vault_tasks_linear_mapping(json.dumps(spec))))
        def edit(self, spec):
            """Links, unlinks or mirrors again one TASK's Linear issue, by the TASK's owner at the mapping revision the caller read, under an intent key."""
            return json.loads(_translate(lambda: self._client.vault_tasks_linear_mapping_edit(json.dumps(spec))))
    class _VaultRunsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def branches(self) -> "Oneiron._VaultRunsBranchesVerbs":
            return Oneiron._VaultRunsBranchesVerbs(self._client)
        def pause(self, spec):
            """Pauses one queued or scheduled branch of a run by its attempt id: the vault owner pauses any branch, any other caller only a branch of a TASK it owns. A repeat answers already_paused; a running branch is not paused."""
            return json.loads(_translate(lambda: self._client.vault_runs_pause(json.dumps(spec))))
        def resume(self, spec):
            """Resumes one paused branch of a run by its attempt id: the vault owner resumes any branch, any other caller only a branch of a TASK it owns. A repeat answers already_resumed."""
            return json.loads(_translate(lambda: self._client.vault_runs_resume(json.dumps(spec))))
        def step(self, spec):
            """Reads one committed model step of a Dreamer attempt by its job reference and step hash: the completion claim, the run identity it recorded and the stored response, without calling a model, spending a lease or admitting work."""
            return json.loads(_translate(lambda: self._client.vault_runs_step(json.dumps(spec))))
        def checkpoint(self, spec):
            """Reads one page of a code run's committed step checkpoints and the stored replies its parked calls resumed with, without attaching, resuming or dispatching the run."""
            return json.loads(_translate(lambda: self._client.vault_runs_checkpoint(json.dumps(spec))))
        def program(self, spec):
            """Reads where one of the caller's turn programs stands, or any program when the owner asks: its admission, queue tries, held park, code-run lifecycle and one page of its steps, without running, resuming or leasing it."""
            return json.loads(_translate(lambda: self._client.vault_runs_program(json.dumps(spec))))
        def program_step(self, spec):
            """Reads one settled step of a turn program's run and its exact result as far as the caller's credential reads it: a model step's terminal claim and stored response, a write's receipt, or a send's kept body."""
            return json.loads(_translate(lambda: self._client.vault_runs_program_step(json.dumps(spec))))
        def program_checkpoint(self, spec):
            """Reads the resume checkpoint of one of the caller's turn programs, or any when the owner asks: its head, frontier, a page of the settled calls its restarter answers and the wait it parked on, without running or resuming it."""
            return json.loads(_translate(lambda: self._client.vault_runs_program_checkpoint(json.dumps(spec))))
        def review(self, spec):
            """The owner reviews an explicit cross-kind set of existing changes, including child-job changes, with a content-bound review id and a derived explainer."""
            return json.loads(_translate(lambda: self._client.vault_runs_review(json.dumps(spec))))
        def settle(self, spec):
            """The owner approves or rejects the exact reviewed set through each kind's existing gate and keeps its ProposalOutcome and run revert handle."""
            return json.loads(_translate(lambda: self._client.vault_runs_settle(json.dumps(spec))))
        def settlement(self, spec):
            """The owner reads the durable cross-kind ProposalOutcome of one reviewed job and its revert handle."""
            return json.loads(_translate(lambda: self._client.vault_runs_settlement(json.dumps(spec))))
    class _VaultRunsBranchesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """The owner reads every branch of one TASK: its lifecycle state, run status, result, typed asks and signals, and its landing, saved partial-result (resume point) and cancellation receipts."""
            return json.loads(_translate(lambda: self._client.vault_runs_branches_get(json.dumps(spec))))
    class _VaultConsultsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """The owner reads one consult TASK: its deadline and terminal register (how it ended, its result, the evidence or abstention reason, the ladder outcome and any counter TASK), as refs, never bodies."""
            return json.loads(_translate(lambda: self._client.vault_consults_get(json.dumps(spec))))
    class _VaultWorkspaceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def establish(self, spec):
            """The caller establishes a workspace preset and companion policy through its existing owner or workspace-settings power; no member or companion is minted."""
            return json.loads(_translate(lambda: self._client.vault_workspace_establish(json.dumps(spec))))
        @property
        def members(self) -> "Oneiron._VaultWorkspaceMembersVerbs":
            return Oneiron._VaultWorkspaceMembersVerbs(self._client)
        def roster(self, spec):
            """The owner reads the workspace house and companion roster with their actor, subject and facet refs."""
            return json.loads(_translate(lambda: self._client.vault_workspace_roster(json.dumps(spec))))
        @property
        def work_companion(self) -> "Oneiron._VaultWorkspaceWorkCompanionVerbs":
            return Oneiron._VaultWorkspaceWorkCompanionVerbs(self._client)
    class _VaultWorkspaceMembersVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def onboard(self, spec):
            """A holder of the workspace AddMember power runs resumable member and companion onboarding. Bringing an existing companion requires the member's own caller proof; mailbox enrollment is separate."""
            return json.loads(_translate(lambda: self._client.vault_workspace_members_onboard(json.dumps(spec))))
    class _VaultWorkspaceWorkCompanionVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """A workspace's work_companion policy, readable by every member it governs."""
            return json.loads(_translate(lambda: self._client.vault_workspace_work_companion_get(json.dumps(spec))))
        def set(self, spec):
            """The owner, or an Admin holding the workspace-settings power, sets a workspace's work_companion policy in person."""
            return json.loads(_translate(lambda: self._client.vault_workspace_work_companion_set(json.dumps(spec))))
    class _VaultCriticVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def review(self, spec):
            """Reviews one document, design or proposed claim through the host's decision ladder, one lens at a time, and writes the verdict as the caller; nothing is applied to the target."""
            return json.loads(_translate(lambda: self._client.vault_critic_review(json.dumps(spec))))
    class _VaultRoomsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self):
            """The caller's rooms its own grants admit; inside a room turn, only that room."""
            return json.loads(_translate(lambda: self._client.vault_rooms_list(json.dumps({}))))
        def messages(self, room_ref, after=None, limit=None, thread_ref=None):
            """One page of the turns in a room this reader may read; with thread_ref, of that one thread alone."""
            return json.loads(_translate(lambda: self._client.vault_rooms_messages(json.dumps({"room_ref": room_ref, "after": after, "limit": limit, "thread_ref": thread_ref}))))
        def participants(self, spec):
            """One page of who took part in a room or one of its threads, each with its causes and whether it may take part now."""
            return json.loads(_translate(lambda: self._client.vault_rooms_participants(json.dumps(spec))))
        def render(self, room_ref):
            """The standalone rendered view of a room's threads."""
            return json.loads(_translate(lambda: self._client.vault_rooms_render(json.dumps({"room_ref": room_ref}))))
        def find(self, room_ref, after=None, limit=None):
            """One page of a room's threads."""
            return json.loads(_translate(lambda: self._client.vault_rooms_find(json.dumps({"room_ref": room_ref, "after": after, "limit": limit}))))
        def get(self, room_ref, turn_ref):
            """One thread of a room by its turn, even when every list omits it."""
            return json.loads(_translate(lambda: self._client.vault_rooms_get(json.dumps({"room_ref": room_ref, "turn_ref": turn_ref}))))
        def trunk(self, room_ref, turn_ref):
            """One trunk turn of a room, with the completed TASK result headers that hang under it."""
            return json.loads(_translate(lambda: self._client.vault_rooms_trunk(json.dumps({"room_ref": room_ref, "turn_ref": turn_ref}))))
        def reply_strips(self, spec):
            """One page of a thread's quote replies, grouped by the message they quote, in reply order."""
            return json.loads(_translate(lambda: self._client.vault_rooms_reply_strips(json.dumps(spec))))
        def claim(self, room_ref, turn_ref):
            """Claims one turn addressed to the caller for it to answer: claimed, held by another, or not addressed."""
            return json.loads(_translate(lambda: self._client.vault_rooms_claim(json.dumps({"room_ref": room_ref, "turn_ref": turn_ref}))))
        def speak(self, spec):
            """Speaks through the witness gate; on a new thread root, thread_audience explicitly limits readers to named room members, an audience later edited through vault.rooms.thread_audience.add and vault.rooms.thread_audience.remove."""
            return json.loads(_translate(lambda: self._client.vault_rooms_speak(json.dumps(spec))))
        @property
        def thread_audience(self) -> "Oneiron._VaultRoomsThreadAudienceVerbs":
            return Oneiron._VaultRoomsThreadAudienceVerbs(self._client)
        def private_threads(self, spec):
            """That a room's private threads exist: id, creator, created and last-active times, member count; never a name, members or words. The vault's Owner or an Admin, seated or not, or the companion agent of either may call it."""
            return json.loads(_translate(lambda: self._client.vault_rooms_private_threads(json.dumps(spec))))
        def thread_delete(self, spec):
            """Deletes a private thread's root and its own messages on the room's delete rail; legal holds keep what they name. The vault's Owner, or an Admin while rooms.private_threads.admin_delete is on, may call it, seated or not."""
            return json.loads(_translate(lambda: self._client.vault_rooms_thread_delete(json.dumps(spec))))
        @property
        def thread_join(self) -> "Oneiron._VaultRoomsThreadJoinVerbs":
            return Oneiron._VaultRoomsThreadJoinVerbs(self._client)
        def join(self, spec):
            """Files and decides a request to take part in a room or one of its threads."""
            return json.loads(_translate(lambda: self._client.vault_rooms_join(json.dumps(spec))))
        def invite(self, spec):
            """The vault's owner invites a person into an ordinary room: files her join with the owner's admission yes, which holds until she answers yes through vault.rooms.consent."""
            return json.loads(_translate(lambda: self._client.vault_rooms_invite(json.dumps(spec))))
        def consent(self, spec):
            """One party's answer to a join that waits on it, after which the join is decided again."""
            return json.loads(_translate(lambda: self._client.vault_rooms_consent(json.dumps(spec))))
        @property
        def offer(self) -> "Oneiron._VaultRoomsOfferVerbs":
            return Oneiron._VaultRoomsOfferVerbs(self._client)
        def offers(self, spec):
            """One page of the current offer cards in a room or one of its threads."""
            return json.loads(_translate(lambda: self._client.vault_rooms_offers(json.dumps(spec))))
        @property
        def host(self) -> "Oneiron._VaultRoomsHostVerbs":
            return Oneiron._VaultRoomsHostVerbs(self._client)
        def sharing(self, spec):
            """A room's effective sharing scope and why it is clamped, for a member of the room."""
            return json.loads(_translate(lambda: self._client.vault_rooms_sharing(json.dumps(spec))))
    class _VaultRoomsThreadAudienceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def add(self, spec):
            """Adds a room member to a private thread's audience, full or from_now. An Owner or Admin adding themselves walks in from now; an Admin adding from outside adds from now; the Owner adding from outside with full opens full history, members told."""
            return json.loads(_translate(lambda: self._client.vault_rooms_thread_audience_add(json.dumps(spec))))
        def open_full_history(self, spec):
            """Opens a private thread's whole history, turns before the caller's add included, to the vault's Owner inside its audience: a logged audience edit, every member told. The Owner alone may call it."""
            return json.loads(_translate(lambda: self._client.vault_rooms_thread_audience_open_full_history(json.dumps(spec))))
        def remove(self, spec):
            """Removes a person from a private thread's audience, ending every read of theirs there, its earlier turns too; its audience, the vault's Owner or an Admin may call it."""
            return json.loads(_translate(lambda: self._client.vault_rooms_thread_audience_remove(json.dumps(spec))))
    class _VaultRoomsThreadJoinVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def request(self, spec):
            """Asks to join a private thread by its exact root, for the caller itself; every member is asked, and a pending request is answered again. The vault's Owner or an Admin, as a person, or an agent may call it."""
            return json.loads(_translate(lambda: self._client.vault_rooms_thread_join_request(json.dumps(spec))))
        def requests(self, spec):
            """The requests to join a private thread pending now: each request, who asked and when; a member in its audience now may call it."""
            return json.loads(_translate(lambda: self._client.vault_rooms_thread_join_requests(json.dumps(spec))))
        def approve(self, spec):
            """Approves a pending request to join a private thread: the one who asked is added from now on, citing the request, and told; the first answer settles it and a later one answers how it settled. Any one member in its audience now may call it."""
            return json.loads(_translate(lambda: self._client.vault_rooms_thread_join_approve(json.dumps(spec))))
        def deny(self, spec):
            """Denies a pending request to join a private thread, and the one who asked is told; the first answer settles it and a later one answers how it settled. Any one member in its audience now may call it."""
            return json.loads(_translate(lambda: self._client.vault_rooms_thread_join_deny(json.dumps(spec))))
    class _VaultRoomsOfferVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Publishes an agent's offer card to join a room or one of its threads, with an optional fixed deadline for a room-wide card."""
            return json.loads(_translate(lambda: self._client.vault_rooms_offer(json.dumps(spec))))
        def answer(self, spec):
            """The room's host answers an offer card: join, or not now."""
            return json.loads(_translate(lambda: self._client.vault_rooms_offer_answer(json.dumps(spec))))
        def vote(self, spec):
            """Someone in the room casts an advisory join or not-now vote on an open room-wide offer card, which keeps it open; only the host's answer admits."""
            return json.loads(_translate(lambda: self._client.vault_rooms_offer_vote(json.dumps(spec))))
        def reopen(self, spec):
            """The room's owner or delegated host reopens its aged-out room-wide offer card."""
            return json.loads(_translate(lambda: self._client.vault_rooms_offer_reopen(json.dumps(spec))))
    class _VaultRoomsHostVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Who hosts a room now, and the caller's own speaking role there."""
            return json.loads(_translate(lambda: self._client.vault_rooms_host(json.dumps(spec))))
        def pin(self, spec):
            """Pins an agent as a room's host, or clears the stored host, pin or handoff."""
            return json.loads(_translate(lambda: self._client.vault_rooms_host_pin(json.dumps(spec))))
        def hand(self, spec):
            """The room's current host hands the hosting duty to another agent that may host."""
            return json.loads(_translate(lambda: self._client.vault_rooms_host_hand(json.dumps(spec))))
    class _VaultConversationsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def turn(self) -> "Oneiron._VaultConversationsTurnVerbs":
            return Oneiron._VaultConversationsTurnVerbs(self._client)
        def create(self, spec):
            """Creates a conversation; a body naming members also authors its membership ledger, creator and role grants as the caller."""
            return json.loads(_translate(lambda: self._client.vault_conversations_create(json.dumps(spec))))
        @property
        def turns(self) -> "Oneiron._VaultConversationsTurnsVerbs":
            return Oneiron._VaultConversationsTurnsVerbs(self._client)
        @property
        def records(self) -> "Oneiron._VaultConversationsRecordsVerbs":
            return Oneiron._VaultConversationsRecordsVerbs(self._client)
    class _VaultConversationsTurnVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def continue_(self, spec):
            """Queues generation that resumes an incomplete assistant reply from exactly its saved text."""
            return json.loads(_translate(lambda: self._client.vault_conversations_turn_continue(json.dumps(spec))))
        def retry(self, spec):
            """Queues a new answer to the user turn an assistant turn answered; the old reply stays."""
            return json.loads(_translate(lambda: self._client.vault_conversations_turn_retry(json.dumps(spec))))
    class _VaultConversationsTurnsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """Puts one TURN under a conversation, with its text index and checked ChildOf edge, in one batch; the host lands the turn once."""
            return json.loads(_translate(lambda: self._client.vault_conversations_turns_create(json.dumps(spec))))
    class _VaultConversationsRecordsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def append(self, spec):
            """Appends one TURN to a conversation's DAG, bylined the caller, with its topology in one transaction; the host lands the turn once."""
            return json.loads(_translate(lambda: self._client.vault_conversations_records_append(json.dumps(spec))))
    class _VaultModelsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def manifest(self) -> "Oneiron._VaultModelsManifestVerbs":
            return Oneiron._VaultModelsManifestVerbs(self._client)
        @property
        def oneironer(self) -> "Oneiron._VaultModelsOneironerVerbs":
            return Oneiron._VaultModelsOneironerVerbs(self._client)
        @property
        def routes(self) -> "Oneiron._VaultModelsRoutesVerbs":
            return Oneiron._VaultModelsRoutesVerbs(self._client)
        @property
        def roles(self) -> "Oneiron._VaultModelsRolesVerbs":
            return Oneiron._VaultModelsRolesVerbs(self._client)
        @property
        def catalog(self) -> "Oneiron._VaultModelsCatalogVerbs":
            return Oneiron._VaultModelsCatalogVerbs(self._client)
        @property
        def trials(self) -> "Oneiron._VaultModelsTrialsVerbs":
            return Oneiron._VaultModelsTrialsVerbs(self._client)
        @property
        def bindings(self) -> "Oneiron._VaultModelsBindingsVerbs":
            return Oneiron._VaultModelsBindingsVerbs(self._client)
    class _VaultModelsManifestVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, spec):
            """Reads the owner-pinned v2 model manifest, or none when no manifest is configured."""
            return json.loads(_translate(lambda: self._client.vault_models_manifest_read(json.dumps(spec))))
        def replace(self, spec):
            """Replaces the v2 model manifest under the owner proof, preserving the teacher-probe guard and atomically clearing resident route overrides."""
            return json.loads(_translate(lambda: self._client.vault_models_manifest_replace(json.dumps(spec))))
    class _VaultModelsOneironerVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def bind(self, spec):
            """Binds the Oneironer this server has loaded as the on-device extraction_encoder in the current v2 model manifest under the owner proof, keeping every other binding and clearing resident route overrides."""
            return json.loads(_translate(lambda: self._client.vault_models_oneironer_bind(json.dumps(spec))))
    class _VaultModelsRoutesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, spec):
            """Reads one independent model slot route with its manifest pin and effective resident narrowing."""
            return json.loads(_translate(lambda: self._client.vault_models_routes_read(json.dumps(spec))))
        def replace(self, spec):
            """Replaces one model slot route within its manifest pin without changing any other slot or role binding."""
            return json.loads(_translate(lambda: self._client.vault_models_routes_replace(json.dumps(spec))))
    class _VaultModelsRolesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, spec):
            """Reads one resolved role binding with its revision-pinned model, slot, route, provider and registered catalog fingerprint; grants no execution authority."""
            return json.loads(_translate(lambda: self._client.vault_models_roles_read(json.dumps(spec))))
        def invoke(self, spec):
            """Invokes a pinned model role through the configured generative, retrieval-embedder or extraction-encoder door and returns its typed output and resolved-model receipt."""
            return json.loads(_translate(lambda: self._client.vault_models_roles_invoke(json.dumps(spec))))
    class _VaultModelsCatalogVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def refresh(self, spec):
            """Refreshes priced model catalog rows and external-score diffs under an immutable revision; changes no role binding."""
            return json.loads(_translate(lambda: self._client.vault_models_catalog_refresh(json.dumps(spec))))
        def get(self, spec):
            """Reads a pinned model catalog revision with its prices, backend offers and score evidence."""
            return json.loads(_translate(lambda: self._client.vault_models_catalog_get(json.dumps(spec))))
        def diff(self, spec):
            """Diffs two immutable model catalog revisions, including prices, scores and retired offers."""
            return json.loads(_translate(lambda: self._client.vault_models_catalog_diff(json.dumps(spec))))
    class _VaultModelsTrialsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def nominate(self, spec):
            """Nominates a question-specific held-out trial at a catalog revision using the caller own labels; external scores grant no authority."""
            return json.loads(_translate(lambda: self._client.vault_models_trials_nominate(json.dumps(spec))))
        def get(self, spec):
            """Reads a retained held-out trial, its catalog revision, independent labels and measured cost."""
            return json.loads(_translate(lambda: self._client.vault_models_trials_get(json.dumps(spec))))
        def approve(self, spec):
            """Approves exploration for a held-out model trial only; leaves its role binding unchanged."""
            return json.loads(_translate(lambda: self._client.vault_models_trials_approve(json.dumps(spec))))
        def run(self, spec):
            """Runs both pinned backend arms through decide and normal inference leases on the original held-out source frontier; records real usage and cost."""
            return json.loads(_translate(lambda: self._client.vault_models_trials_run(json.dumps(spec))))
        def complete(self, spec):
            """Completes a measured model trial with a sufficiency card bound to its exact set and measurements; only produces an offer."""
            return json.loads(_translate(lambda: self._client.vault_models_trials_complete(json.dumps(spec))))
    class _VaultModelsBindingsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def propose(self, spec):
            """Proposes a role model change from a sufficient held-out trial, retaining catalog revision and real trial cost without activating it."""
            return json.loads(_translate(lambda: self._client.vault_models_bindings_propose(json.dumps(spec))))
        def get(self, spec):
            """Reads an owner-reviewed model role-binding proposal and its pinned trial evidence."""
            return json.loads(_translate(lambda: self._client.vault_models_bindings_get(json.dumps(spec))))
        def read(self, spec):
            """Reads the currently active manifest binding for a model role."""
            return json.loads(_translate(lambda: self._client.vault_models_bindings_read(json.dumps(spec))))
        def accept(self, spec):
            """Accepts a pending model role-binding proposal as the owner after transaction-local incumbent, catalog and trial checks."""
            return json.loads(_translate(lambda: self._client.vault_models_bindings_accept(json.dumps(spec))))
        def deny(self, spec):
            """Denies a pending model role-binding proposal as the owner without changing the incumbent manifest binding."""
            return json.loads(_translate(lambda: self._client.vault_models_bindings_deny(json.dumps(spec))))
    class _VaultVoicesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def packs(self) -> "Oneiron._VaultVoicesPacksVerbs":
            return Oneiron._VaultVoicesPacksVerbs(self._client)
        def render_consent(self, spec):
            """The owner records their render decision on their own voice: a grant names the farthest locality its refs may reach; a withdrawal drops each target clone, deleted at its vendor best effort, and keeps the packs."""
            return json.loads(_translate(lambda: self._client.vault_voices_render_consent(json.dumps(spec))))
        @property
        def targets(self) -> "Oneiron._VaultVoicesTargetsVerbs":
            return Oneiron._VaultVoicesTargetsVerbs(self._client)
        def inspect(self, spec):
            """The owner inspects their own voice as the bank holds it for one configured hosted target: identity, pack metadata without audio or transcripts, the current render decision and the target's current clone."""
            return json.loads(_translate(lambda: self._client.vault_voices_inspect(json.dumps(spec))))
    class _VaultVoicesPacksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            """The owner banks one immutable reference pack of their own voice: the first captured or designed pack makes its identity, a captured pack cites their current render grant, and a retry of the same pack is a no-op."""
            return json.loads(_translate(lambda: self._client.vault_voices_packs_put(json.dumps(spec))))
    class _VaultVoicesTargetsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def provision(self, spec):
            """The owner's own voice cloned at a configured hosted target from its banked refs, or that target's current clone. The render consent must reach the target's locality before any provider call."""
            return json.loads(_translate(lambda: self._client.vault_voices_targets_provision(json.dumps(spec))))
        def evict(self, spec):
            """The owner drops a target's clone of their own voice, deleted at its vendor best effort. The identity and its packs stay."""
            return json.loads(_translate(lambda: self._client.vault_voices_targets_evict(json.dumps(spec))))
    class _VaultGraphVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def ask(self, spec):
            return json.loads(_translate(lambda: self._client.vault_graph_ask(json.dumps(spec))))
        def admit(self, spec):
            """Admits the caller's own provider measurement for one graph unit in place of the host ladder's, validating the whole decision and its provider-bound paired readings before landing it as a proposed claim private to the caller."""
            return json.loads(_translate(lambda: self._client.vault_graph_admit(json.dumps(spec))))
    class _VaultQuestionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            return json.loads(_translate(lambda: self._client.vault_questions_create(json.dumps(spec))))
        def edit(self, spec):
            return json.loads(_translate(lambda: self._client.vault_questions_edit(json.dumps(spec))))
        def pause(self, spec):
            return json.loads(_translate(lambda: self._client.vault_questions_pause(json.dumps(spec))))
        def backfill(self, spec):
            return json.loads(_translate(lambda: self._client.vault_questions_backfill(json.dumps(spec))))
        def read(self, spec):
            return json.loads(_translate(lambda: self._client.vault_questions_read(json.dumps(spec))))
        def answers(self, spec):
            return json.loads(_translate(lambda: self._client.vault_questions_answers(json.dumps(spec))))
        def refresh(self, spec):
            """Refreshes the caller's standing question by hand, now, over every unit or artifact its current version covers, on the host's ladder as the standing pump answers it."""
            return json.loads(_translate(lambda: self._client.vault_questions_refresh(json.dumps(spec))))
        @property
        def outcomes(self) -> "Oneiron._VaultQuestionsOutcomesVerbs":
            return Oneiron._VaultQuestionsOutcomesVerbs(self._client)
        def schedule(self, spec):
            """Reads the caller's standing question scheduling head: its current version, paused state, last refresh and any failed-refresh hold."""
            return json.loads(_translate(lambda: self._client.vault_questions_schedule(json.dumps(spec))))
    class _VaultQuestionsOutcomesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Reads the caller's standing question outcome labels and calibration pairs, each pairing an answer prediction and probability with its mapped label."""
            return json.loads(_translate(lambda: self._client.vault_questions_outcomes(json.dumps(spec))))
        def project(self, spec):
            """Projects the caller's standing question bound outcomes over current facts, idempotently binding each admissible fact in an answer horizon as its label."""
            return json.loads(_translate(lambda: self._client.vault_questions_outcomes_project(json.dumps(spec))))
    class _VaultDecisionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def bands(self) -> "Oneiron._VaultDecisionsBandsVerbs":
            return Oneiron._VaultDecisionsBandsVerbs(self._client)
        @property
        def asks(self) -> "Oneiron._VaultDecisionsAsksVerbs":
            return Oneiron._VaultDecisionsAsksVerbs(self._client)
    class _VaultDecisionsBandsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, spec):
            """The owner reads a question version's effective band on the running host; an unlearned row stays shadow at the supplied seed and version zero."""
            return json.loads(_translate(lambda: self._client.vault_decisions_bands_read(json.dumps(spec))))
        def learn(self, spec):
            """The owner declares a question version's learned band in shadow mode on the running host, advancing its band version for that reversibility."""
            return json.loads(_translate(lambda: self._client.vault_decisions_bands_learn(json.dumps(spec))))
        def enforce(self, spec):
            """The owner enforces an already learned question-version and reversibility band on the running host without widening any decision dial or authority."""
            return json.loads(_translate(lambda: self._client.vault_decisions_bands_enforce(json.dumps(spec))))
    class _VaultDecisionsAsksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def answer(self, spec):
            return json.loads(_translate(lambda: self._client.vault_decisions_asks_answer(json.dumps(spec))))
        def climb(self, spec):
            return json.loads(_translate(lambda: self._client.vault_decisions_asks_climb(json.dumps(spec))))
    class _VaultBookingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def availability(self, spec):
            """Lists ranked public slots on a live published booking page as the caller, through the shared booking admission and solver without exposing busy sources."""
            return json.loads(_translate(lambda: self._client.vault_booking_availability(json.dumps(spec))))
        def book(self, spec):
            """Holds or confirms a real slot on a live published booking page as the caller, through the shared admission and home-node lifecycle with opaque session-bound tokens."""
            return json.loads(_translate(lambda: self._client.vault_booking_book(json.dumps(spec))))
        def reschedule(self, spec):
            """Moves a booking on a live published page using its reschedule token, preserving EVENT and UID and replaying without another passport revision."""
            return json.loads(_translate(lambda: self._client.vault_booking_reschedule(json.dumps(spec))))
        def cancel(self, spec):
            """Cancels a booking on a live published page using its cancel token, preserving EVENT and UID and replaying without another passport revision."""
            return json.loads(_translate(lambda: self._client.vault_booking_cancel(json.dumps(spec))))
        def constraint_turn(self, spec):
            """Parses one scheduling constraint on a live published booking page as the caller, returning public slot controls, an email continuation or a deflect; this never holds or confirms a booking."""
            return json.loads(_translate(lambda: self._client.vault_booking_constraint_turn(json.dumps(spec))))
        def page_token(self, spec):
            """The owner discovers the opaque token for an existing configured booking page; this does not publish the page or grant booking authority."""
            return json.loads(_translate(lambda: self._client.vault_booking_page_token(json.dumps(spec))))
    class _VaultCalendarVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def passports(self) -> "Oneiron._VaultCalendarPassportsVerbs":
            return Oneiron._VaultCalendarPassportsVerbs(self._client)
        def create(self, spec):
            """Creates a native or evidence-linked dreamer EVENT as the caller, with atomic projector-recorded origin and engine-stamped recorded time."""
            return json.loads(_translate(lambda: self._client.vault_calendar_create(json.dumps(spec))))
        @property
        def ics(self) -> "Oneiron._VaultCalendarIcsVerbs":
            return Oneiron._VaultCalendarIcsVerbs(self._client)
        def occurrences(self, spec):
            """Expands an admitted stored master inside an inclusive UTC window under the caller's read scope, preserving UID and original-start identities and masking detached exceptions."""
            return json.loads(_translate(lambda: self._client.vault_calendar_occurrences(json.dumps(spec))))
        @property
        def instances(self) -> "Oneiron._VaultCalendarInstancesVerbs":
            return Oneiron._VaultCalendarInstancesVerbs(self._client)
        def read(self, spec):
            """Reads one calendar EVENT under the caller's scoped read, with its mandatory narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_calendar_read(json.dumps(spec))))
        def search(self, spec):
            """Searches calendar EVENTs by calendar, inclusive UTC range and name under the caller's scoped read, with its mandatory narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_calendar_search(json.dumps(spec))))
        def freebusy(self, spec):
            """Projects source-redacted busy occupancy over an inclusive UTC range under the caller's scoped read, as half-open intervals with a mandatory narrowing receipt."""
            return json.loads(_translate(lambda: self._client.vault_calendar_freebusy(json.dumps(spec))))
        def prep(self, spec):
            """Builds a fresh caller-scoped meeting PrepPack with commitments first and a 250-word ceiling, or deliberately returns no pack."""
            return json.loads(_translate(lambda: self._client.vault_calendar_prep(json.dumps(spec))))
        def event_outcome(self, spec):
            """Reads the caller-visible meeting outcome and its recorded basis; silence projects to unknown and never to held or no_show."""
            return json.loads(_translate(lambda: self._client.vault_calendar_event_outcome(json.dumps(spec))))
        @property
        def check_in(self) -> "Oneiron._VaultCalendarCheckInVerbs":
            return Oneiron._VaultCalendarCheckInVerbs(self._client)
        @property
        def outcome_policy(self) -> "Oneiron._VaultCalendarOutcomePolicyVerbs":
            return Oneiron._VaultCalendarOutcomePolicyVerbs(self._client)
        @property
        def transcript(self) -> "Oneiron._VaultCalendarTranscriptVerbs":
            return Oneiron._VaultCalendarTranscriptVerbs(self._client)
    class _VaultCalendarPassportsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, spec):
            """Reads the admitted passport head for one EVENT, system and UID through the caller scoped-read gate, including sequence, semantic hash, direction and presence."""
            return json.loads(_translate(lambda: self._client.vault_calendar_passports_read(json.dumps(spec))))
        def history(self, spec):
            """Reads recorded passport revisions oldest first for one EVENT, system and UID, retaining explicit approval and lifecycle under the caller recorded-read gate."""
            return json.loads(_translate(lambda: self._client.vault_calendar_passports_history(json.dumps(spec))))
    class _VaultCalendarIcsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def import_(self, spec):
            """The owner imports one exact uploaded ICS version through the existing UID diff and imported-claim gate; the receipt exposes pending claim refs without granting consent."""
            return json.loads(_translate(lambda: self._client.vault_calendar_ics_import(json.dumps(spec))))
    class _VaultCalendarInstancesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def move(self, spec):
            """The owner applies one uploaded detached-instance amendment matching its UID, original start and new interval, through the import gate without changing other instances."""
            return json.loads(_translate(lambda: self._client.vault_calendar_instances_move(json.dumps(spec))))
    class _VaultCalendarCheckInVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def due(self, spec):
            """Observes whether a meeting check-in is due under owner proof, live evidence and the engine clock, without advancing time or recording an outcome."""
            return json.loads(_translate(lambda: self._client.vault_calendar_check_in_due(json.dumps(spec))))
        def answer(self, spec):
            """The owner answers a due check-in as held, no_show or rescheduled; the caller cannot assert machine evidence or replace it."""
            return json.loads(_translate(lambda: self._client.vault_calendar_check_in_answer(json.dumps(spec))))
    class _VaultCalendarOutcomePolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """Reads the owner-configured post-meeting grace policy, including the default 1800 seconds when no override exists."""
            return json.loads(_translate(lambda: self._client.vault_calendar_outcome_policy_get(json.dumps({} if spec is None else spec))))
        def set(self, spec):
            """Sets the post-meeting grace in real seconds under owner proof, without changing event times or minting attendance evidence."""
            return json.loads(_translate(lambda: self._client.vault_calendar_outcome_policy_set(json.dumps(spec))))
    class _VaultCalendarTranscriptVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def ingest(self, spec):
            """Ingests verified uploaded UTF-8 transcript bytes as a closed SESSION with ordered TURNs; an optional meeting link earns a machine outcome through the caller gate."""
            return json.loads(_translate(lambda: self._client.vault_calendar_transcript_ingest(json.dumps(spec))))
    class _VaultWritesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def critical_confirm(self) -> "Oneiron._VaultWritesCriticalConfirmVerbs":
            return Oneiron._VaultWritesCriticalConfirmVerbs(self._client)
        def pending(self, input: dict[str, Any]) -> Any:
            """Gated writes parked for consent, newest first."""
            return json.loads(_translate(lambda: self._client.vault_writes_pending(json.dumps(input, allow_nan=False))))
    class _VaultWritesCriticalConfirmVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def pending(self, spec):
            """The owner reads a candidate's exact critical confirmation, with its nonce, effect digest, policy frontier and deadline."""
            return json.loads(_translate(lambda: self._client.vault_writes_critical_confirm_pending(json.dumps(spec))))
        def clear(self, spec):
            """The owner clears exactly the nonce and frontier-bound critical claim confirmation and receives its fold-verified signed receipt."""
            return json.loads(_translate(lambda: self._client.vault_writes_critical_confirm_clear(json.dumps(spec))))
        def decline(self, spec):
            """The owner declines exactly the nonce and frontier-bound critical claim confirmation and receives its fold-verified signed receipt."""
            return json.loads(_translate(lambda: self._client.vault_writes_critical_confirm_decline(json.dumps(spec))))
        def receipt(self, spec):
            """The owner reads a critical confirmation's existing signed authority receipt without settling or rewriting the claim."""
            return json.loads(_translate(lambda: self._client.vault_writes_critical_confirm_receipt(json.dumps(spec))))
    class _VaultRefsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def resolve(self, spec):
            """The bounded preview of one record ref, read through the caller's own scope; unreadable and missing look the same."""
            return json.loads(_translate(lambda: self._client.vault_refs_resolve(json.dumps(spec))))
        def links(self, spec):
            """A text, the texts a read surface returned, or a turn's readable messages, as typed spans whose record links resolve under the caller's own read."""
            return json.loads(_translate(lambda: self._client.vault_refs_links(json.dumps(spec))))
    class _VaultVectorsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            """Supplies one full-width vector for a readable record as the authenticated owner; the existing write gate checks model, transform, width, revision staging and graph updates atomically."""
            return json.loads(_translate(lambda: self._client.vault_vectors_put(json.dumps(spec))))
    class _VaultStructuralVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, input: dict[str, Any]) -> Any:
            """Puts one structural record with its text-index fields and outgoing edges, in one atomic batch; claims go through commit."""
            return json.loads(_translate(lambda: self._client.vault_structural_put(json.dumps(input, allow_nan=False))))
    class _VaultHabitsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def checkin(self, input: dict[str, Any]) -> Any:
            """Appends one immutable check-in under a Habit TASK."""
            return json.loads(_translate(lambda: self._client.vault_habits_checkin(json.dumps(input, allow_nan=False))))
    class _VaultProductivityVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """Creates one inert Goal, Milestone or Habit TASK under an optional checked parent; an illegal nesting refuses the whole write."""
            return json.loads(_translate(lambda: self._client.vault_productivity_create(json.dumps(spec))))
        def tree(self, spec):
            """The role-labelled TASK tree under one root, read through the caller's lane, with each Habit's derived streak counters."""
            return json.loads(_translate(lambda: self._client.vault_productivity_tree(json.dumps(spec))))
    class _VaultEsignVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """Drafts a signing document on PDF artifacts the caller already holds, as the caller; sending it is its own gated act."""
            return json.loads(_translate(lambda: self._client.vault_esign_create(json.dumps(spec))))
        def get(self, spec):
            """Reads one signing document as its trail folds: its status, recipients, filled fields and its hash-chained audit trail, with its delivery receipts. A trail that does not read answers trail unreadable with its error, its receipts still listed."""
            return json.loads(_translate(lambda: self._client.vault_esign_get(json.dumps(spec))))
        @property
        def links(self) -> "Oneiron._VaultEsignLinksVerbs":
            return Oneiron._VaultEsignLinksVerbs(self._client)
        def send_for_signature(self, spec):
            """Sends a drafted signing document to its recipients through the outbound gate, as the caller; an agent sends only within its principal envelope."""
            return json.loads(_translate(lambda: self._client.vault_esign_send_for_signature(json.dumps(spec))))
        @property
        def notices(self) -> "Oneiron._VaultEsignNoticesVerbs":
            return Oneiron._VaultEsignNoticesVerbs(self._client)
        def remind(self, spec):
            """Reminds the recipients whose turn it is to sign a pending document, through the outbound gate, as the caller."""
            return json.loads(_translate(lambda: self._client.vault_esign_remind(json.dumps(spec))))
        def void(self, spec):
            """Withdraws a drafted or pending signing document unsealed and tells its recipients why, through the outbound gate, as the caller."""
            return json.loads(_translate(lambda: self._client.vault_esign_void(json.dumps(spec))))
        @property
        def signing(self) -> "Oneiron._VaultEsignSigningVerbs":
            return Oneiron._VaultEsignSigningVerbs(self._client)
        @property
        def seal(self) -> "Oneiron._VaultEsignSealVerbs":
            return Oneiron._VaultEsignSealVerbs(self._client)
    class _VaultEsignLinksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def issue(self, spec):
            """The vault owner mints the signing links of a drafted document and receives each new one once, to deliver to its recipient."""
            return json.loads(_translate(lambda: self._client.vault_esign_links_issue(json.dumps(spec))))
    class _VaultEsignNoticesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def dispatch(self, spec):
            """Dispatches the due transition notices of one signing document recorded for the caller through the email send gate, as the caller."""
            return json.loads(_translate(lambda: self._client.vault_esign_notices_dispatch(json.dumps(spec))))
    class _VaultEsignSigningVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def act(self, spec):
            """One recipient ceremony act under the signing capability in the body: load the page, save a field, complete with consent, or reject; an agent caller makes Complete an automated sign act."""
            return json.loads(_translate(lambda: self._client.vault_esign_signing_act(json.dumps(spec))))
        def pdf(self, spec):
            """One ceremony item under its signing capability, as base64 PDF bytes: the pinned original while signing, the hash-checked sealed output after sealing."""
            return json.loads(_translate(lambda: self._client.vault_esign_signing_pdf(json.dumps(spec))))
        def image(self, spec):
            """Stores one signature image bound to the signing capability recipient and answers the ref a signature field value names."""
            return json.loads(_translate(lambda: self._client.vault_esign_signing_image(json.dumps(spec))))
        def signature(self, spec):
            """Reads back one stored signature image under the signing capability that uploaded it, as base64 bytes."""
            return json.loads(_translate(lambda: self._client.vault_esign_signing_signature(json.dumps(spec))))
    class _VaultEsignSealVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Where one signing document seal task stands: its folded status, every seal attempt receipt, its sealed manifest once sealed, and its delivery receipts. A trail that does not read answers trail unreadable with its error."""
            return json.loads(_translate(lambda: self._client.vault_esign_seal_get(json.dumps(spec))))
    class _VaultConsolidationVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def enqueue(self, spec):
            """Enqueues one consolidation attempt and returns its durable job reference."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_enqueue(json.dumps(spec))))
        def status(self, spec):
            """Reads the status of one consolidation attempt by its durable job reference."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_status(json.dumps(spec))))
        @property
        def wake(self) -> "Oneiron._VaultConsolidationWakeVerbs":
            return Oneiron._VaultConsolidationWakeVerbs(self._client)
        @property
        def home(self) -> "Oneiron._VaultConsolidationHomeVerbs":
            return Oneiron._VaultConsolidationHomeVerbs(self._client)
        def lineage(self, spec):
            """The owner reads one consolidation job's retry chain back to its root and a page of its committed step refs, without resuming, leasing or calling a model."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_lineage(json.dumps(spec))))
        def promote(self, spec):
            """Promotes typed generated candidates in an admitted Dreamer attempt through its host-stamped writer and checker, returning retained evidence and refusals."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_promote(json.dumps(spec))))
        def pin(self, spec):
            """Pins reference-only evidence for six-axis consolidation buckets at one owner-scoped ledger revision. Hashes, lineage taint and source eligibility are derived by the root, never accepted from children."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_pin(json.dumps(spec))))
        def frontier(self, spec):
            """Records immutable child judgements and reference sets against an existing root pin, in any completion order, and accounts source-plus-hash corroboration without merging projects. Does not settle claims."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_frontier(json.dumps(spec))))
        def accounting(self, spec):
            """Reads the original root revision, source hashes, ancestor and edge provenance taint, zero-signal exclusions and per-bucket corroboration accounting under current owner read authority."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_accounting(json.dumps(spec))))
        def evidence(self, spec):
            """Reads exact generated-claim evidence, source lineage and separate consolidation, corroboration and effector-evidence eligibility as the owner."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_evidence(json.dumps(spec))))
    class _VaultConsolidationWakeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def status(self, spec):
            """Reads one page of a consolidation wake pass observation by attempt or wake reference: its clock and ceiling, admitted attempts, each model call with its lease, the Checkpoint parks it cut and the pass as it runs now."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_wake_status(json.dumps(spec))))
    class _VaultConsolidationHomeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec=None):
            """The owner reads the elected MACRO home this node's runner holds, the host's last candidate set it elected over, his home pick and this install's own sync client id, without electing, minting or waking anything."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_home_get(json.dumps({} if spec is None else spec))))
        def pick(self, spec):
            """The owner picks or clears the node that runs his vault's MACRO consolidation: a signed act every linked machine folds, recorded even for a node unknown here; a stale seen revision refuses. It re-elects this home and moves no job or lease."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_home_pick(json.dumps(spec))))
    class _VaultSieveVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def evidence(self) -> "Oneiron._VaultSieveEvidenceVerbs":
            return Oneiron._VaultSieveEvidenceVerbs(self._client)
        def cadence(self, spec):
            """Read the shared Dreamer/Coach wake policy, the production scheduler cadence receipt and pending recipe evidence ranges; do not tick, enqueue or call a model."""
            return json.loads(_translate(lambda: self._client.vault_sieve_cadence(json.dumps(spec))))
        @property
        def settlements(self) -> "Oneiron._VaultSieveSettlementsVerbs":
            return Oneiron._VaultSieveSettlementsVerbs(self._client)
        def queue(self, spec):
            """The owner reads one ordered page of the sieve interest queue: span handles, source and range refs, kind, score and the rungs still owed."""
            return json.loads(_translate(lambda: self._client.vault_sieve_queue(json.dumps(spec))))
        def retained(self, spec):
            """The owner reads the sieve retained original span readings, which spending never removes, for a later weave over evidence."""
            return json.loads(_translate(lambda: self._client.vault_sieve_retained(json.dumps(spec))))
        def receipts(self, spec):
            """The owner reads consumed-span receipts: each span nightly spending consumed once, its source ref and the attempt that spent it."""
            return json.loads(_translate(lambda: self._client.vault_sieve_receipts(json.dumps(spec))))
        @property
        def policy(self) -> "Oneiron._VaultSievePolicyVerbs":
            return Oneiron._VaultSievePolicyVerbs(self._client)
        @property
        def recipe_policy(self) -> "Oneiron._VaultSieveRecipePolicyVerbs":
            return Oneiron._VaultSieveRecipePolicyVerbs(self._client)
        @property
        def lease(self) -> "Oneiron._VaultSieveLeaseVerbs":
            return Oneiron._VaultSieveLeaseVerbs(self._client)
    class _VaultSieveEvidenceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Read the original TURN identity, sieve reading digest, evidence cursor and owed/continuing state as the owner."""
            return json.loads(_translate(lambda: self._client.vault_sieve_evidence(json.dumps(spec))))
        def replay(self, spec):
            """Replay the same stored TURN through its owed sieve read under the owner proof; preserve every ingress identity and let the existing digest check decide whether evidence changed."""
            return json.loads(_translate(lambda: self._client.vault_sieve_evidence_replay(json.dumps(spec))))
    class _VaultSieveSettlementsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Page shared-scheduler root receipts and all Dreamer/Coach descendants, including exact conclusion identities, authority receipts, terminal states and durable parks."""
            return json.loads(_translate(lambda: self._client.vault_sieve_settlements(json.dumps(spec))))
        def get(self, spec):
            """Read one shared-scheduler root and its complete descendant settlement; a completed dispatcher never implies its children completed."""
            return json.loads(_translate(lambda: self._client.vault_sieve_settlements_get(json.dumps(spec))))
    class _VaultSievePolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads the sieve policy row: how much one pass reads, each kind interest, rule confidences and the uncertain band."""
            return json.loads(_translate(lambda: self._client.vault_sieve_policy(json.dumps(spec))))
        def set(self, spec):
            """The owner replaces the sieve policy row; the new row scores spans read after it and queued spans keep the score they were given."""
            return json.loads(_translate(lambda: self._client.vault_sieve_policy_set(json.dumps(spec))))
    class _VaultSieveRecipePolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads the wake recipe policy row: per-receipt span and child budgets, rung retry and the sampled audit settings."""
            return json.loads(_translate(lambda: self._client.vault_sieve_recipe_policy(json.dumps(spec))))
        def set(self, spec):
            """The owner replaces the wake recipe policy row; unspent interest stays queued and only later receipts spend under the new budgets."""
            return json.loads(_translate(lambda: self._client.vault_sieve_recipe_policy_set(json.dumps(spec))))
    class _VaultSieveLeaseVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The owner reads one wake-budget lease counter without creating it: total, remaining and reserved units by its budget id."""
            return json.loads(_translate(lambda: self._client.vault_sieve_lease(json.dumps(spec))))
        def refill(self, spec):
            """The owner refills one wake-budget lease to a replacement total; spent and reserved units keep their claim and replay adds nothing twice."""
            return json.loads(_translate(lambda: self._client.vault_sieve_lease_refill(json.dumps(spec))))
    class _VaultFreeTimeVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def policy(self) -> "Oneiron._VaultFreeTimePolicyVerbs":
            return Oneiron._VaultFreeTimePolicyVerbs(self._client)
        def cycles(self, spec):
            """The owner reads one agent's free-time cycles a page at a time, newest first: each cycle's state, period and floor from its item receipts, with the cursor of the next page."""
            return json.loads(_translate(lambda: self._client.vault_free_time_cycles(json.dumps(spec))))
        def cycle(self, spec):
            """The owner reads one free-time cycle: its state, the floor and whether every item receipt read, the agent's short note, each item's receipt, and the spend records by label with their own completeness. Never the agent's diary."""
            return json.loads(_translate(lambda: self._client.vault_free_time_cycle(json.dumps(spec))))
    class _VaultFreeTimePolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """The owner reads one agent's free-time policy with its revision: the total one cycle may spend, its daily clock in an IANA zone and any pinned split, or disabled when none is set."""
            return json.loads(_translate(lambda: self._client.vault_free_time_policy_get(json.dumps(spec))))
        def set(self, spec):
            """The owner sets one agent's free-time policy at the revision it read, or clears it with no policy; a clear ends the open cycle and the agent goes back to its nightly dreaming."""
            return json.loads(_translate(lambda: self._client.vault_free_time_policy_set(json.dumps(spec))))
    class _VaultMemoryVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def signal_extraction(self) -> "Oneiron._VaultMemorySignalExtractionVerbs":
            return Oneiron._VaultMemorySignalExtractionVerbs(self._client)
    class _VaultMemorySignalExtractionVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Queues typed extraction of witnessed turns on the configured production Dreamer role; returns durable partition job refs, never caller-authored candidates."""
            return json.loads(_translate(lambda: self._client.vault_memory_signal_extraction(json.dumps(spec))))
        def result(self, spec):
            """Reads extraction completion, accepted claims, generated prospective queries and parent-verified source ranges and MESSAGE revisions as the owner may read them."""
            return json.loads(_translate(lambda: self._client.vault_memory_signal_extraction_result(json.dumps(spec))))
    class _VaultChannelIdentitiesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def provision(self, spec):
            """Provision an engine-held channel address, handle or shared presence through the existing lifecycle gate."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_provision(json.dumps(spec))))
        def bind(self, spec):
            """Bind a requested identity or an existing delegated account with transaction-verified custody."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_bind(json.dumps(spec))))
        def fulfill(self, spec):
            """Record owner-confirmed fulfillment of a pending channel identity; delegated custody is revalidated."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_fulfill(json.dumps(spec))))
        def rotate(self, spec):
            """Rotate an engine-held channel identity through its lifecycle gate; delegated accounts cannot rotate."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_rotate(json.dumps(spec))))
        def release(self, spec):
            """Release a channel identity through its lifecycle gate, retaining engine-held addresses under the never-recycle rule."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_release(json.dumps(spec))))
        def route_inbound(self, spec):
            """Read and receipt the gated inbound routing disposition of a channel identity, including retirement holds."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_route_inbound(json.dumps(spec))))
        def get(self, spec):
            """Read live channel identity facts, custody, lifecycle and outbound capability without granting permission to send."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_get(json.dumps(spec))))
        @property
        def selection(self) -> "Oneiron._VaultChannelIdentitiesSelectionVerbs":
            return Oneiron._VaultChannelIdentitiesSelectionVerbs(self._client)
        def select(self, spec):
            """Select a live channel identity under relationship rules, retaining an existing thread passport mask."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_select(json.dumps(spec))))
        @property
        def passports(self) -> "Oneiron._VaultChannelIdentitiesPassportsVerbs":
            return Oneiron._VaultChannelIdentitiesPassportsVerbs(self._client)
    class _VaultChannelIdentitiesSelectionVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def rules(self, spec):
            """Read the compiled relationship selection law and authenticated writer provenance."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_selection_rules(json.dumps(spec))))
        def update(self, spec):
            """Amend relationship selection rules at an expected revision as the authenticated owner or an authorized agent writer."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_selection_update(json.dumps(spec))))
    class _VaultChannelIdentitiesPassportsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """Read one receiving identity and Message-ID passport through the caller credential."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_passports_get(json.dumps(spec))))
        def list(self, spec):
            """Read canonical thread passports and the sticky identity, actor and facet mask."""
            return json.loads(_translate(lambda: self._client.vault_channel_identities_passports_list(json.dumps(spec))))
    class _VaultDeliveryWindowVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def policy(self) -> "Oneiron._VaultDeliveryWindowPolicyVerbs":
            return Oneiron._VaultDeliveryWindowPolicyVerbs(self._client)
        def evaluate(self, spec):
            """Preview live delivery-window policy with the engine evaluator; the preview does not authorize or release an effect."""
            return json.loads(_translate(lambda: self._client.vault_delivery_window_evaluate(json.dumps(spec))))
    class _VaultDeliveryWindowPolicyVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            """The owner writes one typed interrupt-only delivery-window policy through the gated claim writer."""
            return json.loads(_translate(lambda: self._client.vault_delivery_window_policy_put(json.dumps(spec))))
        def list(self, spec):
            """Read typed delivery-window policy rows with approval, source, lifecycle and validity provenance."""
            return json.loads(_translate(lambda: self._client.vault_delivery_window_policy_list(json.dumps(spec))))
        def retract(self, spec):
            """The owner retracts a delivery-window policy through the existing claim lifecycle door."""
            return json.loads(_translate(lambda: self._client.vault_delivery_window_policy_retract(json.dumps(spec))))
    class _VaultSummariesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, request):
            """Declares a readable source scope; only the configured Dreamer writes and source-links the SUMMARY birth."""
            return json.loads(_translate(lambda: self._client.vault_summaries_create(json.dumps(request))))
        def read(self, request):
            """Reads SUMMARY text, keep, derivation, covers and stable edit anchors in one caller-scoped snapshot."""
            return json.loads(_translate(lambda: self._client.vault_summaries_read(json.dumps(request))))
        def status(self, request):
            """Reads the calling principal's own summary declaration and its retained completion or failure."""
            return json.loads(_translate(lambda: self._client.vault_summaries_status(json.dumps(request))))
        def keep(self, request):
            """Edits the SUMMARY keep memo at the exact frontier read, under the caller's owner proof or entity-bound text grant."""
            return json.loads(_translate(lambda: self._client.vault_summaries_keep(json.dumps(request))))
        def edit(self, request):
            """Applies attributed anchored SUMMARY edits through existing grants; ungranted edits remain a typed review proposal."""
            return json.loads(_translate(lambda: self._client.vault_summaries_edit(json.dumps(request))))
        def patch(self, request):
            """Applies generated anchored SUMMARY operations after a keep fence and source admission; durable receipts name the sources read."""
            return json.loads(_translate(lambda: self._client.vault_summaries_patch(json.dumps(request))))
        def regenerate(self, request):
            """Retains generated SUMMARY text as a source-linked rewrite fork after reading keep; no head moves without explicit switch."""
            return json.loads(_translate(lambda: self._client.vault_summaries_regenerate(json.dumps(request))))
        @property
        def proposals(self) -> "Oneiron._VaultSummariesProposalsVerbs":
            return Oneiron._VaultSummariesProposalsVerbs(self._client)
    class _VaultSummariesProposalsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, request):
            """Reads a SUMMARY proposal's fork provenance, retained text and durable receipts only when every member is readable."""
            return json.loads(_translate(lambda: self._client.vault_summaries_proposals_read(json.dumps(request))))
        def merge(self, request):
            """Merges the complete SUMMARY proposal under existing entity grants, preserving concurrent head edits and durable receipts."""
            return json.loads(_translate(lambda: self._client.vault_summaries_proposals_merge(json.dumps(request))))
        def switch(self, request):
            """Explicitly switches the complete SUMMARY proposal under existing entity grants; a stale causal base refuses the entire set."""
            return json.loads(_translate(lambda: self._client.vault_summaries_proposals_switch(json.dumps(request))))
        def reject(self, request):
            """Rejects the complete SUMMARY proposal under existing entity grants, dropping pending fork text without moving live heads."""
            return json.loads(_translate(lambda: self._client.vault_summaries_proposals_reject(json.dumps(request))))
    class _VaultNotesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def bless_brief_kind(self, input: dict[str, Any]) -> Any:
            """A verified person stamps the brief kind policy seed; it grants no sharing or extraction authority."""
            return json.loads(_translate(lambda: self._client.vault_notes_bless_brief_kind(json.dumps(input, allow_nan=False))))
        def author_brief(self, input: dict[str, Any]) -> Any:
            """Authors markdown with supporting claim citations, capturing source NOTE pins and rechecking their live read authority in the brief write transaction."""
            return json.loads(_translate(lambda: self._client.vault_notes_author_brief(json.dumps(input, allow_nan=False))))
        def follow_citation(self, spec):
            """Follows returned share and claim references under the caller live read scope; revocation stops resolution and hidden citations disclose no quote or lifecycle."""
            return json.loads(_translate(lambda: self._client.vault_notes_follow_citation(json.dumps(spec))))
        def create(self, input: dict[str, Any]) -> Any:
            """Creates a NOTE of a registered kind, its first authored text as its birth."""
            return json.loads(_translate(lambda: self._client.vault_notes_create(json.dumps(input, allow_nan=False))))
        def author_take(self, input: dict[str, Any]) -> Any:
            """Appends an opinion/take NOTE about a subject or claim, attributed to the bound caller without changing the target."""
            return json.loads(_translate(lambda: self._client.vault_notes_author_take(json.dumps(input, allow_nan=False))))
        def from_entity(self, input: dict[str, Any]) -> Any:
            """Creates a NOTE of a registered kind from an existing entity."""
            return json.loads(_translate(lambda: self._client.vault_notes_from_entity(json.dumps(input, allow_nan=False))))
        def read(self, input: dict[str, Any]) -> Any:
            """Reads live NOTE text or one retained NoteVersion, acquiring stable edit anchors in the same scoped snapshot."""
            return json.loads(_translate(lambda: self._client.vault_notes_read(json.dumps(input, allow_nan=False))))
        def history(self, input: dict[str, Any]) -> Any:
            """Reads authenticated NOTE operation identities and actors with the retained history boundary; hidden or purged history is never invented."""
            return json.loads(_translate(lambda: self._client.vault_notes_history(json.dumps(input, allow_nan=False))))
        def fork(self, input: dict[str, Any]) -> Any:
            """Forks one NOTE at the exact live-head version the caller read, retaining its edits or rewrite without moving the live head."""
            return json.loads(_translate(lambda: self._client.vault_notes_fork(json.dumps(input, allow_nan=False))))
        @property
        def forks(self) -> "Oneiron._VaultNotesForksVerbs":
            return Oneiron._VaultNotesForksVerbs(self._client)
        @property
        def proposals(self) -> "Oneiron._VaultNotesProposalsVerbs":
            return Oneiron._VaultNotesProposalsVerbs(self._client)
        def version_tree(self, input: dict[str, Any]) -> Any:
            """Reads NOTE birth, current version, fork parent and frontier links, proposal membership, verdicts and durable head-move receipts."""
            return json.loads(_translate(lambda: self._client.vault_notes_version_tree(json.dumps(input, allow_nan=False))))
        def history_purge(self, spec):
            """The owner explicitly erases a NOTE's safe history, or opens its shared-vault erase veto window; no grant names this action."""
            return json.loads(_translate(lambda: self._client.vault_notes_history_purge(json.dumps(spec))))
        def history_purge_execute(self, spec):
            """Executes the exact history erase this owner started after its veto window closes without objection; retries return its durable receipt."""
            return json.loads(_translate(lambda: self._client.vault_notes_history_purge_execute(json.dumps(spec))))
        def history_purge_receipts(self, spec):
            """The owner reads a NOTE's durable history-purge receipts, including each requested and retained causal frontier."""
            return json.loads(_translate(lambda: self._client.vault_notes_history_purge_receipts(json.dumps(spec))))
        @property
        def editor(self) -> "Oneiron._VaultNotesEditorVerbs":
            return Oneiron._VaultNotesEditorVerbs(self._client)
        def edit(self, input: dict[str, Any]) -> Any:
            """Edits one NOTE in a transaction-local document; a rejected edit leaves nothing pending."""
            return json.loads(_translate(lambda: self._client.vault_notes_edit(json.dumps(input, allow_nan=False))))
        def seal(self, request: dict[str, Any]) -> dict[str, Any]:
            """Seals one NOTE: its document freezes, and a later edit opens a fork."""
            return json.loads(_translate(lambda: self._client.vault_notes_seal(json.dumps(request, allow_nan=False))))
        def lifecycle(self, request: dict[str, Any]) -> dict[str, Any]:
            """Where one NOTE stands (active, sealed, archived or tombstoned) and its seal."""
            return json.loads(_translate(lambda: self._client.vault_notes_lifecycle(json.dumps(request, allow_nan=False))))
        def set_overrides(self, request: dict[str, Any]) -> dict[str, Any]:
            """Sets the defaults one NOTE overrides over its kind's; empty overrides clear them."""
            return json.loads(_translate(lambda: self._client.vault_notes_set_overrides(json.dumps(request, allow_nan=False))))
        def defaults(self, request: dict[str, Any]) -> dict[str, Any]:
            """One NOTE's overrides and the defaults its gates read after them."""
            return json.loads(_translate(lambda: self._client.vault_notes_defaults(json.dumps(request, allow_nan=False))))
    class _VaultNotesForksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def read(self, input: dict[str, Any]) -> Any:
            """Reads a NOTE fork and its retained pending text through the same scoped, reason-logged read as the live NOTE."""
            return json.loads(_translate(lambda: self._client.vault_notes_forks_read(json.dumps(input, allow_nan=False))))
    class _VaultNotesProposalsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def open(self, input: dict[str, Any]) -> Any:
            """Opens one explicit set of NOTE forks with its shared explainer; the engine routes each member under the caller's own existing grants."""
            return json.loads(_translate(lambda: self._client.vault_notes_proposals_open(json.dumps(input, allow_nan=False))))
        def read(self, input: dict[str, Any]) -> Any:
            """Reads an entire NOTE proposal set, its pending fork text, explainer and head-move receipts only when every member is readable."""
            return json.loads(_translate(lambda: self._client.vault_notes_proposals_read(json.dumps(input, allow_nan=False))))
        def merge(self, input: dict[str, Any]) -> Any:
            """Accepts the complete NOTE proposal set by merge under the caller's existing NOTE grants, retaining concurrent head edits and durable receipts."""
            return json.loads(_translate(lambda: self._client.vault_notes_proposals_merge(json.dumps(input, allow_nan=False))))
        def switch(self, input: dict[str, Any]) -> Any:
            """Accepts the complete NOTE proposal set by explicit switch under the caller's existing NOTE grants, recording every head move."""
            return json.loads(_translate(lambda: self._client.vault_notes_proposals_switch(json.dumps(input, allow_nan=False))))
        def reject(self, input: dict[str, Any]) -> Any:
            """Rejects the complete NOTE proposal set under the caller's existing NOTE grants, dropping pending text without changing live heads."""
            return json.loads(_translate(lambda: self._client.vault_notes_proposals_reject(json.dumps(input, allow_nan=False))))
    class _VaultNotesEditorVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def bind(self, spec):
            """Binds a live NOTE editor to the caller and returns its typed text and base version; close the binding when the editor leaves."""
            return json.loads(_translate(lambda: self._client.vault_notes_editor_bind(json.dumps(spec))))
        def close(self, spec):
            """Closes one live NOTE editor held by this caller; a binding id alone grants no authority."""
            return json.loads(_translate(lambda: self._client.vault_notes_editor_close(json.dumps(spec))))
    class _FeedbackVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def preview(self, spec):
            """The owner previews the exact feedback bundle one report issue would send to its publisher: its subject, digest, destination and approval."""
            return json.loads(_translate(lambda: self._client.feedback_preview(json.dumps(spec))))
        def send(self, spec):
            """The owner sends exactly the previewed feedback bundle for one report issue to its publisher, once, through the ordinary outbound gate."""
            return json.loads(_translate(lambda: self._client.feedback_send(json.dumps(spec))))
    class _SelfVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def focus(self) -> "Oneiron._SelfFocusVerbs":
            return Oneiron._SelfFocusVerbs(self._client)
        @property
        def memory(self) -> "Oneiron._SelfMemoryVerbs":
            return Oneiron._SelfMemoryVerbs(self._client)
        @property
        def standing(self) -> "Oneiron._SelfStandingVerbs":
            return Oneiron._SelfStandingVerbs(self._client)
        @property
        def identity(self) -> "Oneiron._SelfIdentityVerbs":
            return Oneiron._SelfIdentityVerbs(self._client)
        @property
        def inbox(self) -> "Oneiron._SelfInboxVerbs":
            return Oneiron._SelfInboxVerbs(self._client)
        def message(self, spec):
            """Sends one message to a person in the Direct room the caller's person and theirs share, making the room on first use."""
            return json.loads(_translate(lambda: self._client.self_message(json.dumps(spec))))
        @property
        def grants(self) -> "Oneiron._SelfGrantsVerbs":
            return Oneiron._SelfGrantsVerbs(self._client)
        @property
        def budget(self) -> "Oneiron._SelfBudgetVerbs":
            return Oneiron._SelfBudgetVerbs(self._client)
        @property
        def credential(self) -> "Oneiron._SelfCredentialVerbs":
            return Oneiron._SelfCredentialVerbs(self._client)
        @property
        def admission(self) -> "Oneiron._SelfAdmissionVerbs":
            return Oneiron._SelfAdmissionVerbs(self._client)
        @property
        def saved_query(self) -> "Oneiron._SelfSavedQueryVerbs":
            return Oneiron._SelfSavedQueryVerbs(self._client)
        @property
        def off_record(self) -> "Oneiron._SelfOffRecordVerbs":
            return Oneiron._SelfOffRecordVerbs(self._client)
        @property
        def consent(self) -> "Oneiron._SelfConsentVerbs":
            return Oneiron._SelfConsentVerbs(self._client)
        def use(self, spec):
            """Hands a secret to one trusted operation by its handle, under the owner's binding; answers what the operation got back, never the value."""
            return json.loads(_translate(lambda: self._client.self_use(json.dumps(spec))))
        @property
        def secrets(self) -> "Oneiron._SelfSecretsVerbs":
            return Oneiron._SelfSecretsVerbs(self._client)
        @property
        def skills(self) -> "Oneiron._SelfSkillsVerbs":
            return Oneiron._SelfSkillsVerbs(self._client)
        @property
        def decisions(self) -> "Oneiron._SelfDecisionsVerbs":
            return Oneiron._SelfDecisionsVerbs(self._client)
        @property
        def run(self) -> "Oneiron._SelfRunVerbs":
            return Oneiron._SelfRunVerbs(self._client)
        @property
        def folds(self) -> "Oneiron._SelfFoldsVerbs":
            return Oneiron._SelfFoldsVerbs(self._client)
        def history(self, spec):
            """Reads checkpointed raw steps and landed fold and epoch boundaries of the attached run; a cleared ask alone never proves compaction settled."""
            return json.loads(_translate(lambda: self._client.self_history(json.dumps(spec))))
        @property
        def browser(self) -> "Oneiron._SelfBrowserVerbs":
            return Oneiron._SelfBrowserVerbs(self._client)
        def fold(self, spec):
            """Marks a span of the attached run as pending; compaction leaves its raw steps untouched until a batch lands."""
            return json.loads(_translate(lambda: self._client.self_fold(json.dumps(spec))))
        def compact(self, spec):
            """Asks the attached run to fold its pending marks in one batch at its next step boundary; read self.history for landed folds and epochs."""
            return json.loads(_translate(lambda: self._client.self_compact(json.dumps(spec))))
        def unfold(self, spec):
            """Appends a fold of the attached run after its current tail, without replacing the earlier stub."""
            return json.loads(_translate(lambda: self._client.self_unfold(json.dumps(spec))))
        def report_blocked(self, spec):
            """Files this credential's attached agent run's own blocked report: a closed category and its detail as the fenced, untrusted leaf of a witnessed receipt for the Coach's Issues job; it grants nothing and completes no task."""
            return json.loads(_translate(lambda: self._client.self_report_blocked(json.dumps(spec))))
        @property
        def agents(self) -> "Oneiron._SelfAgentsVerbs":
            return Oneiron._SelfAgentsVerbs(self._client)
        @property
        def leader(self) -> "Oneiron._SelfLeaderVerbs":
            return Oneiron._SelfLeaderVerbs(self._client)
    class _SelfFocusVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def wakes(self, spec):
            """Takes every wake queued for the attached run's board STREAM connection, each re-read under this credential at delivery."""
            return json.loads(_translate(lambda: self._client.self_focus_wakes(json.dumps(spec))))
        @property
        def scratchpad(self) -> "Oneiron._SelfFocusScratchpadVerbs":
            return Oneiron._SelfFocusScratchpadVerbs(self._client)
        def refresh(self, spec):
            """Re-renders the attached run's context board as one STREAM frame, at the frame epoch the caller last saw."""
            return json.loads(_translate(lambda: self._client.self_focus_refresh(json.dumps(spec))))
        def subscribe(self, spec):
            """Subscribes the attached run's board STREAM connection to the named scopes, inside its credential ceiling."""
            return json.loads(_translate(lambda: self._client.self_focus_subscribe(json.dumps(spec))))
        def unsubscribe(self, spec):
            """Unsubscribes the attached run's board STREAM connection from the named scopes."""
            return json.loads(_translate(lambda: self._client.self_focus_unsubscribe(json.dumps(spec))))
    class _SelfFocusScratchpadVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def recall(self, spec):
            """Searches the bound actor's whole session scratchpad, live or sealed, for the lines holding every query word, folded lines in full."""
            return json.loads(_translate(lambda: self._client.self_focus_scratchpad_recall(json.dumps(spec))))
        def append(self, spec):
            """Appends one line, with an optional keep or scratch mark and pin, to the bound actor's session scratchpad; the session's first line opens the pad, and a sealed pad is refused."""
            return json.loads(_translate(lambda: self._client.self_focus_scratchpad_append(json.dumps(spec))))
        def seal(self, spec):
            """Seals the bound actor's session scratchpad, ending the run's pad; a session with no pad answers no pad."""
            return json.loads(_translate(lambda: self._client.self_focus_scratchpad_seal(json.dumps(spec))))
    class _SelfMemoryVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def diary(self) -> "Oneiron._SelfMemoryDiaryVerbs":
            return Oneiron._SelfMemoryDiaryVerbs(self._client)
    class _SelfMemoryDiaryVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Writes one private entry in the bound actor's own diary, as an actor-private NOTE."""
            return json.loads(_translate(lambda: self._client.self_memory_diary(json.dumps(spec))))
        def reads(self, spec):
            """This agent's diary read log: who read its diary and why, newest first, and the reasons its review holds."""
            return json.loads(_translate(lambda: self._client.self_memory_diary_reads(json.dumps(spec))))
        def review(self, spec):
            """This agent's yes or no to a reader's reason for reading its diary; only the diary's own agent answers."""
            return json.loads(_translate(lambda: self._client.self_memory_diary_review(json.dumps(spec))))
        def query(self, spec):
            """Reads an agent's diary under the caller's diary.read grants, stating a reason the agent sees in its read log."""
            return json.loads(_translate(lambda: self._client.self_memory_diary_query(json.dumps(spec))))
    class _SelfStandingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """This agent's configured standing block in one world: its handle, name and token floor."""
            return json.loads(_translate(lambda: self._client.self_standing_get(json.dumps(spec))))
        def list(self, spec=None):
            """Every standing block configured for this agent, one per world, in world order."""
            return json.loads(_translate(lambda: self._client.self_standing_list(json.dumps({} if spec is None else spec))))
        def edit(self, spec):
            """This agent proposes one persona field's new text for its standing block, as a Generated claim its gate settles; compiled text is never edited."""
            return json.loads(_translate(lambda: self._client.self_standing_edit(json.dumps(spec))))
    class _SelfIdentityVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def answer(self, spec):
            """The owner answers an identity choice with supporting evidence refs; the original mention and verified owner resolution provenance are retained atomically."""
            return json.loads(_translate(lambda: self._client.self_identity_answer(json.dumps(spec))))
        def settle(self, spec):
            """Before acting on a person known only by a name, settles who that name is from its newest saved mention, or opens an ask."""
            return json.loads(_translate(lambda: self._client.self_identity_settle(json.dumps(spec))))
    class _SelfInboxVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec):
            """Lists one page of notifications delivered to the bound actor, without marking them."""
            return json.loads(_translate(lambda: self._client.self_inbox_list(json.dumps(spec))))
        def mark(self, spec):
            """Marks one delivered notification seen or acknowledged for the bound actor."""
            return json.loads(_translate(lambda: self._client.self_inbox_mark(json.dumps(spec))))
        @property
        def concern(self) -> "Oneiron._SelfInboxConcernVerbs":
            return Oneiron._SelfInboxConcernVerbs(self._client)
        def lens(self, spec):
            """Reads the bound actor's own identity inbox slice in impact order, with optional identity filtering and concern groups; not a delivered-notification page."""
            return json.loads(_translate(lambda: self._client.self_inbox_lens(json.dumps(spec))))
    class _SelfInboxConcernVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            return json.loads(_translate(lambda: self._client.self_inbox_concern(json.dumps(spec))))
        def outcome(self, spec):
            return json.loads(_translate(lambda: self._client.self_inbox_concern_outcome(json.dumps(spec))))
        def move(self, spec):
            return json.loads(_translate(lambda: self._client.self_inbox_concern_move(json.dumps(spec))))
    class _SelfGrantsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def ask(self, spec):
            """Asks a person for access on the caller's behalf; the request grants nothing until the vault owner approves it."""
            return json.loads(_translate(lambda: self._client.self_grants_ask(json.dumps(spec))))
    class _SelfBudgetVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """The caller's own dispatched attempt: its persisted spend allowance, landing reserve, checkpoint and saved hold, without substituting a token meter for money."""
            return json.loads(_translate(lambda: self._client.self_budget(json.dumps(spec))))
        def land(self, spec):
            """The worker parks its own dispatched attempt at its budget hold with its lease fence and exact checkpoint; the same run keeps its partial results and resumes later."""
            return json.loads(_translate(lambda: self._client.self_budget_land(json.dumps(spec))))
    class _SelfCredentialVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def attenuate(self, spec):
            """Appends a holder-signed caveat to the caller's own slip, optionally transferring it to a recipient public key. Existing caveats and live parent authority remain binding; no actor or grant is minted."""
            return json.loads(_translate(lambda: self._client.self_credential_attenuate(json.dumps(spec))))
    class _SelfAdmissionVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def status(self, spec):
            """Reads the durable queued, held or terminal receipt of one typed call under its invocation id, as its own actor; never submits or replays work."""
            return json.loads(_translate(lambda: self._client.self_admission_status(json.dumps(spec))))
        def receipts(self, spec):
            """Reconciles an exact authored set of invocation ids against the caller actor durable admission receipts in one snapshot, without duplicate outcomes or replay."""
            return json.loads(_translate(lambda: self._client.self_admission_receipts(json.dumps(spec))))
    class _SelfSavedQueryVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """Creates a saved query (scope, stage-1 filter, stage-2 matcher and evaluation policy) owned by the caller."""
            return json.loads(_translate(lambda: self._client.self_saved_query_create(json.dumps(spec))))
        def read(self, spec):
            """One saved query the caller owns; a query absent or not the caller's reads as not found."""
            return json.loads(_translate(lambda: self._client.self_saved_query_read(json.dumps(spec))))
        def update(self, spec):
            """Replaces a saved query's scope, filter, matcher and evaluation policy whole under a definition-version check."""
            return json.loads(_translate(lambda: self._client.self_saved_query_update(json.dumps(spec))))
        def archive(self, spec):
            """Archives a saved query under a definition-version check: it stays readable and is never evaluated again."""
            return json.loads(_translate(lambda: self._client.self_saved_query_archive(json.dumps(spec))))
        def members(self, spec):
            """One cursor-bounded page of the membership this saved query derived, entered and exited causes preserved."""
            return json.loads(_translate(lambda: self._client.self_saved_query_members(json.dumps(spec))))
        def evaluate(self, spec):
            """Evaluates a saved query the caller owns now, bounded by its per-wake caps, with one verdict and memo receipt per visited entity."""
            return json.loads(_translate(lambda: self._client.self_saved_query_evaluate(json.dumps(spec))))
    class _SelfOffRecordVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def execute(self, spec):
            """The session's creator or the vault's owner runs one entry of a durable code-mode run bound to an off-record session; its rows and spilled outputs stay in the room until close."""
            return json.loads(_translate(lambda: self._client.self_off_record_execute(json.dumps(spec))))
    class _SelfConsentVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def graduation(self) -> "Oneiron._SelfConsentGraduationVerbs":
            return Oneiron._SelfConsentGraduationVerbs(self._client)
    class _SelfConsentGraduationVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def demote(self, spec):
            """The bound actor transparently gives up only its own ramp scope authority, with the existing durable demotion receipt."""
            return json.loads(_translate(lambda: self._client.self_consent_graduation_demote(json.dumps(spec))))
    class _SelfSecretsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def materialize(self, spec):
            """Mints a value-free grant on a secret for this credential's attached run, to one purpose: an operation or connector (door), a host destination (leased) or a declared file (local); the answer never holds the value."""
            return json.loads(_translate(lambda: self._client.self_secrets_materialize(json.dumps(spec))))
        def renew(self, spec):
            """Renews a grant the attached run holds: a fresh grant at the secret's current generation in its place, never a longer life for bytes already handed out."""
            return json.loads(_translate(lambda: self._client.self_secrets_renew(json.dumps(spec))))
        def teardown(self, spec):
            """Tears down a grant the attached run holds, whatever its state: revokes it and its lease, removes its file or clears its destination, and says what the cleanup found."""
            return json.loads(_translate(lambda: self._client.self_secrets_teardown(json.dumps(spec))))
        def use(self, spec):
            """Hands the secret a door grant redeems to one trusted operation or connector call, for the attached run; a grant minted before a rotation refuses until renewed, and the answer never holds the value."""
            return json.loads(_translate(lambda: self._client.self_secrets_use(json.dumps(spec))))
    class _SelfSkillsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def save(self, spec):
            """An agent saves a skill it wrote, SKILL.md and scripts together; it lands as a proposed candidate and nothing activates it."""
            return json.loads(_translate(lambda: self._client.self_skills_save(json.dumps(spec))))
        def fork(self, spec):
            """An agent forks a stored skill under its own identity, keeping its import ancestry."""
            return json.loads(_translate(lambda: self._client.self_skills_fork(json.dumps(spec))))
        def callables(self, spec=None):
            """Every loadable callable helper skill and its call contract: what it takes and returns."""
            return json.loads(_translate(lambda: self._client.self_skills_callables(json.dumps({} if spec is None else spec))))
        def call(self, spec):
            """Runs a callable skill on this credential's attached leased run with its existing sandbox and gates; the result follows the stored return contract, while anchored outcomes settle separately."""
            return json.loads(_translate(lambda: self._client.self_skills_call(json.dumps(spec))))
    class _SelfDecisionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def asks(self, spec=None):
            return json.loads(_translate(lambda: self._client.self_decisions_asks(json.dumps({} if spec is None else spec))))
    class _SelfRunVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def attach(self, spec):
            """Attaches the caller's own credential to its leased live run and returns the handle required by the public fold and history calls."""
            return json.loads(_translate(lambda: self._client.self_run_attach(json.dumps(spec))))
    class _SelfFoldsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Lists the attached run's landed folds, pending marks and outstanding compact ask."""
            return json.loads(_translate(lambda: self._client.self_folds(json.dumps(spec))))
        def describe(self, spec):
            """Reads one pending mark or landed fold of the attached run, with its Generated stub, source ids and retained result handles."""
            return json.loads(_translate(lambda: self._client.self_folds_describe(json.dumps(spec))))
    class _SelfBrowserVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def open(self, spec):
            """Opens a URL in the attached run's own browser session and observes the page whole, each row with its live ref and its locator; a long page's observation comes in pages, read on with observe and its next cursor."""
            return json.loads(_translate(lambda: self._client.self_browser_open(json.dumps(spec))))
        def observe(self, spec):
            """Observes the attached run's browser page as an ordered edit of the base it names or the caller's last whole read, else whole (or whole with full), in pages read on with observe and next; acts follow new tabs and name the move as switched."""
            return json.loads(_translate(lambda: self._client.self_browser_observe(json.dumps(spec))))
        def find(self, spec):
            """Finds the page rows whose role and name match, each with its live ref and its locator, in pages: an answer with next goes on, and find with that cursor reads the next page."""
            return json.loads(_translate(lambda: self._client.self_browser_find(json.dumps(spec))))
        def click(self, spec):
            """Clicks one page target by live ref or locator and observes the result as an edit of the caller's base; a ref whose node is gone acts on its locator's row as rebound; a long observation comes in pages, read on with observe and next."""
            return json.loads(_translate(lambda: self._client.self_browser_click(json.dumps(spec))))
        def click_at(self, spec):
            """Clicks a point of a held screenshot, mapped onto the viewport, and observes the result as an ordered edit of the caller's base; a long page's observation comes in pages, read on with observe and its next cursor."""
            return json.loads(_translate(lambda: self._client.self_browser_click_at(json.dumps(spec))))
        def type(self, spec):
            """Types text into one page target by live ref or locator and observes the result as an edit of the caller's base; a ref whose node is gone acts on its locator's row as rebound; a long observation comes in pages, read on with observe and next."""
            return json.loads(_translate(lambda: self._client.self_browser_type(json.dumps(spec))))
        def select(self, spec):
            """Picks the option of a select element by live ref or locator, by its label, text or value, and observes the result as an edit of the caller's base; a long observation comes in pages, read on with observe and its next cursor."""
            return json.loads(_translate(lambda: self._client.self_browser_select(json.dumps(spec))))
        def wait_for(self, spec):
            """Waits until a page row its live refs or locators name, or else a row matching a role and name, is there; a ref whose node is gone matches its locator's row, listed in rebindings; many rows come in pages, read on with find and next."""
            return json.loads(_translate(lambda: self._client.self_browser_wait_for(json.dumps(spec))))
        def expect(self, spec):
            """Checks that a page row, by live ref or locator, is present or absent, and holds a given value; a ref whose node is gone is checked on its locator's row and listed in rebindings."""
            return json.loads(_translate(lambda: self._client.self_browser_expect(json.dumps(spec))))
        def screenshot(self, spec):
            """Takes a screenshot the session holds, by image ref and never captioned, under its own capture_id; with since_capture, unchanged_from names that earlier capture when this one is the same masked PNG taken in the same scope."""
            return json.loads(_translate(lambda: self._client.self_browser_screenshot(json.dumps(spec))))
        def view(self, spec):
            """Reads back a held image by its ref."""
            return json.loads(_translate(lambda: self._client.self_browser_view(json.dumps(spec))))
        def crop(self, spec):
            """Crops a held image to a rectangle."""
            return json.loads(_translate(lambda: self._client.self_browser_crop(json.dumps(spec))))
        def zoom(self, spec):
            """Zooms into a rectangle of a held image."""
            return json.loads(_translate(lambda: self._client.self_browser_zoom(json.dumps(spec))))
        def batch(self, spec):
            """Runs one batched program of one or more browser steps for a subgoal, stopping at the first failing step; its last observation edits the caller's base, rebindings list refs resolved by locator, and next pages a long one."""
            return json.loads(_translate(lambda: self._client.self_browser_batch(json.dumps(spec))))
        @property
        def library(self) -> "Oneiron._SelfBrowserLibraryVerbs":
            return Oneiron._SelfBrowserLibraryVerbs(self._client)
        def handover(self, spec):
            """Asks a person to take the browser over, saying why (to sign in or pay inside the same page); until they hand it back, every browser verb refuses browser_taken_over, and the answer after carries the takeover's record."""
            return json.loads(_translate(lambda: self._client.self_browser_handover(json.dumps(spec))))
        def switch_engine(self, spec):
            """Moves the run browser to the other engine (lightpanda or chromium) when a page does not work on this one, as after a click_no_effect fact; carries the URL, cookies, storage and scroll, and records the switch. Nothing switches by itself."""
            return json.loads(_translate(lambda: self._client.self_browser_switch_engine(json.dumps(spec))))
    class _SelfBrowserLibraryVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def find(self, spec):
            """The replay library's programs for a site, or for the attached run's open page's site."""
            return json.loads(_translate(lambda: self._client.self_browser_library_find(json.dumps(spec))))
        def propose(self, spec):
            """Offers a solved run's program to the replay library of the attached run's browser session, its live refs stored as their locators; it joins only once a no-model replay meets its postcondition."""
            return json.loads(_translate(lambda: self._client.self_browser_library_propose(json.dumps(spec))))
        def retire(self, spec):
            """Takes a program out of the replay library of the attached run's browser session for every later run, and returns the card it had."""
            return json.loads(_translate(lambda: self._client.self_browser_library_retire(json.dumps(spec))))
        def retired(self, spec):
            """The programs retires took out of the replay library for a site, or for the attached run's open page's site, the newest first, each with when and why."""
            return json.loads(_translate(lambda: self._client.self_browser_library_retired(json.dumps(spec))))
        def run(self, spec):
            """Runs a replay library program live with its arguments in the attached run's browser session, resolving locators step by step; its last observation edits the caller's base, and a missed postcondition goes back to the planner."""
            return json.loads(_translate(lambda: self._client.self_browser_library_run(json.dumps(spec))))
    class _SelfAgentsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def spawn(self, spec):
            """Spawns a child under the leased parent attached to this credential; spec states the need, work and narrowing, never the parent identity."""
            return json.loads(_translate(lambda: self._client.self_agents_spawn(json.dumps(spec))))
    class _SelfLeaderVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def split(self, spec):
            """Splits the attached leader run into a subproject inside its own TASK wrapper; spec may name only the child leader and a narrower scope."""
            return json.loads(_translate(lambda: self._client.self_leader_split(json.dumps(spec))))
    class _TasksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """Mints one TASK and its realizing attempt when the actor's ceiling permits, or parks it as a proposal; an intent key with a typed brief posts it through the task highway."""
            return json.loads(_translate(lambda: self._client.tasks_create(json.dumps(spec))))
        def wave(self, spec):
            """Cuts an epic TASK into a wave of TASKs through a planner agent, as one planning attempt: under the asking run's own lease, or the owner's root wave."""
            return json.loads(_translate(lambda: self._client.tasks_wave(json.dumps(spec))))
        def update(self, spec):
            """Reports task progress, blocked work or a durable result through the task highway; without a report, acknowledges a failed TASK."""
            return json.loads(_translate(lambda: self._client.tasks_update(json.dumps(spec))))
        def accept(self, spec):
            """Accepts one TASK addressed to the caller through the task highway under the caller's intent key; the attempt handle it answers fences the caller's reports."""
            return json.loads(_translate(lambda: self._client.tasks_accept(json.dumps(spec))))
        def answer(self, handle, word):
            """Admits one person's word on an ask; the word is evidence, never approval."""
            return json.loads(_translate(lambda: self._client.tasks_answer(json.dumps({"handle": handle, "word": word}))))
        def outcomes(self, handle):
            """Owner-scoped calibration pairs for an ask: each prediction against the outcome it was bound to."""
            return json.loads(_translate(lambda: self._client.tasks_outcomes(json.dumps(handle))))
        def refuse(self, spec):
            """Applies this credential's attached agent run refusal dial to its own TASK, with a durable reason; the live lease supplies the actor and TASK and the engine owns replay."""
            return json.loads(_translate(lambda: self._client.tasks_refuse(json.dumps(spec))))
    class _AiVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def chat(self) -> "Oneiron._AiChatVerbs":
            return Oneiron._AiChatVerbs(self._client)
        @property
        def steps(self) -> "Oneiron._AiStepsVerbs":
            return Oneiron._AiStepsVerbs(self._client)
        @property
        def streams(self) -> "Oneiron._AiStreamsVerbs":
            return Oneiron._AiStreamsVerbs(self._client)
        def reply(self, spec):
            """Generate one context-bearing reply from the caller's scoped conversation, standing prefix and reader profile through an exact configured model; return durable emit-context receipt refs."""
            return json.loads(_translate(lambda: self._client.ai_reply(json.dumps(spec))))
        @property
        def voice(self) -> "Oneiron._AiVoiceVerbs":
            return Oneiron._AiVoiceVerbs(self._client)
        def anonymous_chat(self, spec):
            """One standalone memory-free turn on the house configuration or a plain model, with ephemeral policy notices; use the HTTP SDK, not a recorded MCP or code-mode call."""
            return json.loads(_translate(lambda: self._client.ai_anonymous_chat(json.dumps(spec))))
        def options(self, spec):
            """The model rows the caller could call now: where each runs, what it takes, its price and rates, and what its meter has left."""
            return json.loads(_translate(lambda: self._client.ai_options(json.dumps(spec))))
        def image(self, spec):
            """One image out of the host's image model; reference images make it an edit."""
            return json.loads(_translate(lambda: self._client.ai_image(json.dumps(spec))))
        def speech(self, spec):
            """Speech audio out of text, from the host's speech model."""
            return json.loads(_translate(lambda: self._client.ai_speech(json.dumps(spec))))
        def transcribe(self, spec):
            """Text out of speech audio, from the host's transcription model."""
            return json.loads(_translate(lambda: self._client.ai_transcribe(json.dumps(spec))))
        def embed(self, spec):
            """One embedding vector per input text, from the host's embedding model."""
            return json.loads(_translate(lambda: self._client.ai_embed(json.dumps(spec))))
        @property
        def video(self) -> "Oneiron._AiVideoVerbs":
            return Oneiron._AiVideoVerbs(self._client)
        def verdict(self, spec):
            """The caller's own typed question through the host's decision ladder: yes or no, one of its options, a score in the caller's range, or a box or point in an image, answered with a probability and a decision receipt."""
            return json.loads(_translate(lambda: self._client.ai_verdict(json.dumps(spec))))
    class _AiChatVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def completions(self, spec):
            """Recalls scoped memory, injects it as data, forwards a buffered OpenAI chat call and proposes the exchange under the paired connector's own ceiling."""
            return json.loads(_translate(lambda: self._client.ai_chat_completions(json.dumps(spec))))
    class _AiStepsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def submit(self, spec):
            """Submit or resume one owner-bound durable model step with declared transport attempts, deterministic fallback and a schema-validated JSON result."""
            return json.loads(_translate(lambda: self._client.ai_steps_submit(json.dumps(spec))))
        def receipt(self, spec):
            """Read the owner-bound model-step checkpoints and persisted terminal result without calling a model or spending another lease."""
            return json.loads(_translate(lambda: self._client.ai_steps_receipt(json.dumps(spec))))
    class _AiStreamsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def open(self, spec):
            """Open one owner-bound shared model stream under a stable key: a single admitted producer starts (or the standing stream answers), and a replay never starts a second one."""
            return json.loads(_translate(lambda: self._client.ai_streams_open(json.dumps(spec))))
        def subscribe(self, spec):
            """Attach before or after open to the caller's shared model stream, without starting a producer; replay every typed part event from the first under an independently detachable handle."""
            return json.loads(_translate(lambda: self._client.ai_streams_subscribe(json.dumps(spec))))
        def events(self, spec):
            """Drain one subscription's queued typed LlmStreamEvents (part-correlated text, reasoning, tool and image deltas, then Done) without blocking; closed once the producer ended and the queue is empty."""
            return json.loads(_translate(lambda: self._client.ai_streams_events(json.dumps(spec))))
        def detach(self, spec):
            """Detach only this subscription from the shared model stream; the producer and every other subscriber continue."""
            return json.loads(_translate(lambda: self._client.ai_streams_detach(json.dumps(spec))))
        def abort(self, spec):
            """Abort the caller's shared model stream with actual usage: subscribers receive the cancelled Done of the parts completed so far, recorded as the one durable terminal."""
            return json.loads(_translate(lambda: self._client.ai_streams_abort(json.dumps(spec))))
        def terminal(self, spec):
            """Read the one durable terminal of the caller's model stream by key (its ordered ContentParts, usage and finish reason, or its recorded failure) after any restart, without calling a model."""
            return json.loads(_translate(lambda: self._client.ai_streams_terminal(json.dumps(spec))))
    class _AiVoiceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def asr(self) -> "Oneiron._AiVoiceAsrVerbs":
            return Oneiron._AiVoiceAsrVerbs(self._client)
        def start(self, spec):
            """Opens an owner-bound live media session on the configured voice routes, using the caller credential, room audience and existing budget gates."""
            return json.loads(_translate(lambda: self._client.ai_voice_start(json.dumps(spec))))
        def audio(self, spec):
            """Feeds one utterance of PCM16LE with client VAD to the live voice host; sustained speech retires old output through the shared cancellation path."""
            return json.loads(_translate(lambda: self._client.ai_voice_audio(json.dumps(spec))))
        def events(self, spec):
            """Reads ordered utterance and epoch events, PCM, flushes, playout stops, safeguard receipts and notices; advancing the cursor releases consumed events."""
            return json.loads(_translate(lambda: self._client.ai_voice_events(json.dumps(spec))))
        def ack(self, spec):
            """Acknowledges the exact playout-end or playout-stop event of one session epoch after client playback or flush has completed."""
            return json.loads(_translate(lambda: self._client.ai_voice_ack(json.dumps(spec))))
        def usage(self, spec):
            """Observes actual voice-brain run settlements and a terminal boundary after producer teardown, epoch retirement, TTS cancel and client playout acknowledgment."""
            return json.loads(_translate(lambda: self._client.ai_voice_usage(json.dumps(spec))))
        def tool(self, spec):
            """Calls a connector under the caller grant and carries its delivered result, marked foreign, into the next voice utterance for parallel sentence safeguards."""
            return json.loads(_translate(lambda: self._client.ai_voice_tool(json.dumps(spec))))
        def end(self, spec):
            """Ends live voice through the shared cancellation path; keeps the session available for final playout acknowledgment and usage observation."""
            return json.loads(_translate(lambda: self._client.ai_voice_end(json.dumps(spec))))
        def close(self, spec):
            """Ends and releases a live voice session and its retained events; read terminal usage and acknowledge playout before closing."""
            return json.loads(_translate(lambda: self._client.ai_voice_close(json.dumps(spec))))
    class _AiVoiceAsrVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def open(self, spec):
            """Opens one credential-bound utterance for host-enriched ASR speculative recall, with fixed scope, at most four fires and a call-mode deadline."""
            return json.loads(_translate(lambda: self._client.ai_voice_asr_open(json.dumps(spec))))
        def hypothesis(self, spec):
            """Observes an ASR hypothesis and host enrichment; returns the engine signature-change decision, actual fire budget, scoped candidates and a per-fire receipt."""
            return json.loads(_translate(lambda: self._client.ai_voice_asr_hypothesis(json.dumps(spec))))
        def finalize(self, spec):
            """Consumes an ASR utterance, promoting its compatible last fire with receipt linkage or running one full finalize pass with warm-fill and honest partial reporting."""
            return json.loads(_translate(lambda: self._client.ai_voice_asr_finalize(json.dumps(spec))))
        def close(self, spec):
            """Closes an unfinished ASR utterance under its opening credential and releases its warm candidates without a final retrieval."""
            return json.loads(_translate(lambda: self._client.ai_voice_asr_close(json.dumps(spec))))
    class _AiVideoVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Starts a video render as a provider job and answers with its ticket."""
            return json.loads(_translate(lambda: self._client.ai_video(json.dumps(spec))))
        def poll(self, spec):
            """Where a video job stands; a finished one answers with its clip on every poll until ai.video.cancel deletes it."""
            return json.loads(_translate(lambda: self._client.ai_video_poll(json.dumps(spec))))
        def cancel(self, spec):
            """Stops a video job at its provider."""
            return json.loads(_translate(lambda: self._client.ai_video_cancel(json.dumps(spec))))
    class _RevealVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Asks for a custody or PERSON handle's value for the model, by its handle and why; answers a pending reveal that reveal.wait collects."""
            return json.loads(_translate(lambda: self._client.reveal(json.dumps(spec))))
        def wait(self, spec):
            """Where a reveal stands: pending, denied, expired or granted; the first granted answer carries the value, later ones the receipt."""
            return json.loads(_translate(lambda: self._client.reveal_wait(json.dumps(spec))))
        def describe(self, spec):
            """What a custody or PERSON handle names, where it was found and what a reveal of it would do now; never the value."""
            return json.loads(_translate(lambda: self._client.reveal_describe(json.dumps(spec))))
    class _HostVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def compact(self, spec):
            """Compacts a conversation window on the configured cheap backend, preserving add-only hook pins through the existing gate and keyframe mint."""
            return json.loads(_translate(lambda: self._client.host_compact(json.dumps(spec))))
        def wake(self, spec):
            """Schedules the host wake through its typed trigger; pre-hook Skip keeps its reason and Timer includes the engine maintenance lanes."""
            return json.loads(_translate(lambda: self._client.host_wake(json.dumps(spec))))
        @property
        def budget(self) -> "Oneiron._HostBudgetVerbs":
            return Oneiron._HostBudgetVerbs(self._client)
    class _HostBudgetVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def hit(self, spec):
            """Notifies a spent durable budget seat under Suspend, retaining the original line, root payer, cap and accounting for hook follow-up work."""
            return json.loads(_translate(lambda: self._client.host_budget_hit(json.dumps(spec))))
    class _GraphFsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def readdir(self, spec):
            """List one directory at the mounted reference under the caller read gate, with a sealed continuation."""
            return json.loads(_translate(lambda: self._client.graph_fs_readdir(json.dumps(spec))))
        def read_file(self, spec):
            """Read a bounded page of file bytes at the mounted reference, with its encoding and sealed continuation."""
            return json.loads(_translate(lambda: self._client.graph_fs_read_file(json.dumps(spec))))
        def read_link(self, spec):
            """Resolve a visible graph link at the mounted reference without following a host filesystem link."""
            return json.loads(_translate(lambda: self._client.graph_fs_read_link(json.dumps(spec))))
        def ls(self, spec):
            """List names at the mounted reference, using the live temporal index when requested."""
            return json.loads(_translate(lambda: self._client.graph_fs_ls(json.dumps(spec))))
        def find(self, spec):
            """Walk visible paths at the mounted reference, or push a live newer-than query into the temporal index."""
            return json.loads(_translate(lambda: self._client.graph_fs_find(json.dumps(spec))))
        def grep(self, spec):
            """Search visible mounted file bytes, using the live claim text index for supported recursive patterns."""
            return json.loads(_translate(lambda: self._client.graph_fs_grep(json.dumps(spec))))
        def cat(self, spec):
            """Read a bounded page of mounted file bytes as UTF-8 or base64 without changing its reference."""
            return json.loads(_translate(lambda: self._client.graph_fs_cat(json.dumps(spec))))
        def head(self, spec):
            """Read the first requested lines at the mounted reference with bounded output and a sealed continuation."""
            return json.loads(_translate(lambda: self._client.graph_fs_head(json.dumps(spec))))
        def wc(self, spec):
            """Count lines, words and bytes of a visible file at the mounted reference."""
            return json.loads(_translate(lambda: self._client.graph_fs_wc(json.dumps(spec))))
    class _ConnectorVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec):
            """Every live catalogued connector whose name or summary matches the query."""
            return json.loads(_translate(lambda: self._client.connector_list(json.dumps(spec))))
        def status(self, spec):
            """One catalogued connector by name, removed ones included."""
            return json.loads(_translate(lambda: self._client.connector_status(json.dumps(spec))))
        def call(self, spec):
            """Calls one tool of one catalogued connector under the caller's own grant and gate; the tool's reply comes back as foreign data."""
            return json.loads(_translate(lambda: self._client.connector_call(json.dumps(spec))))
        def schema(self, spec):
            """One catalogued connector tool's approved input schema, as the caller's own grant resolves it."""
            return json.loads(_translate(lambda: self._client.connector_schema(json.dumps(spec))))
        def call_status(self, spec):
            """Where one held connector.call stands, by the call_ref its held or pending_delivery reply named: still pending, or the reply it settled with. Only the actor that made the call and the vault's owner read it."""
            return json.loads(_translate(lambda: self._client.connector_call_status(json.dumps(spec))))
        @property
        def outbound(self) -> "Oneiron._ConnectorOutboundVerbs":
            return Oneiron._ConnectorOutboundVerbs(self._client)
    class _ConnectorOutboundVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def schedule(self, spec):
            """Schedules one send through a granted outbound connector, gated and held for delivery."""
            return json.loads(_translate(lambda: self._client.connector_outbound_schedule(json.dumps(spec))))
    class _CalendarVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def invite(self, spec):
            """Schedules an iMIP REQUEST or CANCEL through the caller-bound outbound gate, preserving UID, SEQUENCE, vault-only hygiene and delivery dedupe."""
            return json.loads(_translate(lambda: self._client.calendar_invite(json.dumps(spec))))
        @property
        def ics(self) -> "Oneiron._CalendarIcsVerbs":
            return Oneiron._CalendarIcsVerbs(self._client)
        @property
        def connector(self) -> "Oneiron._CalendarConnectorVerbs":
            return Oneiron._CalendarConnectorVerbs(self._client)
        @property
        def imip(self) -> "Oneiron._CalendarImipVerbs":
            return Oneiron._CalendarImipVerbs(self._client)
    class _CalendarIcsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def configure(self, spec):
            """Installs one owner-authorized secret-ref ICS feed per system with the existing bounded poll cadence; configuration grants no import consent."""
            return json.loads(_translate(lambda: self._client.calendar_ics_configure(json.dumps(spec))))
        def poll(self, spec):
            """Fetches the installed ICS feed through secret custody and the existing imported-claim gate, returning a durable completion barrier and cursor; failed or truncated fetches never mean absence."""
            return json.loads(_translate(lambda: self._client.calendar_ics_poll(json.dumps(spec))))
        def status(self, spec):
            """Reads the installed ICS configuration, real cursor and last public poll completion under owner proof, never the secret URL."""
            return json.loads(_translate(lambda: self._client.calendar_ics_status(json.dumps(spec))))
    class _CalendarConnectorVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def configure(self, spec):
            """Installs one CalDAV seat under owner proof, with a custody reference, discovery endpoint and nonzero bounded poll cadence."""
            return json.loads(_translate(lambda: self._client.calendar_connector_configure(json.dumps(spec))))
        def get(self, spec):
            """Reads a configured CalDAV seat, its real provider cursor, kill switch and last sync observation under owner proof."""
            return json.loads(_translate(lambda: self._client.calendar_connector_get(json.dumps(spec))))
        def pull(self, spec):
            """Pulls the configured CalDAV seat through the existing import gate and echo law, returning the real cursor and sync counters under owner proof."""
            return json.loads(_translate(lambda: self._client.calendar_connector_pull(json.dumps(spec))))
        def write(self, spec):
            """Writes a readable EVENT to the owner-installed CalDAV seat through the durable conditional-write outbox, never a blind overwrite."""
            return json.loads(_translate(lambda: self._client.calendar_connector_write(json.dumps(spec))))
        def kill(self, spec):
            """Kills a CalDAV seat under owner proof, revoking its advertised verbs and stopping further polling and writes without erasing calendar evidence."""
            return json.loads(_translate(lambda: self._client.calendar_connector_kill(json.dumps(spec))))
    class _CalendarImipVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def configure(self, spec):
            """Installs the host iMIP mail submission endpoint and custody name under owner proof; this configuration grants no invite consent or sending identity."""
            return json.loads(_translate(lambda: self._client.calendar_imip_configure(json.dumps(spec))))
        def get(self, spec=None):
            """Reads the installed host iMIP submission endpoint and custody name under owner proof, never its credential value."""
            return json.loads(_translate(lambda: self._client.calendar_imip_get(json.dumps({} if spec is None else spec))))

# END GENERATED FACADE VERBS
