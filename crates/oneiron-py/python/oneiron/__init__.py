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
    ) -> "Oneiron":
        """Opens an embedded vault and returns an actor-bound handle.

        Omitting ``path`` resolves to ``~/.oneiron/default`` against the current
        process home, at call time. The handle is usable immediately; there is
        no ``as_actor`` call to make first.

        Embedded open is currently supported only on Unix (macOS/Linux).
        On other targets, including Windows, it fails closed because writer
        locking is unsupported; use :meth:`connect` to a supported server host.

        A second process opening the same directory raises
        ``VAULT_LOCKED_SINGLE_WRITER``; connect to the owning process instead.
        """
        resolved = os.fspath(path) if path is not None else None
        return cls(_translate(lambda: _NativeClient.open(resolved, dimensions)))

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

        Returns ``{"memory", "credential", "pin"}``: the connected handle, the
        credential, and the checkpoint pin the link named (``None`` when the
        vault has no attested checkpoint). Store the credential as
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
        server that rendered the card.
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
    def report(self, spec):
        """Files one feedback report on a skill or run: its subject, category and evidence; the host supplies the actor."""
        return json.loads(_translate(lambda: self._client.report(json.dumps(spec))))
    @property
    def self(self) -> "Oneiron._SelfVerbs":
        return Oneiron._SelfVerbs(self._client)
    @property
    def vault(self) -> "Oneiron._VaultVerbs":
        return Oneiron._VaultVerbs(self._client)
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
    def reveal(self) -> "Oneiron._RevealVerbs":
        return Oneiron._RevealVerbs(self._client)
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
        """Waits on an ask at a step with no other work: pending, changed, ready with its result, or a park for code mode."""
        return json.loads(_translate(lambda: self._client.wait(json.dumps({"handle": handle, "step_key": step_key}))))
    @property
    def ai(self) -> "Oneiron._AiVerbs":
        return Oneiron._AiVerbs(self._client)
    @property
    def connector(self) -> "Oneiron._ConnectorVerbs":
        return Oneiron._ConnectorVerbs(self._client)
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
        def off_record(self) -> "Oneiron._SelfOffRecordVerbs":
            return Oneiron._SelfOffRecordVerbs(self._client)
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
        def fold(self, spec):
            """Marks a span of the attached run as pending; compaction leaves its raw steps untouched until a batch lands."""
            return json.loads(_translate(lambda: self._client.self_fold(json.dumps(spec))))
        def compact(self, spec):
            """Asks the attached run to fold its pending marks in one batch at its next step boundary; read self.history for landed folds and epochs."""
            return json.loads(_translate(lambda: self._client.self_compact(json.dumps(spec))))
        def unfold(self, spec):
            """Appends a fold of the attached run after its current tail, without replacing the earlier stub."""
            return json.loads(_translate(lambda: self._client.self_unfold(json.dumps(spec))))
        @property
        def agents(self) -> "Oneiron._SelfAgentsVerbs":
            return Oneiron._SelfAgentsVerbs(self._client)
        @property
        def leader(self) -> "Oneiron._SelfLeaderVerbs":
            return Oneiron._SelfLeaderVerbs(self._client)
    class _SelfFocusVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def scratchpad(self) -> "Oneiron._SelfFocusScratchpadVerbs":
            return Oneiron._SelfFocusScratchpadVerbs(self._client)
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
    class _SelfIdentityVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def answer(self, spec):
            """A vault owner's tap on an identity choice card: who a person named in their conversations is."""
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
    class _SelfOffRecordVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def execute(self, spec):
            """The owner runs one entry of a durable code-mode run bound to an off-record session; its rows and spilled outputs stay in the room until close."""
            return json.loads(_translate(lambda: self._client.self_off_record_execute(json.dumps(spec))))
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
    class _VaultVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def people(self) -> "Oneiron._VaultPeopleVerbs":
            return Oneiron._VaultPeopleVerbs(self._client)
        @property
        def shape(self) -> "Oneiron._VaultShapeVerbs":
            return Oneiron._VaultShapeVerbs(self._client)
        @property
        def fanout(self) -> "Oneiron._VaultFanoutVerbs":
            return Oneiron._VaultFanoutVerbs(self._client)
        @property
        def budgets(self) -> "Oneiron._VaultBudgetsVerbs":
            return Oneiron._VaultBudgetsVerbs(self._client)
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
            """
            return json.loads(_translate(lambda: self._client.vault_recall(query, effort, json.dumps(scope) if scope is not None else None, limit, format, as_of, deadline_ms, json.dumps(media) if media is not None else None, json.dumps(query_affect) if query_affect is not None else None)))
        @property
        def retrieval(self) -> "Oneiron._VaultRetrievalVerbs":
            return Oneiron._VaultRetrievalVerbs(self._client)
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
        def weave(self) -> "Oneiron._VaultWeaveVerbs":
            return Oneiron._VaultWeaveVerbs(self._client)
        @property
        def skill_hubs(self) -> "Oneiron._VaultSkillHubsVerbs":
            return Oneiron._VaultSkillHubsVerbs(self._client)
        @property
        def packs(self) -> "Oneiron._VaultPacksVerbs":
            return Oneiron._VaultPacksVerbs(self._client)
        @property
        def skills(self) -> "Oneiron._VaultSkillsVerbs":
            return Oneiron._VaultSkillsVerbs(self._client)
        @property
        def connectors(self) -> "Oneiron._VaultConnectorsVerbs":
            return Oneiron._VaultConnectorsVerbs(self._client)
        @property
        def authority(self) -> "Oneiron._VaultAuthorityVerbs":
            return Oneiron._VaultAuthorityVerbs(self._client)
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
        def gate(self) -> "Oneiron._VaultGateVerbs":
            return Oneiron._VaultGateVerbs(self._client)
        @property
        def learning(self) -> "Oneiron._VaultLearningVerbs":
            return Oneiron._VaultLearningVerbs(self._client)
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
        def workspace(self) -> "Oneiron._VaultWorkspaceVerbs":
            return Oneiron._VaultWorkspaceVerbs(self._client)
        @property
        def critic(self) -> "Oneiron._VaultCriticVerbs":
            return Oneiron._VaultCriticVerbs(self._client)
        @property
        def rooms(self) -> "Oneiron._VaultRoomsVerbs":
            return Oneiron._VaultRoomsVerbs(self._client)
        @property
        def projects(self) -> "Oneiron._VaultProjectsVerbs":
            return Oneiron._VaultProjectsVerbs(self._client)
        @property
        def conversations(self) -> "Oneiron._VaultConversationsVerbs":
            return Oneiron._VaultConversationsVerbs(self._client)
        @property
        def messages(self) -> "Oneiron._VaultMessagesVerbs":
            return Oneiron._VaultMessagesVerbs(self._client)
        @property
        def companions(self) -> "Oneiron._VaultCompanionsVerbs":
            return Oneiron._VaultCompanionsVerbs(self._client)
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
        def search(self) -> "Oneiron._VaultSearchVerbs":
            return Oneiron._VaultSearchVerbs(self._client)
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
    class _VaultPeopleVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec):
            """One page of the people the caller reads, in handle order."""
            return json.loads(_translate(lambda: self._client.vault_people_list(json.dumps(spec))))
        def get(self, spec):
            """One person the vault knows, by their pr handle."""
            return json.loads(_translate(lambda: self._client.vault_people_get(json.dumps(spec))))
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
    class _VaultFanoutVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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
        def settlements(self, spec):
            """The owner reads a served run's persisted physical-rung settlement receipts, with reservation, settled units and stamped cost when priced."""
            return json.loads(_translate(lambda: self._client.vault_budgets_settlements(json.dumps(spec))))
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
    class _VaultRetrievalOutcomesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            """The owner attaches an explicit observation to one local serving run; raw reward stays telemetry, never a gated training label."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_outcomes_put(json.dumps(spec))))
        def end(self, spec):
            """The owner records a gate-attributed turn outcome for its exact contributing retrievalRunIds; the engine validates the links and shapes the reward."""
            return json.loads(_translate(lambda: self._client.vault_retrieval_outcomes_end(json.dumps(spec))))
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
        def program(self) -> "Oneiron._VaultCampaignProgramVerbs":
            return Oneiron._VaultCampaignProgramVerbs(self._client)
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
    class _VaultWeaveVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def report(self, spec):
            """The live weave report for the bound actor, read through its own scope and the vault's weave policy for its role."""
            return json.loads(_translate(lambda: self._client.vault_weave_report(json.dumps(spec))))
        def digest(self, spec):
            """One of the bound actor's saved weave digests, or the newest, under the current read policy. Its lens is a card; a server holds its frame for the card's events, an embedded handle holds none."""
            return json.loads(_translate(lambda: self._client.vault_weave_digest(json.dumps(spec))))
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
    class _VaultWeaveLinkVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def wrong(self, spec):
            """A person labels a link in their own lens as wrong; the label teaches the loops and the link stays."""
            return json.loads(_translate(lambda: self._client.vault_weave_link_wrong(json.dumps(spec))))
    class _VaultWeaveOwnerVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def link(self) -> "Oneiron._VaultWeaveOwnerLinkVerbs":
            return Oneiron._VaultWeaveOwnerLinkVerbs(self._client)
        @property
        def item(self) -> "Oneiron._VaultWeaveOwnerItemVerbs":
            return Oneiron._VaultWeaveOwnerItemVerbs(self._client)
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
    class _VaultWeaveItemVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def wrong(self, spec):
            """A person labels a claim, project or budget item in their own lens as wrong; the label teaches the loops and the record stays."""
            return json.loads(_translate(lambda: self._client.vault_weave_item_wrong(json.dumps(spec))))
    class _VaultSkillHubsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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
            """The owner installs a pack folder, or replaces the pack installed under its name; the put is the consent for its hooks."""
            return json.loads(_translate(lambda: self._client.vault_packs_put(json.dumps(spec))))
        @property
        def connector(self) -> "Oneiron._VaultPacksConnectorVerbs":
            return Oneiron._VaultPacksConnectorVerbs(self._client)
        def remove(self, spec):
            """The owner removes an installed pack: it leaves the Active catalog and its hook bindings stop; a built-in goes back to its Candidate."""
            return json.loads(_translate(lambda: self._client.vault_packs_remove(json.dumps(spec))))
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
            """Reads live pack hook bindings as the owner, excluding revoked foreign publisher grants."""
            return json.loads(_translate(lambda: self._client.vault_packs_hooks_list(json.dumps({} if spec is None else spec))))
        def qualify(self, spec):
            """The owner qualifies a Candidate hub hook pack by real sandbox replay; qualification does not consent to wider hooks."""
            return json.loads(_translate(lambda: self._client.vault_packs_hooks_qualify(json.dumps(spec))))
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
    class _VaultSkillsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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
    class _VaultConnectorsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def subscriptions(self) -> "Oneiron._VaultConnectorsSubscriptionsVerbs":
            return Oneiron._VaultConnectorsSubscriptionsVerbs(self._client)
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
    class _VaultMembersVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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
        def connect(self) -> "Oneiron._VaultFederationConnectVerbs":
            return Oneiron._VaultFederationConnectVerbs(self._client)
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
        def revoke(self, spec):
            return json.loads(_translate(lambda: self._client.vault_guests_revoke(json.dumps(spec))))
        def mint_slip(self, spec):
            """The owner mints an ask guest's capability slip, bound to its grant, for the public key the guest generated on their own device."""
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
    class _VaultOffRecordVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def start(self, spec):
            """The owner enters an off-record session, off record or anonymous, as the owner route does; nothing of it reaches the vault unless the owner promotes or saves it."""
            return json.loads(_translate(lambda: self._client.vault_off_record_start(json.dumps(spec))))
        def status(self, spec):
            """The owner reads one live off-record session: its mode, backend, entry time, promoted turns and whether it is closing."""
            return json.loads(_translate(lambda: self._client.vault_off_record_status(json.dumps(spec))))
        def witness(self, spec):
            """The owner witnesses one turn into an off-record session; it stays in the room until promoted or dropped at close."""
            return json.loads(_translate(lambda: self._client.vault_off_record_witness(json.dumps(spec))))
        def discard(self, spec):
            """The owner closes an off-record session without saving it: its turns, writes, receipts and spilled outputs are dropped, and promoted turns stay."""
            return json.loads(_translate(lambda: self._client.vault_off_record_discard(json.dumps(spec))))
        def recall(self, spec):
            """The owner recalls over an off-record session and the vault together, on their own credential: rows the room holds and vault rows alike."""
            return json.loads(_translate(lambda: self._client.vault_off_record_recall(json.dumps(spec))))
        @property
        def notes(self) -> "Oneiron._VaultOffRecordNotesVerbs":
            return Oneiron._VaultOffRecordNotesVerbs(self._client)
        @property
        def claims(self) -> "Oneiron._VaultOffRecordClaimsVerbs":
            return Oneiron._VaultOffRecordClaimsVerbs(self._client)
    class _VaultOffRecordNotesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """The owner writes one NOTE into an off-record session through its handle; it lands in the room, never in the vault, and close drops it."""
            return json.loads(_translate(lambda: self._client.vault_off_record_notes_create(json.dumps(spec))))
    class _VaultOffRecordClaimsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def upsert(self, spec):
            """The owner admits one claim into an off-record session through its handle and the gate; it lands in the room beside the vault heads, and close drops it."""
            return json.loads(_translate(lambda: self._client.vault_off_record_claims_upsert(json.dumps(spec))))
    class _VaultRecordsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def erase_preview(self, spec):
            """What erasing one record would take: the brief grants it revokes, the records holding the same bytes and the LFS chunks it shares, with the digest erase_confirm takes back."""
            return json.loads(_translate(lambda: self._client.vault_records_erase_preview(json.dumps(spec))))
        def erase_confirm(self, spec):
            """Erase the record the caller previewed, once its preview still has the digest they confirmed; in a shared vault a held record starts its own erase act instead."""
            return json.loads(_translate(lambda: self._client.vault_records_erase_confirm(json.dumps(spec))))
    class _VaultResearchVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create_child(self, spec):
            """The owner enqueues an experiment child through ordinary agent dispatch under an unpruned campaign parent; record its actual candidate afterward with research.fork or research.weave."""
            return json.loads(_translate(lambda: self._client.vault_research_create_child(json.dumps(spec))))
        def archive(self, spec):
            """Reads the complete retained campaign record, including every pruned, buggy and woven candidate, original search and held-out evidence, selection rounds and promotion receipts, under the controller gate."""
            return json.loads(_translate(lambda: self._client.vault_research_archive(json.dumps(spec))))
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
        def record_benchmark(self, spec):
            """Records an estimator version's held-out selection benchmark against the DGM parent formula, once per version; a win of at least 30 cases lets its information gain rank parents."""
            return json.loads(_translate(lambda: self._client.vault_research_record_benchmark(json.dumps(spec))))
    class _VaultEvalsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def inventory(self, spec):
            """The owner reads the metadata-only eval-authoring inventory: real receipt families, grounded case candidates, date-cut cohorts and exposure counts. Pin its built_at and digest for cohort setup."""
            return json.loads(_translate(lambda: self._client.vault_evals_inventory(json.dumps(spec))))
        @property
        def cohorts(self) -> "Oneiron._VaultEvalsCohortsVerbs":
            return Oneiron._VaultEvalsCohortsVerbs(self._client)
    class _VaultEvalsCohortsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def setup(self, spec):
            """The owner sets up sealed cohorts from a pinned real inventory through the existing family, case and audited cut doors. Reports refused decisions; never serves sealed content or fabricates labels or skill provenance."""
            return json.loads(_translate(lambda: self._client.vault_evals_cohorts_setup(json.dumps(spec))))
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
            """Stores one retrieval probe the owner or another model wrote: kind, query, family, targets and author."""
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
        def default(self, spec):
            """Composes the default vault lens from the named sources, read under the caller's own scope, as a card. A server holds its frame for the card's events; an embedded handle holds none, so its events need a server."""
            return json.loads(_translate(lambda: self._client.vault_lenses_default(json.dumps(spec))))
    class _VaultDisclosureVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def offer(self, spec):
            """An agent files a clearance offer for one contact, waiting on the owner's answer until it lapses."""
            return json.loads(_translate(lambda: self._client.vault_disclosure_offer(json.dumps(spec))))
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
    class _VaultArtifactsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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
        def oplog(self, spec):
            """Read the durable mutation log of one repository in sequence order: prepared, applied and failed mutations. Owner only. It is not a proposal queue and holds no pending proposal."""
            return json.loads(_translate(lambda: self._client.vault_code_oplog(json.dumps(spec))))
        def model_heal_count(self, spec):
            """Read the tally this vault keeps of its own durable executor turns one model needed wire healing for, by full provider/name@revision id, zero when absent. Owner only. A routing signal, not a run correction receipt or repair policy."""
            return json.loads(_translate(lambda: self._client.vault_code_model_heal_count(json.dumps(spec))))
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
    class _VaultCodeOriginVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def authority(self) -> "Oneiron._VaultCodeOriginAuthorityVerbs":
            return Oneiron._VaultCodeOriginAuthorityVerbs(self._client)
        def publications(self, spec):
            """Read durable publication records for one served repository ref and commit without synthesizing a push acknowledgement."""
            return json.loads(_translate(lambda: self._client.vault_code_origin_publications(json.dumps(spec))))
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
            """The owner creates or imports an inert custom agent composition at a new AGENT_DEF id, with caller-derived authorship and existing fork/ceiling gates; no attempt is dispatched."""
            return json.loads(_translate(lambda: self._client.vault_agents_create(json.dumps(spec))))
        def get(self, spec):
            """The owner reads one saved agent composition and its version and approval state."""
            return json.loads(_translate(lambda: self._client.vault_agents_get(json.dumps(spec))))
        def update(self, spec):
            """The owner edits the expected definition version through the existing immutable-field and ceiling gates; running attempts retain their captured revision."""
            return json.loads(_translate(lambda: self._client.vault_agents_update(json.dumps(spec))))
        @property
        def spawn(self) -> "Oneiron._VaultAgentsSpawnVerbs":
            return Oneiron._VaultAgentsSpawnVerbs(self._client)
        def export_pack(self, request: dict[str, Any]) -> dict[str, Any]:
            """The agent's travelling AgentPack folder (files base64) and what stayed home."""
            return json.loads(_translate(lambda: self._client.vault_agents_export_pack(json.dumps(request, allow_nan=False))))
    class _VaultAgentsSpawnVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """The owner reads one spawned agent's stored observations by its attempt: its type stamp and frozen plan, the team actually launched, its seat route, critic artifacts and receipt-backed learning."""
            return json.loads(_translate(lambda: self._client.vault_agents_spawn_get(json.dumps(spec))))
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
    class _VaultRunsBranchesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """The owner reads every branch of one TASK: its lifecycle state, run status, result, typed asks and signals, and its landing, saved partial-result (resume point) and cancellation receipts."""
            return json.loads(_translate(lambda: self._client.vault_runs_branches_get(json.dumps(spec))))
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
        def messages(self, room_ref, after=None, limit=None):
            """One page of the turns in a room this reader may read."""
            return json.loads(_translate(lambda: self._client.vault_rooms_messages(json.dumps({"room_ref": room_ref, "after": after, "limit": limit}))))
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
            """Speaks through the witness gate; on a new thread root, thread_audience explicitly limits readers to named room members and cannot be changed later."""
            return json.loads(_translate(lambda: self._client.vault_rooms_speak(json.dumps(spec))))
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
    class _VaultProjectsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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
        @property
        def goal(self) -> "Oneiron._VaultProjectsGoalVerbs":
            return Oneiron._VaultProjectsGoalVerbs(self._client)
        def route_tradeoff(self, spec):
            """Asks the A/B tradeoff question pending on a skill proposal on a project TASK, as a visible turn in its home room."""
            return json.loads(_translate(lambda: self._client.vault_projects_route_tradeoff(json.dumps(spec))))
    class _VaultProjectsRosterVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def write(self, spec):
            """Writes an existing project's signed roster as the bound caller, filing joins for the newly seated subjects it stands for and an invitation for each unrelated person, who accepts through vault.rooms.consent."""
            return json.loads(_translate(lambda: self._client.vault_projects_roster_write(json.dumps(spec))))
    class _VaultProjectsGoalVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def intake(self, spec):
            """What a project's goal-intake interview starts from, for a member of its home room."""
            return json.loads(_translate(lambda: self._client.vault_projects_goal_intake(json.dumps(spec))))
        def revisions(self, spec):
            """The learned goal preferences proposed for a project's goal in force and not dismissed, oldest first."""
            return json.loads(_translate(lambda: self._client.vault_projects_goal_revisions(json.dumps(spec))))
        def dismiss(self, spec):
            """The owner dismisses the proposal one tradeoff question made for a project's goal; false for an identical retry."""
            return json.loads(_translate(lambda: self._client.vault_projects_goal_dismiss(json.dumps(spec))))
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
    class _VaultMessagesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def react(self, spec):
            """Puts or removes the caller's own reaction on a message or turn; an owner-grade host also brings a provider's reaction as connector ingress."""
            return json.loads(_translate(lambda: self._client.vault_messages_react(json.dumps(spec))))
    class _VaultCompanionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def sharing(self) -> "Oneiron._VaultCompanionsSharingVerbs":
            return Oneiron._VaultCompanionsSharingVerbs(self._client)
    class _VaultCompanionsSharingVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """One contact's clearance in a companion's source vault, for the principal who controls that vault."""
            return json.loads(_translate(lambda: self._client.vault_companions_sharing_get(json.dumps(spec))))
        def set(self, spec):
            """The owner's standing yes to one frozen clearance offer for a companion's contact."""
            return json.loads(_translate(lambda: self._client.vault_companions_sharing_set(json.dumps(spec))))
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
            """Refreshes the caller's standing question by hand, now, over every unit its current version covers, on the host's ladder as the standing pump answers it."""
            return json.loads(_translate(lambda: self._client.vault_questions_refresh(json.dumps(spec))))
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
        def page_token(self, spec):
            """The owner discovers the opaque token for an existing configured booking page; this does not publish the page or grant booking authority."""
            return json.loads(_translate(lambda: self._client.vault_booking_page_token(json.dumps(spec))))
    class _VaultCalendarVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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
        @property
        def transcript(self) -> "Oneiron._VaultCalendarTranscriptVerbs":
            return Oneiron._VaultCalendarTranscriptVerbs(self._client)
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
    class _VaultCalendarTranscriptVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def ingest(self, spec):
            """Ingests an uploaded UTF-8 transcript as the caller, retaining source labels and atomically closing its SESSION with ordered TURNs and extraction wake receipts."""
            return json.loads(_translate(lambda: self._client.vault_calendar_transcript_ingest(json.dumps(spec))))
    class _VaultWritesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def pending(self, input: dict[str, Any]) -> Any:
            """Gated writes parked for consent, newest first."""
            return json.loads(_translate(lambda: self._client.vault_writes_pending(json.dumps(input, allow_nan=False))))
    class _VaultRefsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def resolve(self, spec):
            """The bounded preview of one record ref, read through the caller's own scope; unreadable and missing look the same."""
            return json.loads(_translate(lambda: self._client.vault_refs_resolve(json.dumps(spec))))
        def links(self, spec):
            """A text, the texts a read surface returned, or a turn's readable messages, as typed spans whose record links resolve under the caller's own read."""
            return json.loads(_translate(lambda: self._client.vault_refs_links(json.dumps(spec))))
    class _VaultSearchVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def hybrid(self, input: dict[str, Any]) -> Any:
            """Searches explicit vector, text, phonetic, temporal and PPR channels under the caller read ceiling, with optional fixed-time blend replay and per-hit score evidence."""
            return json.loads(_translate(lambda: self._client.vault_search_hybrid(json.dumps(input, allow_nan=False))))
        def bm25(self, input: dict[str, Any]) -> Any:
            """BM25 text search over the engine index; surfaceable claims only."""
            return json.loads(_translate(lambda: self._client.vault_search_bm25(json.dumps(input, allow_nan=False))))
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
            """Reads one signing document as its trail folds: its status, recipients, filled fields and its hash-chained audit trail."""
            return json.loads(_translate(lambda: self._client.vault_esign_get(json.dumps(spec))))
        @property
        def links(self) -> "Oneiron._VaultEsignLinksVerbs":
            return Oneiron._VaultEsignLinksVerbs(self._client)
        def send_for_signature(self, spec):
            """Sends a drafted signing document to its recipients through the outbound gate, as the caller; an agent sends only within its principal envelope."""
            return json.loads(_translate(lambda: self._client.vault_esign_send_for_signature(json.dumps(spec))))
        def remind(self, spec):
            """Reminds the recipients whose turn it is to sign a pending document, through the outbound gate, as the caller."""
            return json.loads(_translate(lambda: self._client.vault_esign_remind(json.dumps(spec))))
        def void(self, spec):
            """Withdraws a drafted or pending signing document unsealed and tells its recipients why, through the outbound gate, as the caller."""
            return json.loads(_translate(lambda: self._client.vault_esign_void(json.dumps(spec))))
    class _VaultEsignLinksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def issue(self, spec):
            """The vault owner mints the signing links of a drafted document and receives each new one once, to deliver to its recipient."""
            return json.loads(_translate(lambda: self._client.vault_esign_links_issue(json.dumps(spec))))
    class _VaultConsolidationVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def enqueue(self, spec):
            """Enqueues one consolidation attempt and returns its durable job reference."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_enqueue(json.dumps(spec))))
        def status(self, spec):
            """Reads the status of one consolidation attempt by its durable job reference."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_status(json.dumps(spec))))
        def promote(self, spec):
            """Promotes typed generated candidates in an admitted Dreamer attempt through its host-stamped writer and checker, returning retained evidence and refusals."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_promote(json.dumps(spec))))
        def evidence(self, spec):
            """Reads exact generated-claim evidence, source lineage and separate consolidation, corroboration and effector-evidence eligibility as the owner."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_evidence(json.dumps(spec))))
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
        def create(self, input: dict[str, Any]) -> Any:
            """Creates a NOTE of a registered kind, its first authored text as its birth."""
            return json.loads(_translate(lambda: self._client.vault_notes_create(json.dumps(input, allow_nan=False))))
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
    class _RevealVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Asks for a secret's value for the model, by its handle and why; answers a pending reveal that reveal.wait collects."""
            return json.loads(_translate(lambda: self._client.reveal(json.dumps(spec))))
        def wait(self, spec):
            """Where a reveal stands: pending, denied, expired or granted; the first granted answer carries the value, later ones the receipt."""
            return json.loads(_translate(lambda: self._client.reveal_wait(json.dumps(spec))))
        def describe(self, spec):
            """What a secret handle names, where it was found and what a reveal of it would do now; never the value."""
            return json.loads(_translate(lambda: self._client.reveal_describe(json.dumps(spec))))
    class _AiVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def steps(self) -> "Oneiron._AiStepsVerbs":
            return Oneiron._AiStepsVerbs(self._client)
        def reply(self, spec):
            """Generate one context-bearing reply from the caller's scoped conversation, standing prefix and reader profile through an exact configured model; return durable emit-context receipt refs."""
            return json.loads(_translate(lambda: self._client.ai_reply(json.dumps(spec))))
        @property
        def voice(self) -> "Oneiron._AiVoiceVerbs":
            return Oneiron._AiVoiceVerbs(self._client)
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
    class _AiStepsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def submit(self, spec):
            """Submit or resume one owner-bound durable model step with declared transport attempts, deterministic fallback and a schema-validated JSON result."""
            return json.loads(_translate(lambda: self._client.ai_steps_submit(json.dumps(spec))))
        def receipt(self, spec):
            """Read the owner-bound model-step checkpoints and persisted terminal result without calling a model or spending another lease."""
            return json.loads(_translate(lambda: self._client.ai_steps_receipt(json.dumps(spec))))
    class _AiVoiceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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

# END GENERATED FACADE VERBS
