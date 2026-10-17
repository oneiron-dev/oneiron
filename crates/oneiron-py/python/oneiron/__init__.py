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
    ``suggestions`` is never empty.
    """

    def __init__(
        self,
        code: str,
        message: str,
        suggestions: list[str],
        wrong_root: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.suggestions = tuple(suggestions)
        # A ``WRONG_ROOT`` refusal's ``{attempted, replacement, schemaRef}``.
        self.wrong_root = wrong_root


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
        return OneironError(payload["code"], payload["message"], suggestions, wrong_root)
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
    def pair(cls, link: str) -> tuple["Oneiron", str]:
        """Redeems a one-use pairing link and connects with its credential.

        Returns the connected handle and the credential. Store the credential
        as ``ONEIRON_KEY``; the link cannot be redeemed twice.
        """
        url, credential = _translate(lambda: _NativeClient.pair(link))
        return cls.connect(url, credential), credential

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

    def last_receipt_ref(self) -> str | None:
        """The lasting call receipt the last verb's reply stated, as ``call:<32hex>``.

        It is stated whether the call answered or refused, and
        ``vault.receipts.get`` resolves it for the same actor or the vault's
        owner. Typed returns keep their shape; the ref rides beside them here.
        ``None`` for an embedded handle, before any call, after a call that
        reached no server, and for an anonymous off-record call.
        """
        return self._client.last_receipt_ref()

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
        def skills(self) -> "Oneiron._SelfSkillsVerbs":
            return Oneiron._SelfSkillsVerbs(self._client)
        @property
        def decisions(self) -> "Oneiron._SelfDecisionsVerbs":
            return Oneiron._SelfDecisionsVerbs(self._client)
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
    class _VaultVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def people(self) -> "Oneiron._VaultPeopleVerbs":
            return Oneiron._VaultPeopleVerbs(self._client)
        def witness(self, turn: dict[str, Any]) -> dict[str, Any]:
            """Witnesses one conversational turn.

            Omitting ``occurred_at`` stamps the current wall clock, in Unix
            seconds, at the call boundary.
            """
            return json.loads(_translate(lambda: self._client.vault_witness(json.dumps(turn))))
        @property
        def claims(self) -> "Oneiron._VaultClaimsVerbs":
            return Oneiron._VaultClaimsVerbs(self._client)
        def recall(self, query: str, *, effort: str = 'medium', scope: dict[str, Any] | None = None, limit: int = 10, format: str | None = None, as_of: int | None = None, deadline_ms: int | None = None) -> dict[str, Any]:
            """Recalls a memory pack.

            ``effort="high"`` needs a lease this package never mints: an embedded
            client raises ``LEASE_REQUIRED``; a remote one gets what the server
            serves (reranked on its ``[models]`` reranker, or unreranked and
            saying so). ``effort="call"`` is call mode for live calls:
            light effort under a hard deadline (``deadline_ms``, or the vault's
            call-mode deadline), answering with the best results ready, marked
            ``partial``. ``format`` takes the engine's exact tokens:
            ``"json"``, ``"yaml"``, ``"toon"``, ``"md"``, ``"txt"``.
            """
            return json.loads(_translate(lambda: self._client.vault_recall(query, effort, json.dumps(scope) if scope is not None else None, limit, format, as_of, deadline_ms)))
        def export(self, format: str | None = None) -> dict[str, Any]:
            """Exports the whole vault as one re-importable archive (ZIP, base64 in `archive`)."""
            return json.loads(_translate(lambda: self._client.vault_export(json.dumps({"format": format}))))
        @property
        def receipts(self) -> "Oneiron._VaultReceiptsVerbs":
            return Oneiron._VaultReceiptsVerbs(self._client)
        @property
        def images(self) -> "Oneiron._VaultImagesVerbs":
            return Oneiron._VaultImagesVerbs(self._client)
        @property
        def kv(self) -> "Oneiron._VaultKvVerbs":
            return Oneiron._VaultKvVerbs(self._client)
        @property
        def weave(self) -> "Oneiron._VaultWeaveVerbs":
            return Oneiron._VaultWeaveVerbs(self._client)
        @property
        def packs(self) -> "Oneiron._VaultPacksVerbs":
            return Oneiron._VaultPacksVerbs(self._client)
        @property
        def authority(self) -> "Oneiron._VaultAuthorityVerbs":
            return Oneiron._VaultAuthorityVerbs(self._client)
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
        def guests(self) -> "Oneiron._VaultGuestsVerbs":
            return Oneiron._VaultGuestsVerbs(self._client)
        @property
        def legal_holds(self) -> "Oneiron._VaultLegalHoldsVerbs":
            return Oneiron._VaultLegalHoldsVerbs(self._client)
        @property
        def embedding_spaces(self) -> "Oneiron._VaultEmbeddingSpacesVerbs":
            return Oneiron._VaultEmbeddingSpacesVerbs(self._client)
        @property
        def settings(self) -> "Oneiron._VaultSettingsVerbs":
            return Oneiron._VaultSettingsVerbs(self._client)
        @property
        def widen_proposals(self) -> "Oneiron._VaultWidenProposalsVerbs":
            return Oneiron._VaultWidenProposalsVerbs(self._client)
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
        def rooms(self) -> "Oneiron._VaultRoomsVerbs":
            return Oneiron._VaultRoomsVerbs(self._client)
        @property
        def projects(self) -> "Oneiron._VaultProjectsVerbs":
            return Oneiron._VaultProjectsVerbs(self._client)
        @property
        def conversations(self) -> "Oneiron._VaultConversationsVerbs":
            return Oneiron._VaultConversationsVerbs(self._client)
        @property
        def companions(self) -> "Oneiron._VaultCompanionsVerbs":
            return Oneiron._VaultCompanionsVerbs(self._client)
        @property
        def workspace(self) -> "Oneiron._VaultWorkspaceVerbs":
            return Oneiron._VaultWorkspaceVerbs(self._client)
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
            """Commits claims through the gate, each element decided on its own; rejected elements come back rejected and do not persist."""
            return json.loads(_translate(lambda: self._client.vault_commit(json.dumps(input, allow_nan=False))))
        def remember(self, input: dict[str, Any]) -> Any:
            """Commits one claim through the gate, the same as vault.claims.upsert."""
            return json.loads(_translate(lambda: self._client.vault_remember(json.dumps(input, allow_nan=False))))
        def forget(self, input: dict[str, Any]) -> Any:
            """Retracts claims by exact claim or by subject and predicate; never a hard delete."""
            return json.loads(_translate(lambda: self._client.vault_forget(json.dumps(input, allow_nan=False))))
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
        def consolidation(self) -> "Oneiron._VaultConsolidationVerbs":
            return Oneiron._VaultConsolidationVerbs(self._client)
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
    class _VaultClaimsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def upsert(self, claim: dict[str, Any]) -> dict[str, Any]:
            """Upserts one claim. The consent gate, not this call, decides approval."""
            return json.loads(_translate(lambda: self._client.vault_claims_upsert(json.dumps(claim))))
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
        def seed(self, input: dict[str, Any]) -> Any:
            """Seeds claims through their individual gates, forced proposed, returning one receipt per claim."""
            return json.loads(_translate(lambda: self._client.vault_claims_seed(json.dumps(input, allow_nan=False))))
    class _VaultReceiptsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, limit: int = 100) -> list[dict[str, Any]]:
            """Governance receipts, newest first."""
            return json.loads(_translate(lambda: self._client.vault_receipts(limit)))
        def get(self, spec):
            """One call receipt by ref, readable by its own actor or the vault's live owner; anything else reads as none."""
            return json.loads(_translate(lambda: self._client.vault_receipts_get(json.dumps(spec))))
    class _VaultImagesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def view(self, request: dict[str, Any]) -> dict[str, Any]:
            """The full pixels behind an image's view handle (view, crop or zoom), recorded as a pull."""
            return json.loads(_translate(lambda: self._client.vault_images_view(json.dumps(request, allow_nan=False))))
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
    class _VaultWeaveVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def report(self, spec):
            """The live weave report for the bound actor, read through its own scope and the vault's weave policy for its role."""
            return json.loads(_translate(lambda: self._client.vault_weave_report(json.dumps(spec))))
        def digest(self, spec):
            """One of the bound actor's saved weave digests, or the newest, under the current read policy."""
            return json.loads(_translate(lambda: self._client.vault_weave_digest(json.dumps(spec))))
        def lens(self, spec):
            return json.loads(_translate(lambda: self._client.vault_weave_lens(json.dumps(spec))))
        @property
        def link(self) -> "Oneiron._VaultWeaveLinkVerbs":
            return Oneiron._VaultWeaveLinkVerbs(self._client)
    class _VaultWeaveLinkVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def wrong(self, spec):
            """A person labels a link in their own lens as wrong; the label teaches the loops and the link stays."""
            return json.loads(_translate(lambda: self._client.vault_weave_link_wrong(json.dumps(spec))))
    class _VaultPacksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            """The owner installs a pack folder, or replaces the pack installed under its name; the put is the consent for its hooks."""
            return json.loads(_translate(lambda: self._client.vault_packs_put(json.dumps(spec))))
        @property
        def setup(self) -> "Oneiron._VaultPacksSetupVerbs":
            return Oneiron._VaultPacksSetupVerbs(self._client)
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
    class _VaultAuthorityVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def audit(self, spec):
            """One page of the dated authority log audit: grants, revokes and confirms, for the owner."""
            return json.loads(_translate(lambda: self._client.vault_authority_audit(json.dumps(spec))))
        @property
        def handoff_alarms(self) -> "Oneiron._VaultAuthorityHandoffAlarmsVerbs":
            return Oneiron._VaultAuthorityHandoffAlarmsVerbs(self._client)
    class _VaultAuthorityHandoffAlarmsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec=None):
            """Every saved authority handoff fork alarm, for the owner."""
            return json.loads(_translate(lambda: self._client.vault_authority_handoff_alarms(json.dumps({} if spec is None else spec))))
        def acknowledge(self, spec):
            """The owner acknowledges one saved handoff fork alarm."""
            return json.loads(_translate(lambda: self._client.vault_authority_handoff_alarms_acknowledge(json.dumps(spec))))
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
    class _VaultMembersVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def add(self, spec):
            """An Admin invites a live person into a shared vault at a non-root role; they join when they accept."""
            return json.loads(_translate(lambda: self._client.vault_members_add(json.dumps(spec))))
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
    class _VaultGuestsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def revoke(self, spec):
            return json.loads(_translate(lambda: self._client.vault_guests_revoke(json.dumps(spec))))
        def mint_slip(self, spec):
            """The owner mints an ask guest's capability slip, bound to its grant, for the public key the guest generated on their own device."""
            return json.loads(_translate(lambda: self._client.vault_guests_mint_slip(json.dumps(spec))))
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
            """One page of the vault's lens proposals, each with its slot state from the owner's current selection."""
            return json.loads(_translate(lambda: self._client.vault_lenses_list(json.dumps(spec))))
        def default(self, spec):
            """Composes the default vault lens from the named sources, read under the caller's own scope."""
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
        def put(self, input: dict[str, Any]) -> Any:
            """Registers one blob artifact; its bytes ride vault.artifacts.append."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_put(json.dumps(input, allow_nan=False))))
        def append(self, input: dict[str, Any]) -> Any:
            """Appends one version of bytes to a blob artifact's append-only chain."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_append(json.dumps(input, allow_nan=False))))
        def read(self, input: dict[str, Any]) -> Any:
            """Reads one version of a blob artifact's bytes."""
            return json.loads(_translate(lambda: self._client.vault_artifacts_read(json.dumps(input, allow_nan=False))))
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
        def repo_diff(self, request: dict[str, Any]) -> dict[str, Any] | None:
            """Every file changed between two trees of a repository, unit by unit, with the operations that wrote each."""
            return json.loads(_translate(lambda: self._client.vault_code_repo_diff(json.dumps(request, allow_nan=False))))
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
            """Speaks one turn into the current room turn's room, through the normal witness gate."""
            return json.loads(_translate(lambda: self._client.vault_rooms_speak(json.dumps(spec))))
        def join(self, spec):
            """Files and decides a request to take part in a room or one of its threads."""
            return json.loads(_translate(lambda: self._client.vault_rooms_join(json.dumps(spec))))
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
            """Publishes an agent's offer card to join a room or one of its threads."""
            return json.loads(_translate(lambda: self._client.vault_rooms_offer(json.dumps(spec))))
        def answer(self, spec):
            """The room's host answers an offer card: join, or not now."""
            return json.loads(_translate(lambda: self._client.vault_rooms_offer_answer(json.dumps(spec))))
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
        def goal(self) -> "Oneiron._VaultProjectsGoalVerbs":
            return Oneiron._VaultProjectsGoalVerbs(self._client)
        def route_tradeoff(self, spec):
            """Asks the A/B tradeoff question pending on a skill proposal on a project TASK, as a visible turn in its home room."""
            return json.loads(_translate(lambda: self._client.vault_projects_route_tradeoff(json.dumps(spec))))
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
    class _VaultConversationsTurnVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def continue_(self, spec):
            """Queues generation that resumes an incomplete assistant reply from exactly its saved text."""
            return json.loads(_translate(lambda: self._client.vault_conversations_turn_continue(json.dumps(spec))))
        def retry(self, spec):
            """Queues a new answer to the user turn an assistant turn answered; the old reply stays."""
            return json.loads(_translate(lambda: self._client.vault_conversations_turn_retry(json.dumps(spec))))
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
    class _VaultWorkspaceVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def work_companion(self) -> "Oneiron._VaultWorkspaceWorkCompanionVerbs":
            return Oneiron._VaultWorkspaceWorkCompanionVerbs(self._client)
    class _VaultWorkspaceWorkCompanionVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def get(self, spec):
            """A workspace's work_companion policy, readable by every member it governs."""
            return json.loads(_translate(lambda: self._client.vault_workspace_work_companion_get(json.dumps(spec))))
        def set(self, spec):
            """The owner sets a workspace's work_companion policy in person."""
            return json.loads(_translate(lambda: self._client.vault_workspace_work_companion_set(json.dumps(spec))))
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
        def read(self, spec):
            return json.loads(_translate(lambda: self._client.vault_questions_read(json.dumps(spec))))
        def answers(self, spec):
            return json.loads(_translate(lambda: self._client.vault_questions_answers(json.dumps(spec))))
    class _VaultDecisionsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def asks(self) -> "Oneiron._VaultDecisionsAsksVerbs":
            return Oneiron._VaultDecisionsAsksVerbs(self._client)
    class _VaultDecisionsAsksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def answer(self, spec):
            return json.loads(_translate(lambda: self._client.vault_decisions_asks_answer(json.dumps(spec))))
        def climb(self, spec):
            return json.loads(_translate(lambda: self._client.vault_decisions_asks_climb(json.dumps(spec))))
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
            """A text, or a turn's readable messages, as typed spans whose record links resolve under the caller's own read."""
            return json.loads(_translate(lambda: self._client.vault_refs_links(json.dumps(spec))))
    class _VaultSearchVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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
    class _VaultConsolidationVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def enqueue(self, spec):
            """Enqueues one consolidation attempt and returns its durable job reference."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_enqueue(json.dumps(spec))))
        def status(self, spec):
            """Reads the status of one consolidation attempt by its durable job reference."""
            return json.loads(_translate(lambda: self._client.vault_consolidation_status(json.dumps(spec))))
    class _VaultNotesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, input: dict[str, Any]) -> Any:
            """Creates a NOTE of a registered kind, its first authored text as its birth."""
            return json.loads(_translate(lambda: self._client.vault_notes_create(json.dumps(input, allow_nan=False))))
        def from_entity(self, input: dict[str, Any]) -> Any:
            """Creates a NOTE of a registered kind from an existing entity."""
            return json.loads(_translate(lambda: self._client.vault_notes_from_entity(json.dumps(input, allow_nan=False))))
        def edit(self, input: dict[str, Any]) -> Any:
            """Edits one NOTE in a transaction-local document; a rejected edit leaves nothing pending."""
            return json.loads(_translate(lambda: self._client.vault_notes_edit(json.dumps(input, allow_nan=False))))
    class _TasksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            """Mints one TASK and its realizing attempt when the actor's ceiling permits, or parks it as a proposal."""
            return json.loads(_translate(lambda: self._client.tasks_create(json.dumps(spec))))
        def update(self, spec):
            """Records the owner's acknowledgement of a failed TASK; any other task stays as it was."""
            return json.loads(_translate(lambda: self._client.tasks_update(json.dumps(spec))))
        def answer(self, handle, word):
            """Admits one person's word on an ask; the word is evidence, never approval."""
            return json.loads(_translate(lambda: self._client.tasks_answer(json.dumps({"handle": handle, "word": word}))))
        def outcomes(self, handle):
            """Owner-scoped calibration pairs for an ask: each prediction against the outcome it was bound to."""
            return json.loads(_translate(lambda: self._client.tasks_outcomes(json.dumps(handle))))
    class _AiVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def options(self, spec):
            """The model rows an ai call could use: where each runs, what it takes, its rates, and what the media meter has left."""
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
            """The caller's own typed question through the host's decision ladder, answered with a probability and a decision receipt."""
            return json.loads(_translate(lambda: self._client.ai_verdict(json.dumps(spec))))
    class _AiVideoVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            """Starts a video render as a provider job and answers with its ticket."""
            return json.loads(_translate(lambda: self._client.ai_video(json.dumps(spec))))
        def poll(self, spec):
            """Where a video job stands; a finished one answers with its clip, once."""
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
