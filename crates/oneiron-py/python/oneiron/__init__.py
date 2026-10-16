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

    # BEGIN GENERATED FACADE VERBS
    def report(self, spec):
        return json.loads(_translate(lambda: self._client.report(json.dumps(spec))))
    @property
    def self(self) -> "Oneiron._SelfVerbs":
        return Oneiron._SelfVerbs(self._client)
    def cancel(self, task_ref: str) -> dict[str, Any]:
        """Cancels one task under the ladder's ``auto`` default. The receipt says what stopped and what became a proposal instead."""
        return json.loads(_translate(lambda: self._client.cancel(json.dumps({"task_ref": task_ref}))))
    def steer(self, spec):
        return json.loads(_translate(lambda: self._client.steer(json.dumps(spec))))
    def describe(self, task_ref: str | None = None) -> dict[str, Any]:
        """Describes one task's card, or the whole TASKS section when no task is named."""
        return json.loads(_translate(lambda: self._client.describe(json.dumps({"task_ref": task_ref}))))
    @property
    def tasks(self) -> "Oneiron._TasksVerbs":
        return Oneiron._TasksVerbs(self._client)
    @property
    def vault(self) -> "Oneiron._VaultVerbs":
        return Oneiron._VaultVerbs(self._client)
    def can(self, request: dict[str, Any]) -> dict[str, Any]:
        """Read-only ask routing or attributed partial answers."""
        return json.loads(_translate(lambda: self._client.can(json.dumps(request, allow_nan=False))))
    def peek(self, request: dict[str, Any]) -> list[dict[str, Any]]:
        """Read-only ask routing or attributed partial answers."""
        return json.loads(_translate(lambda: self._client.peek(json.dumps(request, allow_nan=False))))
    def ask(self, spec_or_who, what=None, until=None, default="ask_me"):
        if what is None:
            input = spec_or_who
        else:
            who = {"people": [spec_or_who]} if isinstance(spec_or_who, str) else {"people": list(spec_or_who)} if isinstance(spec_or_who, (set, list, tuple)) else spec_or_who
            input = {"who": who, "what": what, "until": until, "default": default}
        return json.loads(_translate(lambda: self._client.ask(json.dumps(input))))
    def wait(self, handle, step_key="sdk.wait"):
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
        def skills(self) -> "Oneiron._SelfSkillsVerbs":
            return Oneiron._SelfSkillsVerbs(self._client)
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
            return json.loads(_translate(lambda: self._client.self_memory_diary(json.dumps(spec))))
        def reads(self, spec):
            return json.loads(_translate(lambda: self._client.self_memory_diary_reads(json.dumps(spec))))
        def review(self, spec):
            return json.loads(_translate(lambda: self._client.self_memory_diary_review(json.dumps(spec))))
    class _SelfSkillsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def save(self, spec):
            return json.loads(_translate(lambda: self._client.self_skills_save(json.dumps(spec))))
        def fork(self, spec):
            return json.loads(_translate(lambda: self._client.self_skills_fork(json.dumps(spec))))
        def callables(self, spec):
            return json.loads(_translate(lambda: self._client.self_skills_callables(json.dumps(spec))))
    class _TasksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, spec):
            return json.loads(_translate(lambda: self._client.tasks_create(json.dumps(spec))))
        def update(self, spec):
            return json.loads(_translate(lambda: self._client.tasks_update(json.dumps(spec))))
        def answer(self, handle, word):
            return json.loads(_translate(lambda: self._client.tasks_answer(json.dumps({"handle": handle, "word": word}))))
        def outcomes(self, handle):
            return json.loads(_translate(lambda: self._client.tasks_outcomes(json.dumps(handle))))
    class _VaultVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
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
        def shared(self) -> "Oneiron._VaultSharedVerbs":
            return Oneiron._VaultSharedVerbs(self._client)
        @property
        def members(self) -> "Oneiron._VaultMembersVerbs":
            return Oneiron._VaultMembersVerbs(self._client)
        @property
        def authority(self) -> "Oneiron._VaultAuthorityVerbs":
            return Oneiron._VaultAuthorityVerbs(self._client)
        @property
        def lenses(self) -> "Oneiron._VaultLensesVerbs":
            return Oneiron._VaultLensesVerbs(self._client)
        @property
        def hooks(self) -> "Oneiron._VaultHooksVerbs":
            return Oneiron._VaultHooksVerbs(self._client)
        @property
        def artifacts(self) -> "Oneiron._VaultArtifactsVerbs":
            return Oneiron._VaultArtifactsVerbs(self._client)
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
        def commit(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_commit(json.dumps(input, allow_nan=False))))
        def remember(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_remember(json.dumps(input, allow_nan=False))))
        def forget(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_forget(json.dumps(input, allow_nan=False))))
        def delete(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_delete(json.dumps(input, allow_nan=False))))
        @property
        def writes(self) -> "Oneiron._VaultWritesVerbs":
            return Oneiron._VaultWritesVerbs(self._client)
        def hydrate(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_hydrate(json.dumps(input, allow_nan=False))))
        def get(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_get(json.dumps(input, allow_nan=False))))
        @property
        def refs(self) -> "Oneiron._VaultRefsVerbs":
            return Oneiron._VaultRefsVerbs(self._client)
        @property
        def search(self) -> "Oneiron._VaultSearchVerbs":
            return Oneiron._VaultSearchVerbs(self._client)
        def neighbors(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_neighbors(json.dumps(input, allow_nan=False))))
        @property
        def structural(self) -> "Oneiron._VaultStructuralVerbs":
            return Oneiron._VaultStructuralVerbs(self._client)
        @property
        def habits(self) -> "Oneiron._VaultHabitsVerbs":
            return Oneiron._VaultHabitsVerbs(self._client)
        @property
        def notes(self) -> "Oneiron._VaultNotesVerbs":
            return Oneiron._VaultNotesVerbs(self._client)
    class _VaultClaimsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def upsert(self, claim: dict[str, Any]) -> dict[str, Any]:
            """Upserts one claim. The consent gate, not this call, decides approval."""
            return json.loads(_translate(lambda: self._client.vault_claims_upsert(json.dumps(claim))))
        def retract(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_claims_retract(json.dumps(input, allow_nan=False))))
        def list(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_claims_list(json.dumps(input, allow_nan=False))))
        def history(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_claims_history(json.dumps(input, allow_nan=False))))
        def admit(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_claims_admit(json.dumps(input, allow_nan=False))))
    class _VaultReceiptsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, limit: int = 100) -> list[dict[str, Any]]:
            """Governance receipts, newest first."""
            return json.loads(_translate(lambda: self._client.vault_receipts(limit)))
        def get(self, spec):
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
            return json.loads(_translate(lambda: self._client.vault_weave_report(json.dumps(spec))))
        def digest(self, spec):
            return json.loads(_translate(lambda: self._client.vault_weave_digest(json.dumps(spec))))
    class _VaultPacksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, spec):
            return json.loads(_translate(lambda: self._client.vault_packs_put(json.dumps(spec))))
    class _VaultSharedVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def propose_delete(self, spec):
            return json.loads(_translate(lambda: self._client.vault_shared_propose_delete(json.dumps(spec))))
        def propose_transfer(self, spec):
            return json.loads(_translate(lambda: self._client.vault_shared_propose_transfer(json.dumps(spec))))
        def propose_remove_owner(self, spec):
            return json.loads(_translate(lambda: self._client.vault_shared_propose_remove_owner(json.dumps(spec))))
        def execute(self, spec):
            return json.loads(_translate(lambda: self._client.vault_shared_execute(json.dumps(spec))))
        def receipt(self, spec):
            return json.loads(_translate(lambda: self._client.vault_shared_receipt(json.dumps(spec))))
        def outcomes(self, spec):
            return json.loads(_translate(lambda: self._client.vault_shared_outcomes(json.dumps(spec))))
        def deletion(self, spec):
            return json.loads(_translate(lambda: self._client.vault_shared_deletion(json.dumps(spec))))
    class _VaultMembersVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def add(self, spec):
            return json.loads(_translate(lambda: self._client.vault_members_add(json.dumps(spec))))
        def change(self, spec):
            return json.loads(_translate(lambda: self._client.vault_members_change(json.dumps(spec))))
        def remove(self, spec):
            return json.loads(_translate(lambda: self._client.vault_members_remove(json.dumps(spec))))
        def leave(self, spec):
            return json.loads(_translate(lambda: self._client.vault_members_leave(json.dumps(spec))))
    class _VaultAuthorityVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def handoff_alarms(self) -> "Oneiron._VaultAuthorityHandoffAlarmsVerbs":
            return Oneiron._VaultAuthorityHandoffAlarmsVerbs(self._client)
    class _VaultAuthorityHandoffAlarmsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            return json.loads(_translate(lambda: self._client.vault_authority_handoff_alarms(json.dumps(spec))))
        def acknowledge(self, spec):
            return json.loads(_translate(lambda: self._client.vault_authority_handoff_alarms_acknowledge(json.dumps(spec))))
    class _VaultLensesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def propose(self, spec):
            return json.loads(_translate(lambda: self._client.vault_lenses_propose(json.dumps(spec))))
        def activate(self, spec):
            return json.loads(_translate(lambda: self._client.vault_lenses_activate(json.dumps(spec))))
        def deactivate(self, spec):
            return json.loads(_translate(lambda: self._client.vault_lenses_deactivate(json.dumps(spec))))
        def list(self, spec):
            return json.loads(_translate(lambda: self._client.vault_lenses_list(json.dumps(spec))))
        def default(self, spec):
            return json.loads(_translate(lambda: self._client.vault_lenses_default(json.dumps(spec))))
    class _VaultHooksVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def replay(self, spec):
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
            return json.loads(_translate(lambda: self._client.vault_artifacts_put(json.dumps(input, allow_nan=False))))
        def append(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_artifacts_append(json.dumps(input, allow_nan=False))))
        def read(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_artifacts_read(json.dumps(input, allow_nan=False))))
    class _VaultRoomsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self):
            return json.loads(_translate(lambda: self._client.vault_rooms_list(json.dumps({}))))
        def messages(self, room_ref, after=None, limit=None):
            return json.loads(_translate(lambda: self._client.vault_rooms_messages(json.dumps({"room_ref": room_ref, "after": after, "limit": limit}))))
        def render(self, room_ref):
            return json.loads(_translate(lambda: self._client.vault_rooms_render(json.dumps({"room_ref": room_ref}))))
        def find(self, room_ref, after=None, limit=None):
            return json.loads(_translate(lambda: self._client.vault_rooms_find(json.dumps({"room_ref": room_ref, "after": after, "limit": limit}))))
        def get(self, room_ref, turn_ref):
            return json.loads(_translate(lambda: self._client.vault_rooms_get(json.dumps({"room_ref": room_ref, "turn_ref": turn_ref}))))
        def trunk(self, room_ref, turn_ref):
            return json.loads(_translate(lambda: self._client.vault_rooms_trunk(json.dumps({"room_ref": room_ref, "turn_ref": turn_ref}))))
        def reply_strips(self, spec):
            return json.loads(_translate(lambda: self._client.vault_rooms_reply_strips(json.dumps(spec))))
        def claim(self, room_ref, turn_ref):
            return json.loads(_translate(lambda: self._client.vault_rooms_claim(json.dumps({"room_ref": room_ref, "turn_ref": turn_ref}))))
        def speak(self, spec):
            return json.loads(_translate(lambda: self._client.vault_rooms_speak(json.dumps(spec))))
        def join(self, spec):
            return json.loads(_translate(lambda: self._client.vault_rooms_join(json.dumps(spec))))
        def consent(self, spec):
            return json.loads(_translate(lambda: self._client.vault_rooms_consent(json.dumps(spec))))
        def host(self, spec):
            return json.loads(_translate(lambda: self._client.vault_rooms_host(json.dumps(spec))))
        def sharing(self, spec):
            return json.loads(_translate(lambda: self._client.vault_rooms_sharing(json.dumps(spec))))
    class _VaultProjectsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        @property
        def goal(self) -> "Oneiron._VaultProjectsGoalVerbs":
            return Oneiron._VaultProjectsGoalVerbs(self._client)
        def route_tradeoff(self, spec):
            return json.loads(_translate(lambda: self._client.vault_projects_route_tradeoff(json.dumps(spec))))
    class _VaultProjectsGoalVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def revisions(self, spec):
            return json.loads(_translate(lambda: self._client.vault_projects_goal_revisions(json.dumps(spec))))
        def dismiss(self, spec):
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
            return json.loads(_translate(lambda: self._client.vault_conversations_turn_continue(json.dumps(spec))))
        def retry(self, spec):
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
            return json.loads(_translate(lambda: self._client.vault_companions_sharing_get(json.dumps(spec))))
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
            return json.loads(_translate(lambda: self._client.vault_workspace_work_companion_get(json.dumps(spec))))
        def set(self, spec):
            return json.loads(_translate(lambda: self._client.vault_workspace_work_companion_set(json.dumps(spec))))
    class _VaultWritesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def pending(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_writes_pending(json.dumps(input, allow_nan=False))))
    class _VaultRefsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def resolve(self, spec):
            return json.loads(_translate(lambda: self._client.vault_refs_resolve(json.dumps(spec))))
    class _VaultSearchVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def bm25(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_search_bm25(json.dumps(input, allow_nan=False))))
    class _VaultStructuralVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def put(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_structural_put(json.dumps(input, allow_nan=False))))
    class _VaultHabitsVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def checkin(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_habits_checkin(json.dumps(input, allow_nan=False))))
    class _VaultNotesVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def create(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_notes_create(json.dumps(input, allow_nan=False))))
        def from_entity(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_notes_from_entity(json.dumps(input, allow_nan=False))))
        def edit(self, input: dict[str, Any]) -> Any:
            return json.loads(_translate(lambda: self._client.vault_notes_edit(json.dumps(input, allow_nan=False))))
    class _AiVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def options(self, spec):
            return json.loads(_translate(lambda: self._client.ai_options(json.dumps(spec))))
        def image(self, spec):
            return json.loads(_translate(lambda: self._client.ai_image(json.dumps(spec))))
        def speech(self, spec):
            return json.loads(_translate(lambda: self._client.ai_speech(json.dumps(spec))))
        def transcribe(self, spec):
            return json.loads(_translate(lambda: self._client.ai_transcribe(json.dumps(spec))))
        def embed(self, spec):
            return json.loads(_translate(lambda: self._client.ai_embed(json.dumps(spec))))
        @property
        def video(self) -> "Oneiron._AiVideoVerbs":
            return Oneiron._AiVideoVerbs(self._client)
        def verdict(self, spec):
            return json.loads(_translate(lambda: self._client.ai_verdict(json.dumps(spec))))
    class _AiVideoVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def __call__(self, spec):
            return json.loads(_translate(lambda: self._client.ai_video(json.dumps(spec))))
        def poll(self, spec):
            return json.loads(_translate(lambda: self._client.ai_video_poll(json.dumps(spec))))
        def cancel(self, spec):
            return json.loads(_translate(lambda: self._client.ai_video_cancel(json.dumps(spec))))
    class _ConnectorVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def list(self, spec):
            return json.loads(_translate(lambda: self._client.connector_list(json.dumps(spec))))
        def status(self, spec):
            return json.loads(_translate(lambda: self._client.connector_status(json.dumps(spec))))
        @property
        def outbound(self) -> "Oneiron._ConnectorOutboundVerbs":
            return Oneiron._ConnectorOutboundVerbs(self._client)
    class _ConnectorOutboundVerbs:
        def __init__(self, client: _NativeClient) -> None:
            self._client = client
        def schedule(self, spec):
            return json.loads(_translate(lambda: self._client.connector_outbound_schedule(json.dumps(spec))))

# END GENERATED FACADE VERBS
