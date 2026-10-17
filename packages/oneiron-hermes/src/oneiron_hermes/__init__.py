"""Oneiron as Hermes Agent's memory provider (OF-442, ARCH-0028 ``#plugin-hermes``).

Hermes runs one outside memory provider at a time, in its memory slot. This one
starts on the cohabitation default:

- Oneiron alone (Hermes's built-in memory off): Oneiron is the agent's memory.
- Hermes's built-in memory on: Oneiron runs beside it. The built-in files stay
  primary; Oneiron keeps the conversation, mirrors the built-in writes and
  recalls related context into each turn.

``mode`` in the provider's config pins either one (``memory`` or ``beside``);
``auto`` reads Hermes's ``memory.memory_enabled`` / ``memory.user_profile_enabled``.

The vault a session binds comes from ``oneiron hook --host hermes bind``, the
same order every Oneiron plugin uses (PLUGIN-FIRSTRUN = D): a pin, a running
local vault, else a local server it starts. Reads and writes go through the
Python SDK with the agent credential ``oneiron token agent --out`` wrote.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Optional

from agent.memory_provider import (
    MemoryProvider,
    RecallStatus,
    is_trivial_prompt,
    spawn_context_thread,
)

__all__ = ["OneironMemoryProvider", "register"]

logger = logging.getLogger(__name__)

NAME = "oneiron"
LABEL = "Oneiron"
CONFIG_FILE = "oneiron.json"
MODES = ("auto", "memory", "beside")
EFFORTS = ("light", "medium", "high", "xhigh", "max")
RECALL_TOOL = "oneiron_recall"
REMEMBER_TOOL = "oneiron_remember"
# Non-secret config keys ``save_config`` keeps; the key itself stays in the env.
CONFIG_KEYS = ("url", "credential_file", "mode", "effort", "limit", "oneiron")
DEFAULTS: dict[str, Any] = {
    "url": "",
    "credential_file": "",
    "mode": "auto",
    "effort": "light",
    "limit": 8,
    "oneiron": "oneiron",
}
# How long `oneiron hook bind` may take: it may start a local server.
BIND_TIMEOUT_S = 20.0
# A prefetch with nothing queued reads in call mode under this deadline.
PREFETCH_DEADLINE_MS = 1500
# Longest content one witnessed message or claim value carries.
MAX_CONTENT_CHARS = 32_000
# Most characters a recall block injects.
MAX_BLOCK_CHARS = 6_000


def _sdk():
    """The Oneiron SDK class, or None when the package is not installed."""
    try:
        from oneiron import Oneiron
    except ImportError:
        return None
    return Oneiron


def _entity_hex(seed: str) -> str:
    """A stable 32-hex entity id for ``seed``: a session's conversation."""
    digest = bytearray(hashlib.blake2b(seed.encode("utf-8"), digest_size=16).digest())
    digest[0] &= 0x7F  # outside the received-foreign id range
    return digest.hex()


def _clip(text: str, limit: int = MAX_CONTENT_CHARS) -> str:
    return text if len(text) <= limit else text[:limit]


def _builtin_memory_on() -> bool:
    """Whether Hermes's built-in memory store is on (either of its two files)."""
    try:
        from tools.memory_tool import get_builtin_memory_store_flags

        memory_enabled, user_profile_enabled = get_builtin_memory_store_flags()
        return bool(memory_enabled or user_profile_enabled)
    except Exception:
        logger.debug("Hermes built-in memory flags unreadable; assuming on", exc_info=True)
        return True


class OneironMemoryProvider(MemoryProvider):
    """Hermes's memory slot, filled by an Oneiron vault."""

    def __init__(self) -> None:
        self._config: dict[str, Any] = dict(DEFAULTS)
        self._client: Any = None
        self._mode = "memory"
        self._vault_line = ""
        self._session_id = ""
        self._conversation = ""
        self._primary = True
        self._lock = threading.Lock()
        self._cached: dict[str, tuple[str, int]] = {}
        self._status: Optional[RecallStatus] = None
        self._threads: list[threading.Thread] = []
        self._unavailable = ""

    # -- identity and setup ---------------------------------------------------

    @property
    def name(self) -> str:
        return NAME

    def _load_config(self, hermes_home: Optional[str]) -> dict[str, Any]:
        config = dict(DEFAULTS)
        home = hermes_home or os.environ.get("HERMES_HOME")
        if home:
            path = Path(home) / CONFIG_FILE
            try:
                saved = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(saved, dict):
                    config.update({k: v for k, v in saved.items() if k in CONFIG_KEYS})
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                logger.warning("Oneiron: %s is unreadable; using defaults", path)
        for key, env in (
            ("url", "ONEIRON_URL"),
            ("credential_file", "ONEIRON_CREDENTIAL_FILE"),
            ("mode", "ONEIRON_HERMES_MODE"),
        ):
            if os.environ.get(env):
                config[key] = os.environ[env]
        return config

    def _key(self) -> str:
        """The agent credential: ``ONEIRON_KEY``, else the credential file."""
        key = os.environ.get("ONEIRON_KEY", "").strip()
        if key:
            return key
        path = str(self._config.get("credential_file") or "").strip()
        if not path:
            return ""
        try:
            return Path(path).expanduser().read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def is_available(self) -> bool:
        self._config = self._load_config(None)
        if _sdk() is None:
            self._unavailable = "the oneiron package is not installed: pip install oneiron"
            return False
        if not os.environ.get("ONEIRON_KEY") and not str(self._config.get("credential_file") or ""):
            self._unavailable = (
                "no agent credential: run `oneiron token agent --name hermes --out <file>` "
                "and set credential_file (or ONEIRON_KEY)"
            )
            return False
        self._unavailable = ""
        return True

    def unavailable_reason(self) -> str:
        return self._unavailable

    def _bind(self) -> str:
        """The vault's origin, in the plugins' one order; '' when none answers."""
        url = str(self._config.get("url") or "")
        binary = shutil.which(str(self._config.get("oneiron") or "oneiron"))
        if binary is None:
            self._vault_line = f"Oneiron: this session uses the vault at {url}." if url else ""
            return url
        command = [binary, "hook", "--host", "hermes", "bind", "--timeout", str(BIND_TIMEOUT_S)]
        if url:
            command += ["--url", url]
        try:
            done = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=BIND_TIMEOUT_S + 5,
                check=False,
            )
            bound = json.loads(done.stdout.strip().splitlines()[-1])
        except (OSError, subprocess.SubprocessError, ValueError, IndexError):
            logger.warning("Oneiron: `oneiron hook --host hermes bind` gave no answer", exc_info=True)
            return url
        lines = [line for line in bound.get("lines") or [] if isinstance(line, str)]
        self._vault_line = lines[0] if lines else ""
        for line in lines[1:]:
            logger.info("%s", line)
        return bound.get("url") or ""

    def initialize(self, session_id: str, **kwargs) -> None:
        self._config = self._load_config(kwargs.get("hermes_home"))
        self._primary = kwargs.get("agent_context", "primary") == "primary"
        self._rebind(session_id)
        mode = str(self._config.get("mode") or "auto")
        if mode not in MODES:
            logger.warning("Oneiron: mode %r is not one of %s; using auto", mode, MODES)
            mode = "auto"
        if mode == "auto":
            mode = "beside" if _builtin_memory_on() else "memory"
        self._mode = mode
        Oneiron = _sdk()
        url, key = self._bind(), self._key()
        if Oneiron is None or not url or not key:
            logger.warning("Oneiron: no vault or credential; this session runs without Oneiron")
            return
        try:
            self._client = Oneiron.connect(url, key)
        except Exception:
            logger.warning("Oneiron: connect to %s failed; this session runs without it", url, exc_info=True)
            self._client = None

    def _rebind(self, session_id: str) -> None:
        self._session_id = session_id
        self._conversation = _entity_hex(f"hermes:session:{session_id}")

    def system_prompt_block(self) -> str:
        if self._client is None:
            return ""
        tools = (
            f"Use `{RECALL_TOOL}` to look up anything older than this conversation and "
            f"`{REMEMBER_TOOL}` to keep something for later."
        )
        if self._mode == "memory":
            body = (
                "Oneiron is your memory. Memories related to each message are recalled into "
                "the turn, and this conversation is kept in Oneiron as it happens. " + tools
            )
        else:
            body = (
                "Your built-in memory (its memory and user profile files) stays your primary "
                "memory. Oneiron runs beside it: it keeps this conversation, mirrors what you "
                "write to the built-in memory, and recalls related context into each turn. " + tools
            )
        return f"{self._vault_line}\n{body}".strip()

    # -- recall ---------------------------------------------------------------

    def _recall(self, query: str, *, effort: str, deadline_ms: Optional[int] = None,
                limit: Optional[int] = None) -> tuple[str, int]:
        pack = self._client.vault.recall(
            _clip(query, 4096),
            effort=effort,
            limit=int(limit or self._config.get("limit") or 8),
            format="md",
            deadline_ms=deadline_ms,
        )
        items = pack.get("items") or []
        text = pack.get("rendered") or "\n".join(
            f"- {item.get('value_text', '')}" for item in items if item.get("value_text")
        )
        return _clip(text.strip(), MAX_BLOCK_CHARS), len(items)

    def _effort(self) -> str:
        effort = str(self._config.get("effort") or "light")
        return effort if effort in EFFORTS else "light"

    def _recall_into_cache(self, query: str, session_id: str) -> None:
        try:
            recalled = self._recall(query, effort=self._effort())
        except Exception:
            logger.debug("Oneiron: background recall failed", exc_info=True)
            return
        with self._lock:
            self._cached[session_id] = recalled

    def _spawn(self, target, *, name: str, args: tuple = ()) -> None:
        thread = spawn_context_thread(target, name=name, args=args)
        with self._lock:
            self._threads = [t for t in self._threads if t.is_alive()]
            self._threads.append(thread)
        thread.start()

    def queue_prefetch(self, query: str, *, session_id: str = "") -> None:
        if self._client is None or is_trivial_prompt(query):
            return
        self._spawn(self._recall_into_cache, name="oneiron-prefetch",
                    args=(query, session_id or self._session_id))

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        self._status = None
        if self._client is None or is_trivial_prompt(query):
            return ""
        with self._lock:
            cached = self._cached.pop(session_id or self._session_id, None)
        if cached is None:
            try:
                cached = self._recall(query, effort="call", deadline_ms=PREFETCH_DEADLINE_MS)
            except Exception:
                logger.debug("Oneiron: prefetch recall failed", exc_info=True)
                return ""
        text, count = cached
        if not text:
            return ""
        self._status = RecallStatus(provider_label=LABEL, count=count)
        return f"From your Oneiron vault (recalled for this turn; may be dated):\n{text}"

    def recall_status(self) -> Optional[RecallStatus]:
        return self._status

    # -- writes ---------------------------------------------------------------

    def _witness(self, author: str, content: str, message_type: str = "text",
                 metadata: Optional[dict[str, Any]] = None) -> None:
        if not content or not content.strip():
            return
        self._client.vault.witness({
            "conversation_ref": self._conversation,
            "turn_ref": None,
            "messages": [{
                "id": None,
                "author": author,
                "message_type": message_type,
                "content": _clip(content),
                "metadata": {"source": "hermes", "session_id": self._session_id, **(metadata or {})},
                "is_visible": True,
                "order": 0,
            }],
            "occurred_at": int(time.time()),
        })

    def _sync(self, user_content: str, assistant_content: str) -> None:
        try:
            self._witness("user", user_content)
            self._witness("companion", assistant_content)
        except Exception:
            logger.debug("Oneiron: witnessing the turn failed", exc_info=True)

    def sync_turn(self, user_content: str, assistant_content: str, *, session_id: str = "",
                  messages: Optional[list[dict[str, Any]]] = None,
                  turn_author: Optional[dict[str, Any]] = None) -> None:
        # Subagents, cron runs and flushes write nothing: only the primary
        # agent's conversation is the person's.
        if self._client is None or not self._primary:
            return
        self._spawn(self._sync, name="oneiron-sync", args=(user_content, assistant_content))

    def _keep(self, content: str, *, predicate: str, message_type: str,
              claim_id: Optional[str] = None, metadata: Optional[dict[str, Any]] = None,
              valid_to: Optional[int] = None) -> dict[str, Any]:
        """Witnesses ``content`` as a note in this conversation, then keeps it as
        one claim about the conversation, so recall finds it at once."""
        self._witness("companion", content, message_type, metadata)
        return self._client.vault.claims.upsert({
            "id": claim_id,
            "predicate": predicate,
            "subject_ref": self._conversation,
            "value": {"content": _clip(content), **(metadata or {})},
            "confidence": 0.8,
            "source": "generated",
            "world_ref": None,
            "relationship_ref": None,
            "scope": None,
            "valid_from": None,
            "valid_to": valid_to,
            "occurred_at": None,
            "learned_at": None,
            "salience": None,
        })

    def on_memory_write(self, action: str, target: str, content: str,
                        metadata: Optional[dict[str, Any]] = None) -> None:
        """Beside the built-in memory, each of its writes is mirrored as one
        claim, keyed by the entry so a replace or a remove reaches it."""
        if self._client is None or not self._primary:
            return
        metadata = metadata or {}
        previous = metadata.get("previous_content")
        entry = previous if action in ("replace", "remove") and isinstance(previous, str) else content
        claim_id = _entity_hex(f"hermes:memory:{target}:{entry}")
        predicate = "hermes.memory.user" if target == "user" else "hermes.memory.note"

        def mirror() -> None:
            try:
                self._keep(
                    content if action != "remove" else entry,
                    predicate=predicate,
                    message_type=f"memory_{action}",
                    claim_id=claim_id,
                    metadata={"action": action, "target": target},
                    valid_to=int(time.time()) if action == "remove" else None,
                )
            except Exception:
                logger.debug("Oneiron: mirroring a memory write failed", exc_info=True)

        self._spawn(mirror, name="oneiron-mirror")

    # -- tools ----------------------------------------------------------------

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        # `memory` is a reserved core tool name in Hermes; these never shadow it.
        return [
            {
                "name": RECALL_TOOL,
                "description": "Recall memories from your Oneiron vault related to a query.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "What to recall."},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 50,
                                  "description": "Most memories returned."},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": REMEMBER_TOOL,
                "description": "Keep something in your Oneiron vault for later sessions.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "What to remember."},
                        "about": {"type": "string", "enum": ["user", "agent"],
                                  "description": "Whether it is about the user or your own work."},
                    },
                    "required": ["content"],
                },
            },
        ]

    def handle_tool_call(self, tool_name: str, args: dict[str, Any], **kwargs) -> str:
        if self._client is None:
            return json.dumps({"ok": False, "error": "Oneiron is not connected in this session."})
        try:
            if tool_name == RECALL_TOOL:
                text, count = self._recall(str(args.get("query") or ""), effort=self._effort(),
                                           limit=args.get("limit"))
                return json.dumps({"ok": True, "count": count, "memories": text})
            if tool_name == REMEMBER_TOOL:
                about = "user" if args.get("about") == "user" else "agent"
                receipt = self._keep(str(args.get("content") or ""), predicate=f"hermes.remember.{about}",
                                     message_type="note", metadata={"about": about})
                return json.dumps({"ok": True, "claim": receipt.get("claim_short_id"),
                                   "approval": receipt.get("approval")})
        except Exception as error:
            return json.dumps({"ok": False, "error": str(error)})
        return json.dumps({"ok": False, "error": f"unknown tool {tool_name}"})

    # -- lifecycle hooks ------------------------------------------------------

    def _drain(self, timeout: float = 10.0) -> None:
        with self._lock:
            threads = list(self._threads)
        end = time.monotonic() + timeout
        for thread in threads:
            thread.join(max(0.0, end - time.monotonic()))

    def on_pre_compress(self, messages: list[dict[str, Any]]) -> str:
        # Every turn about to be compressed lands before the summary is cut.
        self._drain()
        return ""

    def on_session_switch(self, new_session_id: str, *, parent_session_id: str = "",
                          reset: bool = False, rewound: bool = False, **kwargs) -> None:
        self._drain()
        with self._lock:
            if reset:
                self._cached.clear()
            else:
                self._cached.pop(self._session_id, None)
        self._rebind(new_session_id)

    def shutdown(self) -> None:
        self._drain()
        self._client = None

    # -- config ---------------------------------------------------------------

    def get_config_schema(self) -> list[dict[str, Any]]:
        return [
            {"key": "url", "description": "The vault's origin. Empty: a pin, a running local vault, "
                                          "else a local server `oneiron hook` starts.",
             "required": False, "default": DEFAULTS["url"], "type": "text"},
            {"key": "credential_file", "description": "The agent credential "
                                                      "`oneiron token agent --name hermes --out <file>` wrote.",
             "required": False, "default": DEFAULTS["credential_file"], "type": "text"},
            {"key": "key", "description": "The agent credential itself, instead of a file.",
             "secret": True, "required": False, "env_var": "ONEIRON_KEY"},
            {"key": "mode", "description": "auto: beside Hermes's built-in memory when it is on, "
                                           "else the agent's memory.",
             "required": False, "default": DEFAULTS["mode"], "choices": list(MODES), "type": "text"},
            {"key": "effort", "description": "Recall effort; medium and up embed the query.",
             "required": False, "default": DEFAULTS["effort"], "choices": list(EFFORTS), "type": "text"},
            {"key": "limit", "description": "Most memories one recall returns.",
             "required": False, "default": DEFAULTS["limit"], "type": "integer",
             "minimum": 1, "maximum": 50, "step": 1},
            {"key": "oneiron", "description": "The oneiron binary that binds the vault.",
             "required": False, "default": DEFAULTS["oneiron"], "type": "text"},
        ]

    def save_config(self, values: dict[str, Any], hermes_home: str) -> None:
        path = Path(hermes_home) / CONFIG_FILE
        current = self._load_config(hermes_home)
        current.update({k: v for k, v in values.items() if k in CONFIG_KEYS})
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({k: current[k] for k in CONFIG_KEYS}, indent=2) + "\n",
                        encoding="utf-8")


def register(ctx) -> None:
    """Hermes's plugin entry: the provider for the memory slot."""
    ctx.register_memory_provider(OneironMemoryProvider())
