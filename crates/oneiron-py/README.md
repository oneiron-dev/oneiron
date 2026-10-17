# Memory Wire — oneiron

Memory Wire is the Oneiron developer profile. Start with `vault.witness`,
`vault.recall`, and `vault.receipts`. The same package also ships
`vault.claims.upsert` (the same path in JS) and the other facade verbs listed
under [API](#api). The verb set is generated from
`scripts/sdk/agent-verbs.json` by `scripts/sdk/generate.py`; the shipped stubs
(`oneiron/__init__.pyi`) carry the typed signatures.
There is no separate lite SDK and no alternate mutation path.

```sh
pip install oneiron
```

Python 3.10 or newer. The package ships a compiled extension; the public import
stays `from oneiron import Oneiron`.

## Quickstart

Four calls, no configuration, no server. `Oneiron.open()` creates and owns an
embedded vault at `~/.oneiron/default` and binds a local owner actor, so there
is no actor ceremony before the first write.

```python
import json

from oneiron import Oneiron

memory = Oneiron.open()

witnessed = memory.vault.witness(
    {
        "conversation_ref": "11111111111111111111111111111111",
        "messages": [
            {
                "author": "user",
                "message_type": "dialogue",
                "content": "I prefer a window seat when I fly.",
                "order": 0,
            }
        ],
    }
)

claimed = memory.vault.claims.upsert(
    {
        "id": "22222222222222222222222222222222",
        "predicate": "preference.travel.seat",
        "subject_ref": witnessed["turn_short_id"],
        "value": {"seat": "window"},
        "confidence": 1.0,
        "source": "user_stated",
    }
)
recalled = memory.vault.recall("window seat")
receipts = memory.vault.receipts()

print(json.dumps({
    "witnessed": witnessed,
    "claimed": claimed,
    "recalled": recalled,
    "receipts": receipts,
}, indent=2))
```

DTOs are plain dicts with snake_case keys, typed by the shipped stubs.

## Connecting to a server

`connect` returns the same handle type, so the four calls above are unchanged —
embedded and remote differ by one line:

```python
import os

from oneiron import Oneiron

memory = Oneiron.connect("http://127.0.0.1:8080", os.environ["ONEIRON_KEY"])
```

`key` is the credential `Oneiron.pair(link)` returned once, from a link the
server's owner created with `oneiron-server token pair`: it holds the slip and
its connection key, and this package signs every request with that key. The
package never reads the slip's claims: write identity comes from the
server-verified slip, and every authority decision is made server-side. A
connected handle's `as_actor` therefore raises `FORBIDDEN` — pair a link
created for the actor you want to act as instead.

## API

| method | returns |
|---|---|
| `Oneiron.open(path=None, *, dimensions=None)` | an embedded handle |
| `Oneiron.connect(url, key)` | a remote handle |
| `Oneiron.pair(link)` | `(handle, credential)`: a remote handle and the credential to store |
| `handle.as_actor(actor_key)` | a new handle bound to another actor |
| `handle.in_room_turn(room_ref)` | a new handle whose every verb runs as a turn in that room |
| `handle.vault.witness(turn)` | `WitnessReceipt` |
| `handle.vault.claims.upsert(claim)` | `CommitReceipt` |
| `handle.vault.recall(query, ...)` | `MemoryPack` |
| `handle.vault.receipts(limit=100)` | `list[FacadeReceipt]` |
| `handle.vault.export(format=None)` | the whole vault as one re-importable archive: a ZIP (JSONL per record kind, files by BLAKE3, manifest), base64 in `archive` |
| `handle.cancel(task_ref)` | `TaskCancelReceipt` |
| `handle.describe(task_ref=None)` | `TaskDescription`: one task card, or the whole TASKS section |
| `handle.can(request)` | `TaskAskPreflight` |
| `handle.peek(request)` | `list[TaskAskPersonEvidence]` |
| `handle.ask(spec)` / `handle.wait(handle)` | an ask's receipt / its wait outcome |
| `handle.vault.kv.get` / `put` / `delete` / `search` / `namespaces(request)` | exact, actor-owned keyed memory |
| `handle.tasks.*` | `create`, `update`, `answer`, `outcomes` |
| `handle.vault.rooms.*` | `list`, `messages`, `render`, `find`, `get`, `trunk`, `claim`, `speak` |

Every other verb in the SDK verb table sits at its SDK path on the handle and
takes its whole input as one dict. The stubs type that dict and the result as
TypedDicts from `oneiron.facade_types` (imported in the stubs as `Facade`),
which `scripts/sdk/generate.py` reads from the Rust types each row names, and
each method's docstring is its row's description. Of the table's 153 facade
rows, 131 inputs and 127 results are fully typed; the rest are typed down to a
leaf that is opaque JSON by design (`Any`), and none is left untyped. The
module is stub-only: annotate with it under `typing.TYPE_CHECKING`.

`vault.recall` keyword arguments are `effort` (`"light" | "medium" | "high" | "xhigh" | "max" | "call"`,
default `"medium"`), `scope` (`{"world_ref": ..., "facet": ...}`), `limit`
(default `10`), `format` (`"json" | "yaml" | "toon" | "md" | "txt"`), `as_of`
(Unix seconds; the recall's reference time, default now) and `deadline_ms`.
`high`, `xhigh` and `max` need a lease this package never mints: an embedded client raises
`LEASE_REQUIRED`; a remote one gets what the server serves (reranked on its `[models]`
reranker, or unreranked and saying so). `"call"` is call mode for live calls: light
effort under a hard deadline (`deadline_ms`, or the vault's call-mode deadline, 100 ms
by default), answering with the best results ready, marked `partial`.

Timestamps are Unix **seconds** everywhere and are never converted. Omitting
`occurred_at` stamps the current wall clock at the call boundary.

## Errors

Every failure is an `OneironError` carrying the engine's own vocabulary:

```python
from oneiron import Oneiron, OneironError

try:
    memory.vault.recall("window seat", effort="high")
except OneironError as error:
    print(error.code, error.message, error.suggestions)
```

`code` is the engine's stable string — `BAD_REQUEST`, `FORBIDDEN`,
`NOT_FOUND`, `LEASE_REQUIRED`, `VAULT_LOCKED_SINGLE_WRITER`, and others — and
`suggestions` is never empty. One `except` clause is all a caller needs.

## One writer per vault

An embedded vault directory is owned by one process at a time. A second process
opening it raises `VAULT_LOCKED_SINGLE_WRITER` with a suggestion to `connect`
to the owner instead. Ownership is a live OS lock, so a crash releases it and a
stale `oneiron.writer.lock` file never blocks a reopen.

Opening the same path twice in ONE process is fine and shares the same native
vault; reopening it with different options raises `BAD_REQUEST` rather than
silently handing back a differently configured vault.

## Documentation

Full documentation, the Node package, and the engine itself live in the repo:
<https://github.com/oneiron-dev/oneiron>.

## License

Apache-2.0
