# oneiron

Memory for agents. Witness a turn, claim a fact, recall it, read the receipts.

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

witnessed = memory.witness(
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

claimed = memory.claim_upsert(
    {
        "id": "22222222222222222222222222222222",
        "predicate": "preference.travel.seat",
        "subject_ref": witnessed["turn_short_id"],
        "value": {"seat": "window"},
        "confidence": 1.0,
        "source": "user_stated",
    }
)
recalled = memory.recall("window seat")
receipts = memory.receipts()

print(json.dumps({"witnessed": witnessed, "claimed": claimed}, indent=2))
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

`key` is a slip minted by the server operator and passed verbatim as
`Authorization: Bearer v2.<claims>.<mac-hex>`. This package never parses,
splits, or validates it: every authority decision is made server-side from the
MAC-verified `principal_ref` and `actor_class` claims. A connected handle's
`as_actor` therefore raises `FORBIDDEN` — reconnect with a differently scoped
slip instead.

## API

| method | returns |
|---|---|
| `Oneiron.open(path=None, *, dimensions=None)` | an embedded handle |
| `Oneiron.connect(url, key)` | a remote handle |
| `handle.as_actor(actor_key)` | a new handle bound to another actor |
| `handle.witness(turn)` | `WitnessReceipt` |
| `handle.claim_upsert(claim)` | `CommitReceipt` |
| `handle.recall(query, ...)` | `MemoryPack` |
| `handle.receipts(limit=100)` | `list[FacadeReceipt]` |

`recall` keyword arguments are `effort` (`"minimal" | "standard" | "deep"`,
default `"standard"`), `scope` (`{"world_ref": ..., "facet": ...}`), `limit`
(default `10`) and `format` (`"json" | "yaml" | "toon" | "md" | "txt"`).
`deep` is lease-gated and raises `LEASE_REQUIRED`; this package neither mints
nor simulates a lease.

Timestamps are Unix **seconds** everywhere and are never converted. Omitting
`occurred_at` stamps the current wall clock at the call boundary.

## Errors

Every failure is an `OneironError` carrying the engine's own vocabulary:

```python
from oneiron import Oneiron, OneironError

try:
    memory.recall("window seat", effort="deep")
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
