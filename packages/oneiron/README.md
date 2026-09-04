# oneiron

Memory for agents. Witness a turn, claim a fact, recall it, read the receipts.

```sh
npm install oneiron
```

Node 20 or newer. The package ships prebuilt native artifacts for macOS
(arm64/x64), Linux gnu (arm64/x64), and Windows x64.

## Quickstart

Four calls, no configuration, no server. `Oneiron.open()` creates and owns an
embedded vault at `~/.oneiron/default` and binds a local owner actor, so there
is no actor ceremony before the first write.

<!-- snippet:quickstart/node.mjs -->
```js
import { Oneiron } from "oneiron"

const memory = Oneiron.open()

const witnessed = memory.witness({
  conversationRef: "11111111111111111111111111111111",
  messages: [{
    author: "user",
    messageType: "dialogue",
    content: "I prefer a window seat when I fly.",
    order: 0,
  }],
})

const claimed = memory.claimUpsert({
  id: "22222222222222222222222222222222",
  predicate: "preference.travel.seat",
  subjectRef: witnessed.turnShortId,
  value: { seat: "window" },
  confidence: 1,
  source: "user_stated",
})
const recalled = memory.recall("window seat")
const receipts = memory.receipts()

console.log(JSON.stringify({ witnessed, claimed, recalled, receipts }, null, 2))
```
<!-- /snippet -->

The same four calls in Python (`pip install oneiron`):

<!-- snippet:quickstart/python.py -->
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

print(
    json.dumps(
        {"witnessed": witnessed, "claimed": claimed, "recalled": recalled, "receipts": receipts},
        indent=2,
    )
)
```
<!-- /snippet -->

The two packages differ by the constructor line and the field spelling —
JavaScript is camelCase, Python is snake_case — and by nothing else.

## Connecting to a server

`connect` returns the same handle type, so the four calls above are unchanged:

```js
const memory = Oneiron.connect("http://127.0.0.1:8080", process.env.ONEIRON_KEY)
```

`key` is a slip minted by the server operator:

```sh
oneiron-server token mint \
  --scope core:read,core:write \
  --principal-ref <32-hex person id> \
  --actor-class human
```

It is passed verbatim as `Authorization: Bearer v2.<claims>.<mac-hex>`. This
package never parses, splits, or validates it: write identity comes from the
server-verified `principal_ref` and `actor_class` claims, and every authority
decision is made server-side. A connected handle's `asActor` therefore fails
with `FORBIDDEN` — reconnect with a differently scoped slip instead.

## API

| method | returns |
|---|---|
| `Oneiron.open(path?, opts?)` | an embedded handle |
| `Oneiron.connect(url, key)` | a remote handle |
| `handle.asActor(actorKey)` | a new handle bound to another actor |
| `handle.witness(turn)` | `WitnessReceipt` |
| `handle.claimUpsert(claim)` | `CommitReceipt` |
| `handle.recall(query, opts?)` | `MemoryPack` |
| `handle.receipts(limit?)` | `FacadeReceipt[]` |

`recall` options are `effort` (`"minimal" | "standard" | "deep"`, default
`"standard"`), `scope` (`{ worldRef?, facet? }`), `limit` (default `10`) and
`format` (`"json" | "yaml" | "toon" | "md" | "txt"`). `deep` is lease-gated and
returns `LEASE_REQUIRED`; this package neither mints nor simulates a lease.

Timestamps are Unix **seconds** everywhere and are never converted. Omitting
`occurredAt` stamps the current wall clock at the call boundary; supplying one
means passing `Math.floor(Date.now() / 1000)`.

## Errors

Every failure is an `OneironError` carrying the engine's own vocabulary:

```js
import { Oneiron, OneironError } from "oneiron"

try {
  memory.recall("window seat", { effort: "deep" })
} catch (error) {
  if (error instanceof OneironError) {
    console.error(error.code, error.message, error.suggestions)
  }
}
```

`code` is the engine's stable string — `BAD_REQUEST`, `FORBIDDEN`,
`NOT_FOUND`, `LEASE_REQUIRED`, `VAULT_LOCKED_SINGLE_WRITER`, and others — and
`suggestions` is never empty.

## One writer per vault

An embedded vault directory is owned by one process at a time. A second
process opening it gets `VAULT_LOCKED_SINGLE_WRITER` with a suggestion to
`connect` to the owner instead. Ownership is a live OS lock, so a crash
releases it and a stale `oneiron.writer.lock` file never blocks a reopen.

Opening the same path twice in ONE process is fine and shares the same native
vault; reopening it with different options fails `BAD_REQUEST` rather than
silently handing back a differently configured vault.

## Versioning

This package's semver **major** always equals the engine's
`MEMORY_PACK_VERSION`, which is the schema `recall` returns. Both build scripts
and the packaging dry-run assert it.

## License

Apache-2.0
