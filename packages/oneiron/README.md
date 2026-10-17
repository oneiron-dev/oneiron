# Memory Wire — oneiron

Memory Wire is the Oneiron developer profile. Start with `vault.witness`,
`vault.recall`, and `vault.receipts`. The same package also ships
`vault.claims.upsert`, the fourth quickstart verb. The same authoritative `FACADE_VERB_CATALOG` also
ships five exact keyed-memory verbs for actor-bound long-term stores.
There is no separate lite SDK and no alternate mutation path.

```sh
npm install oneiron
```

Node 20 or newer. The package ships prebuilt native artifacts for macOS
(arm64/x64), Linux gnu (arm64/x64), and Windows x64. In both the Node and Python
SDKs, embedded `Oneiron.open()` is currently supported only on Unix
(macOS/Linux). On other targets, including Windows, use `Oneiron.connect()`
to reach a server on a supported host; embedded open fails closed because
writer locking is unsupported.

## Quickstart

Four calls, no configuration, no server. `Oneiron.open()` creates and owns an
embedded vault at `~/.oneiron/default` and binds a local owner actor, so there
is no actor ceremony before the first write.

<!-- snippet:quickstart/node.mjs -->
```js
import { Oneiron } from "oneiron"

const memory = Oneiron.open()

const witnessed = memory.vault.witness({
  conversationRef: "11111111111111111111111111111111",
  messages: [{
    author: "user",
    messageType: "dialogue",
    content: "I prefer a window seat when I fly.",
    order: 0,
  }],
})

const claimed = memory.vault.claims.upsert({
  id: "22222222222222222222222222222222",
  predicate: "preference.travel.seat",
  subjectRef: witnessed.turnShortId,
  value: { seat: "window" },
  confidence: 1,
  source: "user_stated",
})
const recalled = memory.vault.recall("window seat")
const receipts = memory.vault.receipts()

console.log(JSON.stringify({ witnessed, claimed, recalled, receipts }, null, 2))
```
<!-- /snippet -->

The same four calls in Python (`pip install oneiron`):

<!-- snippet:quickstart/python.py -->
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

Pairing takes three steps. First, the server's owner creates a one-hour,
one-use link for the person the connection writes as, and hands over the one
line it prints:

```sh
oneiron-server token pair \
  --scope core:read,core:write \
  --principal-ref <32-hex person id> \
  --actor-class human
```

Second, you pair once with that link as `ONEIRON_LINK`, and store the
credential it prints as `ONEIRON_KEY`:

<!-- snippet:quickstart/node-pair.mjs -->
```js
import { Oneiron } from "oneiron"

const link = process.env.ONEIRON_LINK
if (!link) throw new Error("Set ONEIRON_LINK to the one-line link your server's owner created")
const { credential } = Oneiron.pair(link)

// Store this as ONEIRON_KEY. The link is now spent; the credential is not.
console.log(credential)
```
<!-- /snippet -->

<!-- snippet:quickstart/python-pair.py -->
```python
import os

from oneiron import Oneiron

memory, credential = Oneiron.pair(os.environ["ONEIRON_LINK"])

# Store this as ONEIRON_KEY. The link is now spent; the credential is not.
print(credential)
```
<!-- /snippet -->

Third, set `ONEIRON_URL` to the server origin and connect. These are complete
programs; the constructors are the only behavioral change.

<!-- snippet:quickstart/node-connect.mjs -->
```js
import { Oneiron } from "oneiron"

const url = process.env.ONEIRON_URL
const key = process.env.ONEIRON_KEY
if (!url || !key) throw new Error("Set ONEIRON_URL and ONEIRON_KEY to your server and paired credential")
const memory = Oneiron.connect(url, key)

const witnessed = memory.vault.witness({
  conversationRef: "11111111111111111111111111111111",
  messages: [{
    author: "user",
    messageType: "dialogue",
    content: "I prefer a window seat when I fly.",
    order: 0,
  }],
})

const claimed = memory.vault.claims.upsert({
  id: "22222222222222222222222222222222",
  predicate: "preference.travel.seat",
  subjectRef: witnessed.turnShortId,
  value: { seat: "window" },
  confidence: 1,
  source: "user_stated",
})
const recalled = memory.vault.recall("window seat")
const receipts = memory.vault.receipts()

console.log(JSON.stringify({ witnessed, claimed, recalled, receipts }, null, 2))
```
<!-- /snippet -->

<!-- snippet:quickstart/python-connect.py -->
```python
import json
import os

from oneiron import Oneiron

memory = Oneiron.connect(os.environ["ONEIRON_URL"], os.environ["ONEIRON_KEY"])

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

print(
    json.dumps(
        {"witnessed": witnessed, "claimed": claimed, "recalled": recalled, "receipts": receipts},
        indent=2,
    )
)
```
<!-- /snippet -->

`key` is the credential `pair` returned: it holds the slip and its connection
key, and this package signs every request with that key. The package never
reads the slip's claims: write identity comes from the server-verified slip,
and every authority decision is made server-side. A connected handle's
`asActor` therefore fails with `FORBIDDEN` — pair a link created for the actor
you want to act as instead.

## API

| method | returns |
|---|---|
| `Oneiron.open(path?, opts?)` | an embedded handle |
| `Oneiron.connect(url, key)` | a remote handle |
| `Oneiron.pair(link)` | `{ memory, credential }`: a remote handle and the credential to store |
| `handle.asActor(actorKey)` | a new handle bound to another actor |
| `handle.inRoomTurn(roomRef)` | a new handle whose every verb runs as a turn in that room |
| `handle.lastReceiptRef()` | the `call:<32hex>` receipt the last remote reply stated, answered or refused; `null` when embedded or before any call |
| `handle.retry(pending, verb, input)` | resends a call a verb hook stopped on an ask (`OneironError` `PENDING_ASK`, its `hook` naming the invocation) under that invocation, with the same verb name and input; answers the verb's wire JSON |
| `handle.lensFrameEvent(cardId, request)` | sends one `{ event, idempotencyKey }` on a lens card the connected server rendered; answers `{ $state }`, `{ outcome, readReceipt }`, or a model round trip's `{ queued, callbackId }` |
| `handle.closeLensFrame(cardId)` | closes that card and frees its frame; answers `{ closed }` |
| `handle.vault.witness(turn)` | `WitnessReceipt` |
| `handle.vault.claims.upsert(claim)` | `CommitReceipt` |
| `handle.vault.recall(query, opts?)` | `MemoryPack` |
| `handle.vault.receipts(limit?, kinds?)` | `FacadeReceipt[]`: the gate decision ledger, or the receipts of the named kinds (`gate`, `hook`, `outbound`, ...) |

`lensFrameEvent` and `closeLensFrame` are the two lens-card routes outside the
facade (OF-181), not verbs. A card's frame lives only on the server that
rendered it (`vault.lenses.default`), so they need a connected handle: an
embedded one throws `BAD_REQUEST`. Their keys keep the wire's camelCase.

Every other verb in the SDK verb table sits at its SDK path on the handle
(`handle.vault.people.list(input)`, `handle.self.memory.diary(input)`, ...).
Its input and result are typed by `Facade`, the wire declarations
`scripts/sdk/generate.py` reads from the Rust types each row names, and its
JSDoc is the row's own description. The keys are the engine's wire spelling
(snake_case). Of the table's 170 facade rows, 148 inputs and 144 results are
fully typed; the rest are typed down to a leaf that is opaque JSON by design (a
claim's `value`, an entity `body`), and none is left untyped. The same
declarations ship in `@oneiron/client` and, as TypedDicts, in the Python stubs.

`vault.recall` options are `effort` (`"light" | "medium" | "high" | "xhigh" | "max" | "call"`,
default `"medium"`), `scope` (`{ worldRef?, facet?, kinds? }`), `limit` (default
`10`), `format` (`"json" | "yaml" | "toon" | "md" | "txt"`), `asOf` (Unix seconds
the query's time words resolve against; default now), `deadlineMs` (1 to
60000), `media` (`{ space, mime, bytesB64, kinds? }`: bytes the server embeds
into that declared space and searches beside the query, at medium effort or
above; an embedded client returns `MODEL_UNAVAILABLE`) and `queryAffect`
(`{ valence, arousal, dominance }`: the affect the query is asked in, valence
-1 to 1, arousal and dominance 0 to 1; emotion congruence ranks each item by how
near its own affect sits, embedded and remote alike; out of range returns
`BAD_REQUEST`). `kinds` lists the registry kinds to return; unset returns every kind but
conversations, sessions, facets and worlds. `high`, `xhigh` and `max` need
a budget lease this package never mints: an embedded client returns `LEASE_REQUIRED`;
a remote one gets what the server serves (reranked on its `[models]` reranker, or
unreranked and saying so). `call` is call mode for live calls: light effort
under a hard deadline (`deadlineMs`, or the vault's call-mode deadline). With a
deadline, recall answers with the best results ready, marked `partial`; without
one, it runs to the end.

Timestamps are Unix **seconds** everywhere and are never converted. Omitting
`occurredAt` stamps the current wall clock at the call boundary; supplying one
means passing `Math.floor(Date.now() / 1000)`.

## Errors

Every failure is an `OneironError` carrying the engine's own vocabulary:

```js
import { Oneiron, OneironError } from "oneiron"

try {
  memory.vault.recall("window seat", { effort: "high" })
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
`MEMORY_PACK_VERSION`, which is the schema `vault.recall` returns. Both build scripts
and the packaging dry-run assert it.

## License

Apache-2.0

## Exact keyed long-term memory

`vault.kv.get`, `vault.kv.put`, `vault.kv.delete`, `vault.kv.search`, and
`vault.kv.namespaces` are the same engine facade in embedded and remote mode,
at the same path in JS and Python. They do not emulate exact keys from ranked
recall.

```python
from uuid import uuid4
from oneiron import Oneiron

memory = Oneiron.open()
address = {"namespace": ["preferences"], "key": "color"}
# This example records a preference explicitly stated by its user.
request = {**address, "value": {"name": "blue"},
           "request_id": uuid4().hex, "source": "user_stated"}
receipt = memory.vault.kv.put(request)
assert memory.vault.kv.get(address) == receipt["item"]
assert memory.vault.kv.put(request)["replayed"]
print(memory.vault.kv.search({"namespace_prefix": ["preferences"]}))
print(memory.vault.kv.namespaces({"prefix": ["preferences"]}))
memory.vault.kv.delete(address)
assert memory.vault.kv.get(address) is None
```

```js
import { randomUUID } from "node:crypto"
import { Oneiron } from "oneiron"

const memory = Oneiron.open()
const address = { namespace: ["preferences"], key: "color" }
const receipt = memory.vault.kv.put({ ...address, value: { name: "blue" },
  requestId: randomUUID(), source: "user_stated" })
console.log(memory.vault.kv.get(address), receipt.receiptRef)
console.log(memory.vault.kv.search({ namespacePrefix: ["preferences"], limit: 10, offset: 0 }))
console.log(memory.vault.kv.namespaces({ prefix: ["preferences"], maxDepth: 1 }))
memory.vault.kv.delete(address)
```

The key space is actor-id **and actor-class** bound, and explicitly worldless.
No input chooses another actor, world, owner, entity ID, or erasure reason.
Namespaces compare complete literal string segments. Search accepts exact
field-equality filters, not operators or semantic queries. Results have lexical
namespace/key order. Namespace rows are deduplicated after optional depth
truncation. `limit` is 1–1000 and `offset` is 0–1000000. Pages are individual live
snapshots; concurrent mutations can shift subsequent offsets.

Keyed bodies never appear in generic recall, context packs, scoped hydration,
entity/claim views, or history projections, even for the owner. The exact keyed
API is the only app-tier reader. Privileged raw Vault/batch systems APIs remain
outside this actor isolation boundary.

Equality preserves the engine's JSON number representation: integer `2` differs
from floating `2.0`. Integers are not normalized through lossy `f64`. Each SDK
is limited by its host JSON encoder; JavaScript represents `2.0` as `2` and
cannot exactly represent all large integers. JS optional request fields may be
explicitly `undefined` and use the engine defaults. `undefined` inside stored
JSON values or filter data is rejected, not silently dropped or changed to null.

A put's omitted source is `generated`. The real claim gate must permit it.
Review-required writes fail and roll back without replacing the current value;
a proposed claim is never mislabeled as a completed key write. Successful puts
return `item`, `replayed`, and `receipt_ref` (`receiptRef` in JS). Preserve
`request_id` only for an identical retry while that revision remains current.
A stale retry returns `INVALID_STATE`, including after deletion.

Replacement also preserves source trust. Generated output cannot supersede a
user-stated head, even for the same actor and key or under a generated auto
permit. That refusal returns `INVALID_STATE` without changing the current value,
history, or receipts. Keep the true source and use a separate key for generated
output. Only a genuine new user statement may be submitted as `user_stated`.
Never relabel model output or delete then put to bypass the protection.

Erased shells and malformed rows are not live heads. Reads skip them and never
fall back to superseded values. Unrelated keys remain usable. Replaying a
request against an erased/malformed revision refuses instead of restoring it.

Delete retracts the caller's current claim and returns `existed` plus receipt
refs. It is idempotent while absent and retains history. It is not an owner
`vault.delete` or compliance erase. Conflicting synced heads fail closed with
`INVALID_STATE` rather than inventing a local winner.

[The LangGraph satellite](../oneiron-langgraph/README.md) adapts these doors to
the real `BaseStore.batch/abatch` interface and includes a runnable graph.
It is long-term memory, not a checkpoint saver. TTL and vector search are not
supported.
