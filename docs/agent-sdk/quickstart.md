# Memory Wire — oneiron

Memory Wire is the Oneiron developer profile. Start with `witness`, `recall`, and
`receipts`. The same package also ships `claim_upsert` (`claimUpsert` in JS),
the fourth quickstart verb. The same authoritative `FACADE_VERB_CATALOG` also
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

Set `ONEIRON_URL` to the server origin and `ONEIRON_KEY` to a minted slip.
These are complete programs; the constructors are the only behavioral change.

<!-- snippet:quickstart/node-connect.mjs -->
```js
import { Oneiron } from "oneiron"

const url = process.env.ONEIRON_URL
const key = process.env.ONEIRON_KEY
if (!url || !key) throw new Error("Set ONEIRON_URL and ONEIRON_KEY to your server and minted slip")
const memory = Oneiron.connect(url, key)

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

<!-- snippet:quickstart/python-connect.py -->
```python
import json
import os

from oneiron import Oneiron

memory = Oneiron.connect(os.environ["ONEIRON_URL"], os.environ["ONEIRON_KEY"])

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

## Exact keyed long-term memory

`key_value_get`, `key_value_put`, `key_value_delete`, `key_value_search`, and
`key_value_namespaces` are the same engine facade in embedded and remote mode.
JS spells these `keyValueGet`, `keyValuePut`, `keyValueDelete`, `keyValueSearch`,
and `keyValueNamespaces`. They do not emulate exact keys from ranked recall.

```python
from uuid import uuid4
from oneiron import Oneiron

memory = Oneiron.open()
address = {"namespace": ["preferences"], "key": "color"}
# This example records a preference explicitly stated by its user.
request = {**address, "value": {"name": "blue"},
           "request_id": uuid4().hex, "source": "user_stated"}
receipt = memory.key_value_put(request)
assert memory.key_value_get(address) == receipt["item"]
assert memory.key_value_put(request)["replayed"]
print(memory.key_value_search({"namespace_prefix": ["preferences"]}))
print(memory.key_value_namespaces({"prefix": ["preferences"]}))
memory.key_value_delete(address)
assert memory.key_value_get(address) is None
```

```js
import { randomUUID } from "node:crypto"
import { Oneiron } from "oneiron"

const memory = Oneiron.open()
const address = { namespace: ["preferences"], key: "color" }
const receipt = memory.keyValuePut({ ...address, value: { name: "blue" },
  requestId: randomUUID(), source: "user_stated" })
console.log(memory.keyValueGet(address), receipt.receiptRef)
console.log(memory.keyValueSearch({ namespacePrefix: ["preferences"], limit: 10, offset: 0 }))
console.log(memory.keyValueNamespaces({ prefix: ["preferences"], maxDepth: 1 }))
memory.keyValueDelete(address)
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
`safe_delete` or compliance erase. Conflicting synced heads fail closed with
`INVALID_STATE` rather than inventing a local winner.

[The LangGraph satellite](../oneiron-langgraph/README.md) adapts these doors to
the real `BaseStore.batch/abatch` interface and includes a runnable graph.
It is long-term memory, not a checkpoint saver. TTL and vector search are not
supported. External application cutovers remain held.
