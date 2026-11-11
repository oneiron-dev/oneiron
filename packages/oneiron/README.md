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
writer locking is unsupported. One verb is narrower: `putCodebaseSnapshot` refuses SharedArrayBuffer-backed inputs on Node runtimes below 22.21 (22.x) / 24.9 (24+), which cannot measure the shared backing.

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
credential it prints as a private credential file. For CLI-compatible
environment variables, split it into `ONEIRON_SECRET` (the `v2.slip.*`
bearer) and `ONEIRON_BINDING_KEY` (its 64-hex holder seed). Pairing also returns the checkpoint pin
the link named, already checked against it and stored nowhere by the SDK. A
machine that will run a local replica keeps that pin beside the server origin
and the credential, and supplies it when the replica starts; a remote-only
caller needs only the credential:

<!-- snippet:quickstart/node-pair.mjs -->
```js
import { Oneiron } from "oneiron"

const link = process.env.ONEIRON_LINK
if (!link) throw new Error("Set ONEIRON_LINK to the one-line link your server's owner created")
const { credential } = Oneiron.pair(link)

// The link is now spent; the credential is not. Store these privately.
const [slip, seed] = credential.slice("v2.cred.".length).split(".")
console.log(JSON.stringify({ ONEIRON_SECRET: `v2.slip.${slip}`, ONEIRON_BINDING_KEY: seed }))
// The result's `pin` is the checkpoint pin the link named (null when the vault
// has no attested checkpoint): a machine that will run a local replica keeps
// it beside the server origin and the credential.
```
<!-- /snippet -->

<!-- snippet:quickstart/python-pair.py -->
```python
import os

from oneiron import Oneiron

paired = Oneiron.pair(os.environ["ONEIRON_LINK"])

# The link is now spent; the credential is not. Store these privately.
slip, seed = paired["credential"].removeprefix("v2.cred.").rsplit(".", 1)
print({"ONEIRON_SECRET": "v2.slip." + slip, "ONEIRON_BINDING_KEY": seed})
# paired["pin"] is the checkpoint pin the link named (None when the vault has
# no attested checkpoint): a machine that will run a local replica keeps it
# beside the server origin and the credential.
```
<!-- /snippet -->

Third, set `ONEIRON_URL` to the server origin and connect. These are complete
programs; the constructors are the only behavioral change.

<!-- snippet:quickstart/node-connect.mjs -->
```js
import { Oneiron } from "oneiron"

const url = process.env.ONEIRON_URL
const secret = process.env.ONEIRON_SECRET
const bindingKey = process.env.ONEIRON_BINDING_KEY
if (!url || !secret || !bindingKey) throw new Error("Set ONEIRON_URL, ONEIRON_SECRET and ONEIRON_BINDING_KEY")
const credential = `v2.cred.${secret.slice("v2.slip.".length)}.${bindingKey}`
const memory = Oneiron.connect(url, credential)

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

credential = "v2.cred." + os.environ["ONEIRON_SECRET"].removeprefix("v2.slip.") + "." + os.environ["ONEIRON_BINDING_KEY"]
memory = Oneiron.connect(os.environ["ONEIRON_URL"], credential)

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

`credential` is the paired value reconstructed from those two variables: it holds the slip and its connection
key, and this package signs every request with that key. The package never
reads the slip's claims: write identity comes from the server-verified slip,
and every authority decision is made server-side. A connected handle's
`asActor` therefore fails with `FORBIDDEN` — pair a link created for the actor
you want to act as instead.

## Let an agent act

The server operator first stops `oneiron serve`, then creates a named agent
credential against the same vault config on its host. This writes a private
paired credential file and prints `principal_ref`; keep that id for `agentRef`
below. Start `oneiron serve --config /absolute/private/oneiron.toml` again
before making the SDK calls.

```sh
oneiron token agent --name sdk-example --tier full-access \
  --out /absolute/private/agent.cred --config /absolute/private/oneiron.toml
```

`--tier` sets the credential's read/propose/write ceiling. A person's pairing
`--scope core:read,core:write` chooses its HTTP capabilities. Neither is an
owner grant: an owner-only act stays owner-only, and an agent using `ai.embed`
also needs an active grant naming that verb. The grant is checked at use and
stops conferring when revoked or expired.

Use a connected **owner** handle as `memory` for mint, revoke and audit.
Replace `agentRef` with the principal printed above. This example permits
`read` and `ai.embed` across all worlds, facets, bands, projects and
sensitivity levels in the owner's scope; narrow those axes for your use.
The server must have an embedding model configured for the agent call.

```js
import { readFileSync } from "node:fs"
import { Oneiron } from "oneiron"

const agentRef = "<32-hex principal from token agent>"
const minted = memory.vault.agents.grants.mint({
  agent: agentRef,
  authority_scope: {
    worlds: { kind: "all" }, facets: { kind: "all" },
    bands: { kind: "all" }, audience: { kind: "all" },
    sensitivity: { kind: "all" },
    verbs: { kind: "some", values: ["read", "ai.embed"] },
  },
})
const agent = Oneiron.connect(process.env.ONEIRON_URL,
  readFileSync("/absolute/private/agent.cred", "utf8").trim())
try {
  console.log(agent.ai.embed({ prompt: "A project note to embed." }))
} finally {
  memory.vault.agents.grants.revoke({ grant_ref: minted.grant.grant_ref })
}
console.log(memory.vault.authority.audit({ kinds: ["grant", "revoke"], limit: 100 }))
```

`vault.authority.audit` shows the grant and revoke in the authority log. It
returns a page; use its `next_after` as `after` to continue. `self.grants.*`
are requests for grants, not a list of active grants.

## Export

`vault.export` is **owner-only** and **includes custody secrets** by default.
Keep the output private. It carries every world; `notices` names worlds that
the owner's recipient choice would otherwise keep from the destination.
To load the ZIP back today, stop `oneiron serve` for the target vault and run
the local CLI on that vault's host:

```sh
oneiron import archive vault-export.zip --config /absolute/private/oneiron.toml
```

The CLI checks the archive against its manifest and imports it in one
transaction. It refuses while the vault is served. No served HTTP/MCP verb
imports a whole-vault archive; `oneiron restore` uses a different backup format.
This command takes the ZIP archive, not an OKF bundle.

On an embedded or connected owner handle `memory`, save the inline ZIP:

```js
import { writeFileSync } from "node:fs"
const exported = memory.vault.export()
writeFileSync("vault-export.zip", Buffer.from(exported.archive, "base64"), { mode: 0o600, flag: "wx" })
```

For a large vault, use the transfer form through `oneiron api` (which reads
`ONEIRON_URL`, `ONEIRON_SECRET` and `ONEIRON_BINDING_KEY` and signs each call).
It keeps the archive on the server. `vault.export.transfer.read` returns
4 MiB by default; only the exporter can read or release it. This Bun script
writes a private file and checks the length and BLAKE3 before release:

```js
import { openSync, writeSync, closeSync } from "node:fs"
function call(verb, input) {
  const reply = Bun.spawnSync(["oneiron", "api", "call", verb, "--data", JSON.stringify(input)])
  if (reply.exitCode !== 0) throw new Error(reply.stderr.toString())
  return JSON.parse(reply.stdout.toString())
}
const file = openSync("vault-export.zip", "wx", 0o600)
const digest = new Bun.CryptoHasher("blake3")
let transfer
let offset = 0
try {
  transfer = call("vault.export", { delivery: "transfer" })
  for (;;) {
    const piece = call("vault.export.transfer.read", { transfer_ref: transfer.transfer_ref, offset })
    const bytes = Buffer.from(piece.bytes_base64, "base64")
    let written = 0
    while (written < bytes.length) written += writeSync(file, bytes, written)
    digest.update(bytes)
    offset += piece.length
    if (piece.end) break
  }
  if (offset !== transfer.bytes || digest.digest("hex") !== transfer.digest) throw new Error("Export length or digest mismatch")
} finally {
  closeSync(file)
  if (transfer) call("vault.export.transfer.release", { transfer_ref: transfer.transfer_ref })
}
```

The environment names used here and by the agent quickstart are:

| Value | Environment name |
|---|---|
| One-use pairing link | `ONEIRON_LINK` (read by the pairing example) |
| Bearer slip (`v2.slip.*`) | `ONEIRON_SECRET` (CLI default) |
| Holder seed (64 hex) | `ONEIRON_BINDING_KEY` (CLI default) |
| Server origin, not a credential | `ONEIRON_URL` |

A paired `v2.cred.*` value is the two credential components together, not a
second bearer name. The agent example reads it from its private file. Never
put the host issuer secret in any request-credential variable.

## API

| method | returns |
|---|---|
| `Oneiron.open(path?, opts?)` | an embedded handle |
| `Oneiron.openWithHostRoot(path, hostRootSecret, opts?)` | `{ memory, hostRoot }`: an embedded handle whose install the vault's host root (its exact bytes, a `Uint8Array` you keep and clear) profiled as `Unanswered`, so the owner's acts carry from it, and `hostRoot.{ enrolled, wrongRoot }`: `wrongRoot` says the root is not the vault's settled one and went unused (reported, never refused). Rooted-only; `FORBIDDEN` under a managed or relay posture |
| `Oneiron.connect(url, key)` | a remote handle |
| `Oneiron.pair(link)` | `{ memory, credential, pin, comm }`: a remote handle, the credential to store, the checkpoint pin the link named (`null` when the vault has none) for a local replica to adopt by, and the credential's comm reach (`"parent"`, `"subtree"`, `"project"` or `"vault"`): whom an agent paired by it may address |
| `handle.asActor(actorKey)` | a new handle bound to another actor |
| `handle.inRoomTurn(roomRef)` | a new handle whose every verb runs as a turn in that room |
| `handle.withReadCredential(credential)` | a new handle whose every read runs under that delegated-reader credential, verified once; reads refuse unless the slip's holder is the bound actor, rebindings keep the same proof, and a connected handle fails `FORBIDDEN` |
| `handle.lastReceiptRef()` | the `call:<32hex>` receipt the last remote reply stated, answered or refused; `null` when embedded or before any call |
| `handle.retry(pending, verb, input)` | resends a call a verb hook stopped on an ask (`OneironError` `PENDING_ASK`, its `hook` naming the invocation) under that invocation, with the same verb name and input; answers the verb's wire JSON |
| `handle.lensFrameEvent(cardId, request)` | sends one `{ event, idempotencyKey }` on a lens card the connected server rendered; answers `{ $state }`, `{ outcome, readReceipt }`, or a model round trip's `{ queued, callbackId }` |
| `handle.closeLensFrame(cardId)` | closes that card and frees its frame; answers `{ closed }` |
| `handle.vault.witness(turn)` | `WitnessReceipt` |
| `handle.vault.claims.upsert(claim)` | `CommitReceipt` |
| `handle.vault.recall(query, opts?)` | `MemoryPack` |
| `handle.vault.receipts(limit?, kinds?)` | `FacadeReceipt[]`: the gate decision ledger, or the receipts of the named kinds (`gate`, `hook`, `outbound`, ...) |

Approval-required inbox rows from held outbound receipts may carry
`approval_digest`, the exact 64-lowercase-hex digest already on that receipt.
Other inbox rows omit it. Gate decision receipts and the claim-only pending
tray do not gain a digest through this projection; it adds no approval or
release authority.
Witness-read grants (`vault.connectors.read_grants.grant` and `.revoke`)
keep earlier lifecycle generations. For kind `scoped_read`, `vault.receipts`
projects a created receipt for each stored generation and a revoked receipt
only when that generation was revoked. Witness receipt IDs are
`scoped_read:<grant-hex>:v<generation-hex>:created` or `...:revoked`, with
trigger `access_grant:<grant-hex>`; an ID stays the same when its generation
becomes historical. This is unsigned audit metadata, not grant authority or
proof of the owner's act. Erasure clears this history. Other receipt IDs and
verbs are unchanged.

`lensFrameEvent` and `closeLensFrame` are the two lens-card routes outside the
facade (OF-181), not verbs. A card's frame lives only on the served host
that rendered it (`vault.lenses.default`), so render the lens through a
connected handle and send its events and close on that same handle. An
embedded handle keeps no frame and throws `BAD_REQUEST`; a card it rendered
is rendered again through the connected handle. Their keys keep the wire's
camelCase.

Every other verb in the SDK verb table sits at its SDK path on the handle
(`handle.vault.people.list(input)`, `handle.self.memory.diary(input)`, ...).
Its input and result are typed by `Facade`, the wire declarations
the SDK generator reads from the Rust types each row names, and its
JSDoc is the row's own description. The keys are the engine's wire spelling
(snake_case). Inputs and results are fully typed or typed down to a leaf
that is opaque JSON by design (a claim's `value`, an entity `body`); none is
left untyped. The same declarations ship in `@oneiron/client` and, as
TypedDicts, in the Python stubs.

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
truncation. `limit` is 1–1000 and `offset` is any nonnegative integer. Namespaces
and keys may be any length; past the `[limits]` rows `keyed_namespace_segments`,
`keyed_namespace_bytes` and `keyed_key_bytes` the engine asks whether everything is
okay and serves them whole. Pages are individual live
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

Erased shells and malformed rows are not live heads. Nor is a value the
canonical claim read withholds: deleted, archived or withdrawn words, a stale
value, or a value whose recorded source was deleted or is being withdrawn.
Reads skip them and never fall back to superseded values; a put at that key
writes a fresh head. Unrelated keys remain usable. Replaying a request against
an erased/malformed revision refuses instead of restoring it.

Delete retracts the caller's current claim and returns `existed` plus receipt
refs. It is idempotent while absent and retains history. It is not an owner
`vault.delete` or compliance erase. Conflicting synced heads fail closed with
`INVALID_STATE` rather than inventing a local winner.

[The LangGraph satellite](../oneiron-langgraph/README.md) adapts these doors to
the real `BaseStore.batch/abatch` interface and includes a runnable graph.
It is long-term memory, not a checkpoint saver. TTL and vector search are not
supported.

## Witness-read owner acts

`vault.connectors.read_grants.grant` and `.revoke` record the owner's act in
this install's local typed index, in the same commit that changes the grant.
Repeating an already-active grant or an already-revoked revoke changes
nothing and records no new act. Automatic witness grants are not owner acts.

The `scoped_read` receipt family includes these owner acts separately from
grant-state receipts. Each act names the stored owner, target grant and
`granted` or `revoked` change, with a sequence-based receipt ID and the vault's
recorded time. These are writer-trusted local audit records, not signed or
mesh-verified authority. They do not authorize a read or change grant rules.
The request's actual ingress surface is recorded for audit only.
