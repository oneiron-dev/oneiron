# @oneiron/client

The one thin typed client for the Oneiron API (ARCH-0028), generated from the
SDK verb table, with raw-response passthrough. It is the second lane of the
packaging ladder — the lane for agents and apps that can install one package —
and it exists to save typing, never to become the contract.

The verb table, `scripts/sdk/verbs/`, is the contract. This package
is a small fetch wrapper over it: it builds URLs and default headers, types
every verb's input and result, and hands back the raw `Response`.

## What is generated, and what is written by hand

The SDK generator (`crates/oneiron-sdk-generator`) writes two files here from the verb table; never
edit them by hand:

* `src/facade.ts`: `FACADE_VERBS`; `FacadeInputs` and `FacadeResults`, each
  verb's typed request body and 2xx result body (`FacadeInput<V>`,
  `FacadeResult<V>`); `FACADE_CATALOG`, each verb's row metadata
  (`description`, `scope`, `proposes`, `hostDoor`, `section`); and
  `facadeTree(transport)`, every verb at its SDK path
  (`vault.claims.upsert`, `self.memory.diary`), each with its row's
  description as JSDoc.
* `src/facade-types.ts`: the wire declarations (`Facade.*`), read from the Rust
  serde types each row's input and output name and every type they reach:
  structs, enums in each serde tagging, renames, defaults, flattens and id
  codecs. The same file ships in `oneiron`, and the Python stubs carry the same
  shapes as TypedDicts (`oneiron/facade_types.pyi`).

Written by hand: `src/index.ts`, the HTTP transport (origin pinning, header
merging, redirect hops) and the `discover`, `searchText`, `getEntity`,
`callVerb`, `lensFrameEvent` and `closeLensFrame` conveniences.

### Typed coverage census

Every one of the 153 facade rows has a typed method. Of their inputs, 131 are
fully typed and 22 are typed down to a leaf that is an opaque
`serde_json::Value` by design (a claim's `value`, a task `spec`, an entity
`body`); of their results, 127 and 26. No row has a shape the generator could
not read. The generator prints the current census, with every opaque leaf and
every unread shape by name, each time it runs, and the header of
`src/facade-types.ts` carries it.

## Install

**Bun 1.3 or newer is required. Plain Node.js is not supported.** This
source-direct package publishes TypeScript, not a compiled JavaScript entry
point. Run the example with `bun`, not `node`.

```bash
bun add @oneiron/client
```

`main`, `types`, and the `.` export resolve to `./src/index.ts`; `./facade`
and `./facade-types` resolve to the generated tree and declarations alone.
The published package includes those generated files. A source checkout runs
`bun run prepare` once before importing it. That script writes them with
`cargo run -p oneiron-sdk-generator -- --package oneiron-client`, so it needs
Rust's `cargo` on `PATH`.

## Use

Set `ONEIRON_URL` to your running server's origin, `ONEIRON_SECRET` to the
bearer slip (`v2.slip.*`), and `ONEIRON_BINDING_KEY` to its holder seed (64 hex).
These are the names `oneiron api` and `oneiron mcp` read by default. If you
have a paired `v2.cred.<slip hex>.<seed hex>` credential from `Oneiron.pair()`
or `oneiron token agent --out`, its two components supply those variables.
The server's issuer secret is not a request credential.

```ts
import { HttpBaseClient, createSignedFetch } from "@oneiron/client";

const url = process.env.ONEIRON_URL;
const secret = process.env.ONEIRON_SECRET;
const bindingKey = process.env.ONEIRON_BINDING_KEY;
if (!url || !secret || !bindingKey) {
  throw new Error("Set ONEIRON_URL, ONEIRON_SECRET and ONEIRON_BINDING_KEY");
}
const credential = `v2.cred.${secret.slice("v2.slip.".length)}.${bindingKey}`;
const client = new HttpBaseClient({
  baseUrl: url,
  fetch: createSignedFetch(credential),
});

const response = await client.facade.vault.recall({
  query: "where did we leave the launch plan?", effort: "light", limit: 5,
});
if (!(response instanceof Response)) {
  throw new Error(`Call paused on ask ${response.ask}`);
}
if (!response.ok) {
  throw new Error(`${response.status}: ${await response.text()}`);
}
console.log(await response.json());
```

Save this as `index.ts` and run `bun index.ts`. `createSignedFetch` accepts
one paired credential and attaches its bearer plus a fresh `x-oneiron-binding`
proof on every request, including retries and redirect hops. Wire it once
through `fetch`; individual calls need no signer, verb string or proof header.
The existing client still pins requests and redirect hops to `baseUrl`'s origin.
Do not use the signing transport alone as a general-purpose fetch.
Against a loopback server started with `--insecure-allow-unauthenticated` and
no auth secret, omit the signer and `secret` instead. See the
[authentication reference](../../oneiron.skills.md#authentication).

Every facade verb is `client.facade.<path>(input, init?)`, a
`POST /v1/core/facade/<verb>` whose body is the typed input. The input is
checked at compile time; the `Response` is the original one. `FacadeResult<V>`
types its JSON body. `request`, `discover`, `searchText`, `getEntity`, and
`callVerb` also return `Promise<Response>`.

Each facade call carries a fresh `x-oneiron-invocation`. A verb hook that
stops it on a `202 PENDING_ASK` returns a `FacadePending`, not a `Response`.
`client.retry(pending, init?)` resends the same verb and input under that id;
the signing transport makes a new holder proof automatically.

A lens card that `vault.lenses.default` rendered takes its events at routes
outside the facade (OF-181). `client.lensFrameEvent(cardId, request, init?)`
is `POST /v1/core/lens-frames/{cardId}/events` with the
`{ event, idempotencyKey }` body (`LensFrameEventRequest`), and
`client.closeLensFrame(cardId, init?)` is `DELETE
/v1/core/lens-frames/{cardId}`. Both return the original `Response`;
`LensFrameEventReply` (`{ $state }`, `{ outcome, readReceipt }`, or a model
round trip's `202` `{ queued, callbackId }`) and
`CloseLensFrameReply` (`{ closed }`) type their 2xx bodies. Send them to the
server that rendered the card, where its frame lives. The credential that sends
an event authors the card's action, whoever rendered it; only the credential
that rendered a card closes it. An optional `selectedContext` lists the
`selectionRef`s this credential made on the card, context for a model round
trip.

## What this client will not do

* It does not parse a response body, clone a response, or throw on an HTTP
  status. `4xx` and `5xx` resolve like any other response; only a network
  failure rejects, exactly as `fetch` rejects. The one exception is a facade
  `202`: it is cloned and, when it carries a `PENDING_ASK` envelope, read into
  a `FacadePending`.
* It does not re-send a mutation, cache a result, or iterate pages behind your
  back, so wire metadata is never hidden. `retry` re-sends only when you call it.
* It does not add an endpoint, a second authority model, or a second request
  envelope. Caller headers merge additively, and swapping the configured
  `Authorization` header for a different credential is refused loudly.
* It never logs the credential. The optional signing transport retains its
  holder key to sign requests; do not log or share the paired credential.
* It does not let the runtime chase redirects. Each hop is taken by hand and
  re-checked against the configured origin, so a `Location` pointing at another
  host throws instead of being followed with your credential attached;
  same-origin hops follow fetch's own method rules and stop after five.

## Consumers

One artifact serves three consumers. `facadeTree` takes the one thing that
differs between them, an injected invocation transport
(`FacadeTransport<K, O>`: a verb, its typed input, the transport's own
options, the call's invocation id and, on a retry, the ask it stopped on,
which the transport sends beside the id: `x-oneiron-hook-ask` over HTTP),
and every consumer gets the same
typed tree and the same `FACADE_CATALOG`. `K` says what a call answers: `"response"` (the original
`Response`), `"result"` (a promise of the typed result) or `"sync"` (the typed
result itself). Each kind may answer a `FacadePending` instead, for a call a
verb hook stopped on an ask; `facadeRetry` resends it under its invocation,
naming that ask.

1. **Bun-capable external agent (BYOA)** — `bun add @oneiron/client`, then
   `new HttpBaseClient(...)`: its `facade` is
   `facadeTree<"response", RequestInit>` over the fetch transport above.
2. **Native app** — imports `facadeTree` from `@oneiron/client/facade` and
   supplies an adapter over its in-process binding, for example
   `facadeTree<"sync", undefined>((verb, input) => native.call(verb, input))`.
3. **Code mode** — the sandbox inject builds its `vault` and `self` roots with
   `facadeTree<"result", undefined>` over the host dispatcher it already has,
   so the sandbox shares the artifact as well as the wire. That wiring lives in
   the code-mode runtime, not here, and is not done yet; until it is, the
   sandbox keeps its own method table.

Board, browser and run rows are not facade rows: their answers need a run's
own board, browser or dispatcher, so they appear in the verb table and code
mode only.

## Development

```bash
bun install --frozen-lockfile
bun run check   # tsc --noEmit && bun test
```

Examples in this repository use placeholder localhost URLs and placeholder
credentials only.
