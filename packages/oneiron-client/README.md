# @oneiron/client

The one thin typed client for the Oneiron API (ARCH-0028), generated from the
SDK verb table, with raw-response passthrough. It is the second lane of the
packaging ladder — the lane for agents and apps that can install one package —
and it exists to save typing, never to become the contract.

The verb table, `scripts/sdk/agent-verbs.json`, is the contract. This package
is a small fetch wrapper over it: it builds URLs and default headers, types
every verb's input and result, and hands back the raw `Response`.

## What is generated, and what is written by hand

`scripts/sdk/generate.py` writes two files here from the verb table; never
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
merging, redirect hops) and the `discover`, `searchText`, `getEntity` and
`callVerb` conveniences.

### Typed coverage census

Every one of the 153 facade rows has a typed method. Of their inputs, 131 are
fully typed and 22 are typed down to a leaf that is an opaque
`serde_json::Value` by design (a claim's `value`, a task `spec`, an entity
`body`); of their results, 127 and 26. No row has a shape the generator could
not read. The generator prints the current census, with every opaque leaf and
every unread shape by name, each time it runs, and the header of
`src/facade-types.ts` carries it.

## Install

```bash
npm install @oneiron/client   # or: bun add @oneiron/client
```

Source-direct and dependency-free: `main`, `types`, and the `.` export resolve
to `./src/index.ts`; `./facade` and `./facade-types` resolve to the generated
tree and declarations alone, with no fetch client. There is no build step: the
generated files are checked in, and `generate.py --check` fails CI when they
drift from the table.

That shape has a requirement attached, and `engines` declares it: the consuming
runtime must load TypeScript itself. **Bun 1.3 or newer is the supported
runtime**, and it is the one the tests run on. Plain `node` is NOT supported:
without a TypeScript loader, importing `@oneiron/client` fails at resolution,
and this package publishes no compiled JavaScript entry point to fall back to.
A bundler or a Node with its own TS loader may work, but it is your
arrangement rather than a contract this package keeps. An agent or app that
cannot run TypeScript should take the curl lane (`oneiron api …` or plain
`curl`) against the same routes instead.

## Use

```ts
import { HttpBaseClient } from "@oneiron/client";

const client = new HttpBaseClient({
  baseUrl: "http://127.0.0.1:9090",
  secret: process.env.ONEIRON_TOKEN, // a logged `v2.slip.*` capability slip
});

// `holderProof` is a placeholder for your own signer; this package makes no proofs.
const response = await client.discover({
  headers: { "x-oneiron-binding": await holderProof("GET", "/api/core/discover") },
});
if (!response.ok) {
  // The server's own error envelope, verbatim: status, headers, and body.
  console.error(response.status, await response.text());
}
```

`secret` is sent as `Authorization: Bearer` on every request. It must be a
logged `v2.slip.*` capability slip; the server's issuer secret is not a
credential. Each protected request also needs a fresh `x-oneiron-binding`
holder proof, signed with the slip's holder key, and a proof cannot be replayed.
Pass it in that call's `init.headers`, as above. `/api/core/discover` needs an
owner-grade slip. See the
[authentication reference](../../oneiron.skills.md#authentication). Against a
loopback server started with `--insecure-allow-unauthenticated` and no auth
secret, omit both.

Every facade verb is `client.facade.<path>(input, init?)`, a
`POST /v1/core/facade/<verb>` whose body is the typed input:

```ts
import type { FacadeResult } from "@oneiron/client";

const response = await client.facade.vault.recall(
  { query: "where did we leave the launch plan?", effort: "medium" },
  { headers: { "x-oneiron-binding": await holderProof("POST", "/v1/core/facade/vault.recall") } },
);
if (response.ok) {
  const pack = (await response.json()) as FacadeResult<"vault.recall">;
  console.log(pack.items.length, pack.narrowing.narrowed_axes);
}
```

The input is checked at compile time; the `Response` is the original one, so
reading and trusting its body stays the caller's decision. `request`,
`discover`, `searchText`, `getEntity`, and `callVerb` also return
`Promise<Response>`. Any route the convenience methods do not cover is one
`client.request(path, init)` away.

## What this client will not do

* It does not parse a response body, clone a response, or throw on an HTTP
  status. `4xx` and `5xx` resolve like any other response; only a network
  failure rejects, exactly as `fetch` rejects.
* It does not re-send a mutation, cache a result, or iterate pages behind your
  back, so wire metadata is never hidden.
* It does not add an endpoint, a second authority model, or a second request
  envelope. Caller headers merge additively, and swapping the configured
  `Authorization` header for a different credential is refused loudly.
* It never logs the credential. The secret becomes one default header and is
  stored nowhere else.
* It does not let the runtime chase redirects. Each hop is taken by hand and
  re-checked against the configured origin, so a `Location` pointing at another
  host throws instead of being followed with your credential attached;
  same-origin hops follow fetch's own method rules and stop after five.

## Consumers

One artifact serves three consumers. `facadeTree` takes the one thing that
differs between them, an injected invocation transport
(`FacadeTransport<K, O>`: a verb, its typed input, the transport's own
options), and every consumer gets the same typed tree and the same
`FACADE_CATALOG`. `K` says what a call answers: `"response"` (the original
`Response`), `"result"` (a promise of the typed result) or `"sync"` (the typed
result itself).

1. **npm-capable external agent (BYOA)** — `npm i @oneiron/client`, then
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
